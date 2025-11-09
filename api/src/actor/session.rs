use std::collections::HashSet;

use chrono::{DateTime, Utc};
use tokio::time::Instant;
use uuid::Uuid;

use super::{
    database::DatabaseActorHandle,
    mailbox::MailboxCommand,
    playtime::{PlaytimeActor, PlaytimeActorHandle},
    prelude::*,
    single_use_token::SingleUseTokenActorHandle,
    RespCell,
};
use crate::core::{
    trans::to_monotonic,
    types::{consts::session::LEASE_TIME, structs::Profile},
};

/*
 * Session Actor
 * The actor for keeping track of individual player state.
 * Represents an username that was seen at any given point at a server (via KeepAlives)
 * or an profile that successfully has logged in.
 */

pub struct SessionA {
    // Sessions are tied to any username that is connected to an server.
    // And as such they are keyed by their username
    username: String,
    // Sessions are server-agnostic. They don't care which server you are connected to.
    // server: Uuid,
    // But they do keep track of which servers you are actively connected.
    active_servers: HashSet<Uuid>,
    // They represent the state which this username is in. Be it an
    // - Vistor: Username was never seen before
    // - PendingLogin: Username has an profile but hasn't authenticated yet
    // - LoggedIn: Profile is authenticated.
    state: SessionState,
    // Sessions track when they begun
    created_at: DateTime<Utc>,
    // And also the last time the user was seen
    last_seen: DateTime<Utc>,
    // And also the bad login attempts.
    bad_login_attempts: i32,
    mailbox_hnd: WeakUnboundedSender<MailboxCommand>,
    token_hnd: SingleUseTokenActorHandle,
    playtime_hnd: PlaytimeActorHandle,
}

impl SessionA {
    pub fn is_visitor(&self) -> bool {
        matches!(self.state, SessionState::Visitor)
    }

    pub fn deadline(&self) -> Instant {
        let target = self.last_seen + LEASE_TIME;
        to_monotonic(target)
    }

    pub fn ping(&mut self) {
        debug!("[a:Session({})] Event:Ping RECV", self.username);
        self.last_seen = Utc::now();
    }

    pub async fn authenticate(&mut self, server_id: Uuid, password: String) -> LoginAttempt {
        debug!(
            "[a:Session({})] Event:Authenticate RECV | server_id:{}",
            self.username, server_id
        );
        match &self.state {
            SessionState::Visitor => LoginAttempt::InvalidProfile,
            SessionState::PendingLogin { profile } => {
                let result = self
                    .check_otp(profile, password.clone())
                    .await
                    .unwrap_or_else(|| self.chk_passwd(profile, password));

                match result {
                    LoginAttempt::LoggedIn => {
                        let clone = profile.clone();
                        self.playtime_hnd.start(server_id);
                        self.active_servers.insert(server_id);
                        self.state = SessionState::LoggedIn { profile: clone };
                    }
                    LoginAttempt::InvalidProfile => self.bad_login_attempts += 1,
                    _ => {}
                }

                result
            }
            SessionState::LoggedIn { .. } => LoginAttempt::LoggedIn,
        }
    }

    async fn check_otp(&self, profile: &Profile, password: String) -> Option<LoginAttempt> {
        if let Some(id) = self.token_hnd.query_profile(password.clone()).await {
            if profile.id == id {
                self.token_hnd.clear(password);
                return Some(LoginAttempt::LoggedIn);
            }
        }
        None
    }

    fn chk_passwd(&self, profile: &Profile, password: String) -> LoginAttempt {
        if bcrypt::verify(password, &profile.hash_password).unwrap_or(false) {
            LoginAttempt::LoggedIn
        } else {
            LoginAttempt::InvalidPassword {
                error_count: self.bad_login_attempts + 1,
                max_errors: 5,
            }
        }
    }

    pub fn profile_update(&mut self, new: Profile) {
        debug!("[a:Session({})] Event:ProfileUpdate RECV", self.username);
        self.playtime_hnd.promote(new.id);
        match &self.state {
            SessionState::Visitor => {
                self.state = SessionState::PendingLogin { profile: new };
            }
            SessionState::PendingLogin { .. } => {
                self.state = SessionState::PendingLogin { profile: new };
            }
            SessionState::LoggedIn { profile: old } => {
                // if the password changed, invalidate session.
                if old.hash_password != new.hash_password {
                    self.state = SessionState::PendingLogin { profile: new };
                } else {
                    self.state = SessionState::LoggedIn { profile: new };
                }
            }
        }
    }

    pub fn get_state(&self) -> SessionState {
        debug!("[a:Session({})] Event:GerState RECV", self.username);
        self.state.clone()
    }

    pub fn join_server(&mut self, server_id: Uuid) {
        debug!("[a:Session({})] Event:JoinServer RECV | server_id:{}", self.username, server_id);
        if matches!(self.state, SessionState::LoggedIn { .. }) {
            self.active_servers.insert(server_id);
            self.playtime_hnd.start(server_id);
        }
    }

    pub fn leave_server(&mut self, server_id: Uuid) {
        debug!(
            "[a:Session({})] Event:LeaveServer RECV | server_id:{}",
            self.username, server_id
        );

        if matches!(self.state, SessionState::LoggedIn { .. }) {
            self.active_servers.remove(&server_id);
            self.playtime_hnd.end(server_id);
        }
    }

    pub fn check_activity(&self, server_id: Uuid) -> bool {
        debug!(
            "[a:Session({})] Event:CheckActivity RECV | server_id:{}",
            self.username, server_id
        );
        self.active_servers.contains(&server_id)
    }
}

#[derive(Clone)]
pub enum SessionState {
    Visitor,
    PendingLogin { profile: Profile },
    LoggedIn { profile: Profile },
}

pub enum LoginAttempt {
    InvalidProfile,
    InvalidPassword { error_count: i32, max_errors: i32 },
    LoggedIn,
}

pub enum SessionCommand {
    Ping,
    Authenticate {
        server_id: Uuid,
        password: String,
        tx: oneshot::Sender<LoginAttempt>,
    },
    // If passwords are changed, emit this event so the session server is aware of it.
    ProfileUpdate(Profile),
    GetState {
        tx: oneshot::Sender<SessionState>,
    },
    JoinServer(Uuid),
    LeaveServer(Uuid),
    CheckActivity(Uuid, RespCell<bool>),
}

pub struct SessionActor {
    state: SessionA,
    queue: mpsc::UnboundedReceiver<SessionCommand>,
}

#[derive(Clone)]
pub struct SessionActorHandle {
    queue: mpsc::UnboundedSender<SessionCommand>,
}

impl SessionActor {
    pub fn spawn(
        username: String, profile: Option<Profile>, database: DatabaseActorHandle,
        token: SingleUseTokenActorHandle, mailbox: WeakUnboundedSender<MailboxCommand>,
    ) -> SessionActorHandle {
        let now = Utc::now();
        let (tx, rx) = mpsc::unbounded_channel();

        let playtime = PlaytimeActor::spawn(profile.as_ref().map(|it| it.id), database);
        debug!("[a:Session({})] Spawn:Self SPAWN PlaytimeActor({:?}) ", username, profile);

        let actor = Self {
            state: SessionA {
                username,
                state: match profile {
                    Some(p) => SessionState::PendingLogin { profile: p },
                    None => SessionState::Visitor,
                },
                created_at: now,
                last_seen: now,
                bad_login_attempts: 0,
                playtime_hnd: playtime,
                mailbox_hnd: mailbox,
                token_hnd: token,
                active_servers: HashSet::new(),
            },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        SessionActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        while !self.queue.is_closed() {
            tokio::select! {
                cmd = self.queue.recv() => match cmd {
                    Some(cmd) => match cmd {
                        SessionCommand::Ping => self.state.ping(),
                        SessionCommand::Authenticate { server_id, password, tx } => {
                            let k = self.state.authenticate(server_id, password).await;
                            let _ = tx.send(k);
                        },
                        SessionCommand::ProfileUpdate(update) => self.state.profile_update(update),
                        SessionCommand::GetState { tx } => {
                            let _ = tx.send(self.state.get_state());
                        }
                        SessionCommand::JoinServer(server_id) => self.state.join_server(server_id),
                        SessionCommand::LeaveServer(server_id) => self.state.leave_server(server_id),
                        SessionCommand::CheckActivity(server_id, tx) => {
                            let _ = tx.send(self.state.check_activity(server_id));
                        }
                    },
                    None => {
                        break;
                    },
                },
                _ = tokio::time::sleep_until(self.state.deadline()) => {
                    break;
                }
            }
        }

        if let Some(hnd) = self.state.mailbox_hnd.upgrade() {
            let _ = hnd.send(MailboxCommand::CleanupSession(self.state.username));
        }
    }
}

impl SessionActorHandle {
    pub fn ping(&self) {
        notify_actor!(self.queue, SessionCommand::Ping);
    }

    pub async fn authenticate(&self, server_id: Uuid, password: String) -> LoginAttempt {
        ask_actor!(self.queue, SessionCommand::Authenticate { server_id, password });
    }

    pub fn profile_update(&self, update: Profile) {
        notify_actor!(self.queue, SessionCommand::ProfileUpdate(update));
    }

    pub async fn get_state(&self) -> SessionState {
        ask_actor!(self.queue, SessionCommand::GetState {});
    }

    pub fn join_server(&self, server_uuid: Uuid) {
        notify_actor!(self.queue, SessionCommand::JoinServer(server_uuid));
    }

    pub fn leave_server(&self, server_uuid: Uuid) {
        notify_actor!(self.queue, SessionCommand::LeaveServer(server_uuid));
    }

    pub async fn check_activity(&self, server_uuid: Uuid) -> bool {
        ask_actor!(self.queue, SessionCommand::CheckActivity(server_uuid));
    }
}
