/*
 * The "mailbox". An actor that spawns new actors if needed and routes messages through.
 */

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use axum::extract::ws::CloseFrame;
use axum_typed_websockets::WebSocket;
use serenity::all::{ChannelId, GuildId, MessageId, RoleId, UserId};
use uuid::Uuid;

use super::{
    cidr::{CidrActorHandle, CidrResolution},
    database::{DatabaseActor, DatabaseActorHandle},
    discord::{DiscordActor, DiscordActorHandle},
    new_connection::{InteractionHolder, NewConnectionActor, NewConnectionActorHandle},
    prelude::*,
    server_liveliness::{ServerLivelinessActor, ServerLivelinessActorHandle},
    session::{LoginAttempt, SessionActor, SessionActorHandle, SessionState},
    single_use_token::SingleUseTokenActorHandle,
    RespCell,
};
use crate::{
    actor::{
        cidr::CidrActor,
        database::ChangePasswordAttempt,
        server_liveliness::ServerSpawn,
        single_use_token::SingleUseTokenActor,
        websocket::{
            DiscordLink, IncomingMessage, OutgoingMessage, WebsocketActor, WebsocketActorHandle,
        },
    },
    core::types::{enums::Heuristic, structs::Profile},
    db::drivers::sqlite::Sqlite,
};

pub struct Mailbox {
    sessions: HashMap<String, SessionActorHandle>,
    liveliness: HashMap<Uuid, ServerLivelinessActorHandle>,
    new_ips: HashMap<Ipv4Addr, NewConnectionActorHandle>,
    websockets: HashMap<Uuid, WebsocketActorHandle>,
    cidr: CidrActorHandle,
    database: DatabaseActorHandle,
    discord: DiscordActorHandle,
    tokens: SingleUseTokenActorHandle,
    server_liveliness_channel_id: ChannelId,
    new_ip_fallback_channel_id: ChannelId,
    playing_role_id: RoleId,
    verification_role_id: RoleId,
    guild_id: GuildId,
    self_hnd: WeakUnboundedSender<MailboxCommand>,
}

impl Mailbox {
    pub async fn server_ping(&mut self, server_id: Uuid) {
        debug!("[a:Mailbox] Event:ServerPing RECV ServerLivelinessActor({})", server_id);
        // Check cache in order.
        if let Some(handle) = self.liveliness.get(&server_id) {
            debug!("[a:Mailbox] Event:ServerPing UPDATE ServerLivelinessActor({})", server_id);
            handle.ping();
        } else if let Some(server) = self.database.get_server(server_id).await {
            let handle = ServerLivelinessActor::spawn(
                ServerSpawn {
                    uuid: server.id,
                    name: server.name,
                    game: server.game,
                    versions: server.versions,
                    max_players: server.max_players,
                },
                self.server_liveliness_channel_id,
                self.discord.clone(),
                self.self_hnd.clone(),
            )
            .await;

            self.liveliness.insert(server_id, handle);
            debug!("[a:Mailbox] Event:ServerPing SPAWN ServerLivelinessActor({})", server_id);
        } else {
            warn!("[a:Mailbox] Event:ServerPing NOT_FOUND Server({})", server_id);
        }
    }

    pub async fn server_keepalive(
        &mut self, server_id: Uuid, players: Vec<String>, motd: Option<String>,
    ) {
        if let Some(l_hnd) = self.liveliness.remove(&server_id) {
            let (profiles, visitors) = self.process_playerlist(players).await;
            l_hnd.keep_alive(visitors, profiles, motd);
            debug!("[a:Mailbox] Event:ServerKeepAlive UPDATE ServerLivelinessActor({})", server_id);
            self.liveliness.insert(server_id, l_hnd);
        } else if let Some(server) = self.database.get_server(server_id).await {
            let handle = ServerLivelinessActor::spawn(
                ServerSpawn {
                    uuid: server.id,
                    name: server.name,
                    game: server.game,
                    versions: server.versions,
                    max_players: server.max_players,
                },
                self.server_liveliness_channel_id,
                self.discord.clone(),
                self.self_hnd.clone(),
            )
            .await;
            self.liveliness.insert(server_id, handle.clone());
            debug!("[a:Mailbox] Event:ServerKeepAlive SPAWN ServerLivelinessActor({})", server_id);
            let (profiles, visitors) = self.process_playerlist(players).await;
            handle.keep_alive(visitors, profiles, motd);
        }
    }

    pub async fn session_authenticate(
        &mut self, username: String, password: String, server_id: Uuid,
    ) -> LoginAttempt {
        if let Some(s_hnd) = self.sessions.get(&username) {
            s_hnd.authenticate(server_id, password).await
        } else if let Some(profile) = self.database.get_profile(username.clone()).await {
            let s_hnd = SessionActor::spawn(
                username.clone(),
                Some(profile),
                self.database.clone(),
                self.tokens.clone(),
                self.self_hnd.clone(),
            );
            self.sessions.insert(username.clone(), s_hnd.clone());
            debug!("[a:Mailbox] Event:SessionAuthenticate SPAWN SessionActor({})", username);
            s_hnd.authenticate(server_id, password).await
        } else {
            LoginAttempt::InvalidProfile
        }
    }

    pub async fn session_update_profile(&mut self, username: String, profile: Profile) {
        if let Some(s_hnd) = self.sessions.get(&username) {
            s_hnd.profile_update(profile);
        }
    }

    pub async fn session_restore(&mut self, username: String) -> bool {
        if let Some(s_hnd) = self.sessions.get(&username) {
            matches!(s_hnd.get_state().await, SessionState::LoggedIn { .. })
        } else {
            false
        }
    }

    pub fn cleanup_session(&mut self, username: &String) {
        self.sessions.remove(username);
        debug!("[a:Mailbox] Event:CleanupSession REMOVE SessionActor({})", username);
    }

    pub fn cleanup_liveliness(&mut self, id: &Uuid) {
        self.liveliness.remove(id);
        debug!("[a:Mailbox] Event:CleanupLiveliness REMOVE SessionActor({})", id);
    }

    pub fn cleanup_new_ip(&mut self, ip: &Ipv4Addr) {
        self.new_ips.remove(ip);
    }

    pub async fn profile_check_activity(&self, username: &String, server: Uuid) -> bool {
        debug!(
            "[a:Mailbox] Event:ProfileCheckActivity RECV | username={}, server={}",
            username.clone(),
            server
        );
        if let Some(hnd) = self.sessions.get(username) {
            hnd.check_activity(server).await
        } else {
            false
        }
    }

    pub async fn profile_change_password(
        &self, username: String, old: String, new: String,
    ) -> ChangePasswordAttempt {
        let res = self
            .database
            .change_password(username.clone(), old, new)
            .await;
        if matches!(res, ChangePasswordAttempt::Changed) {
            let new = self.database.get_profile(username.clone()).await.unwrap();
            if let Some(hnd) = self.sessions.get(&username) {
                hnd.profile_update(new);
            }
        }
        res
    }

    pub fn profile_login(&self, username: &String, server: Uuid) {
        if let Some(hnd) = self.sessions.get(username) {
            hnd.join_server(server);
        }
    }

    pub fn profile_logout(&self, username: &String, server: Uuid) {
        if let Some(hnd) = self.sessions.get(username) {
            hnd.leave_server(server);
        }
    }

    pub async fn check_ip(
        &self, ip: Ipv4Addr, username: String, server_id: Uuid,
    ) -> CidrResolution {
        let is_active = self.profile_check_activity(&username, server_id).await;
        self.cidr.check(ip, username, server_id, is_active).await
    }

    pub async fn notify_unknown_ip(&mut self, ip: Ipv4Addr, username: String, server: Uuid) {
        let profile = self
            .database
            .get_profile(username)
            .await
            .expect("Need an profile to send a notification");

        let server_name = self.database.get_server(server).await.unwrap().name;

        let hnd = match self.new_ips.get(&ip) {
            Some(h) => h.clone(),
            None => {
                let hnd = NewConnectionActor::spawn(
                    ip,
                    self.new_ip_fallback_channel_id,
                    self.verification_role_id,
                    self.guild_id,
                    self.discord.clone(),
                    self.database.clone(),
                    self.self_hnd.clone(),
                );

                self.new_ips.insert(ip, hnd.clone());

                hnd
            }
        };

        hnd.notify_new_user(profile, server_name);
    }

    pub fn notify_heuristic(&mut self, ip: Ipv4Addr, heuristic: Heuristic) {
        if let Some(hnd) = self.new_ips.get(&ip) {
            hnd.heuristic_solve(heuristic);
        }
    }

    pub fn btn_ip_clicked_allow(
        &mut self, ip: Ipv4Addr, channel: ChannelId, message: MessageId, author: UserId,
        interaction: InteractionHolder,
    ) {
        if let Some(hnd) = self.new_ips.get(&ip) {
            hnd.btn_click_allow(channel, message, interaction, author);
        }
    }

    pub fn btn_ip_clicked_deny(
        &mut self, ip: Ipv4Addr, channel: ChannelId, message: MessageId, author: UserId,
        interaction: InteractionHolder,
    ) {
        if let Some(hnd) = self.new_ips.get(&ip) {
            hnd.btn_click_deny(channel, message, interaction, author);
        }
    }

    async fn get_profile_otp(&self, profile: Uuid) -> String {
        self.tokens.request_profile(profile).await
    }

    async fn get_discord_manual_link_otp(&self, user: UserId) -> String {
        self.tokens.request_discord(user).await
    }

    fn token_submit_csrf(&self, username: String, csrf: String) {
        self.tokens.submit_csrf(username, csrf)
    }

    async fn get_username_by_csrf(&self, csrf: String) -> Option<String> {
        self.tokens.query_username(csrf).await
    }

    async fn get_userid_by_token(&self, token: String) -> Option<UserId> {
        self.tokens.query_discord(token).await
    }

    fn token_revoke(&self, token: String) {
        self.tokens.clear(token)
    }

    fn ws_initiate(&mut self, server: Uuid, ws: WebSocket<OutgoingMessage, IncomingMessage>) {
        if let Some(hnd) = self.websockets.remove(&server) {
            warn!("[a:Mailbox] Event:WsInitiate({}) REMOVE | Closing old websocket.", server);
            hnd.close(Some(CloseFrame {
                code: 1000,
                reason:
                    "Closing since another websocket connection has started for the same server."
                        .into(),
            }));
        }
        trace!("[a:Mailbox] Event:WsInitiate({}) SPAWN WebsocketActor", server);
        let hnd = WebsocketActor::spawn(ws, server, self.self_hnd.clone());

        self.websockets.insert(server, hnd);
    }

    fn ws_send_discord_link(&self, link: &DiscordLink) {
        // We actually broadcast this to everyone since we dont know where it came from.
        for hnd in self.websockets.values() {
            hnd.send_discord_link(link.clone());
        }
    }

    async fn grant_playing_role(&self, username: String) {
        if let Some(profile) = self.database.get_profile(username).await {
            self.discord.grant_role(
                profile.discord_id.parse().unwrap(),
                self.guild_id,
                self.playing_role_id,
            );
        }
    }

    async fn revoke_playing_role(&self, username: String) {
        if let Some(profile) = self.database.get_profile(username).await {
            self.discord.revoke_role(
                profile.discord_id.parse().unwrap(),
                self.guild_id,
                self.playing_role_id,
            );
        }
    }

    async fn grant_verification_role(&self, username: String) {
        if let Some(profile) = self.database.get_profile(username).await {
            self.discord.grant_role(
                profile.discord_id.parse().unwrap(),
                self.guild_id,
                self.verification_role_id,
            );
        }
    }

    async fn revoke_verification_role(&self, username: String) {
        if let Some(profile) = self.database.get_profile(username).await {
            self.discord.revoke_role(
                profile.discord_id.parse().unwrap(),
                self.guild_id,
                self.verification_role_id,
            );
        }
    }

    async fn process_playerlist(
        &mut self, players: Vec<String>,
    ) -> (Vec<SessionState>, Vec<String>) {
        let mut members: Vec<_> = vec![];
        let mut visitors: Vec<_> = vec![];
        for username in players {
            // Check the cache!
            if let Some(u_hnd) = self.sessions.get(&username) {
                u_hnd.ping();
                let state = u_hnd.get_state().await;
                match state {
                    super::session::SessionState::Visitor => {
                        visitors.push(username.clone());
                    }
                    _ => members.push(state),
                }
            } else {
                let profile = self.database.get_profile(username.clone()).await;
                let new_actor = SessionActor::spawn(
                    username.clone(),
                    profile.clone(),
                    self.database.clone(),
                    self.tokens.clone(),
                    self.self_hnd.clone(),
                );

                self.sessions.insert(username.clone(), new_actor.clone());
                debug!("[a:Mailbox] Event:ServerKeepAlive SPAWN SessionActor({})", username);

                if profile.is_some() {
                    members.push(new_actor.get_state().await);
                } else {
                    visitors.push(username.clone());
                }
            }
        }
        (members, visitors)
    }
}
#[allow(clippy::large_enum_variant)]
pub enum MailboxCommand {
    SessionProfileUpdate(String, Profile),
    SessionAuthenticate {
        username: String,
        password: String,
        server_id: Uuid,
        tx: RespCell<LoginAttempt>,
    },

    SessionRestore(String, RespCell<bool>),

    /* Profile-Server Interaction */
    ProfileLogin(String, Uuid),
    ProfileLogout(String, Uuid),
    ProfileCheckActivity(String, Uuid, RespCell<bool>),
    ProfileChangePassword {
        username: String,
        old: String,
        new: String,
        tx: RespCell<ChangePasswordAttempt>,
    },

    /* Discord Role-related interactions */
    GrantPlayingRole(String),
    RevokePlayingRole(String),
    GrantVerificationRole(String),
    RevokeVerificationRole(String),

    /* Websockets */
    WsInitiate(Uuid, WebSocket<OutgoingMessage, IncomingMessage>),
    WsSendDiscordLink(DiscordLink),
    /* Game Server Notifications */
    ServerPing(Uuid),
    ServerKeepAlive {
        id: Uuid,
        players: Vec<String>,
        motd: Option<String>,
    },

    /* Actually checking Ip Addresses */
    CheckIp(Ipv4Addr, String, Uuid, RespCell<CidrResolution>),

    /* Single-use tokens */
    GetProfileOTP(Uuid, RespCell<String>),
    GetDiscordManualLinkOTP(UserId, RespCell<String>),
    TokensSubmitCsrf(String, String),
    GetUserByCsrf(String, RespCell<Option<String>>),
    GetUserIdByToken(String, RespCell<Option<UserId>>),
    TokenRevoke(String),

    /* Discord Button Interactions */
    BtnIpClickedAllow(Ipv4Addr, ChannelId, MessageId, UserId, InteractionHolder),
    BtnIpClickedDeny(Ipv4Addr, ChannelId, MessageId, UserId, InteractionHolder),

    /* Cidr Actor -> Discord Notification */
    NotifyUnknownIp {
        ip: Ipv4Addr,
        username: String,
        server: Uuid,
    },

    NotifyHeurisiticSolve(Ipv4Addr, Heuristic),

    /* Cleanup Notifications */
    CleanupLiveliness(Uuid),
    CleanupSession(String),
    CleanupNewIp(Ipv4Addr),
}

pub struct MailboxActor {
    state: Mailbox,
    queue: mpsc::UnboundedReceiver<MailboxCommand>,
}

impl MailboxActor {
    pub fn spawn(
        db: Arc<Sqlite>, discord: Arc<serenity::Client>, server_liveliness_channel_id: ChannelId,
        new_ip_fallback_channel_id: ChannelId, verification_role_id: RoleId,
        playing_role_id: RoleId, guild_id: GuildId,
    ) -> MailboxActorHandle {
        debug!("[a:Mailbox] SPAWN");

        let (tx, rx) = mpsc::unbounded_channel();

        let db_hnd = DatabaseActor::spawn(db);
        let discord_hnd = DiscordActor::spawn(discord);
        let cidr_hnd = CidrActor::spawn(db_hnd.clone(), tx.downgrade());
        let otp_hnd = SingleUseTokenActor::spawn();

        let actor = Self {
            state: Mailbox {
                sessions: HashMap::new(),
                liveliness: HashMap::new(),
                new_ips: HashMap::new(),
                websockets: HashMap::new(),
                cidr: cidr_hnd,
                database: db_hnd,
                discord: discord_hnd,
                tokens: otp_hnd,
                server_liveliness_channel_id,
                new_ip_fallback_channel_id,
                self_hnd: tx.downgrade(),
                playing_role_id,
                verification_role_id,
                guild_id,
            },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        MailboxActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        debug!("[a:Mailbox] RUN");
        while let Some(cmd) = self.queue.recv().await {
            trace!("[MailboxQueue] RECV");
            match cmd {
                MailboxCommand::SessionProfileUpdate(u, p) => {
                    self.state.session_update_profile(u, p).await;
                }
                MailboxCommand::SessionAuthenticate { username, password, server_id, tx } => {
                    let k = self
                        .state
                        .session_authenticate(username, password, server_id)
                        .await;
                    let _ = tx.send(k);
                }
                MailboxCommand::SessionRestore(user, res) => {
                    let k = self.state.session_restore(user).await;
                    let _ = res.send(k);
                }
                MailboxCommand::ProfileCheckActivity(user, server, res) => {
                    let k = self.state.profile_check_activity(&user, server).await;
                    let _ = res.send(k);
                }
                MailboxCommand::ProfileChangePassword { username, old, new, tx } => {
                    let k = self.state.profile_change_password(username, old, new).await;
                    let _ = tx.send(k);
                }
                MailboxCommand::ProfileLogin(user, server) => {
                    self.state.profile_login(&user, server)
                }
                MailboxCommand::ProfileLogout(user, server) => {
                    self.state.profile_logout(&user, server)
                }
                MailboxCommand::ServerPing(id) => {
                    self.state.server_ping(id).await;
                }
                MailboxCommand::ServerKeepAlive { id, players, motd } => {
                    self.state.server_keepalive(id, players, motd).await;
                }
                MailboxCommand::CleanupLiveliness(id) => self.state.cleanup_liveliness(&id),
                MailboxCommand::CleanupSession(name) => self.state.cleanup_session(&name),
                MailboxCommand::CleanupNewIp(ip) => self.state.cleanup_new_ip(&ip),
                MailboxCommand::CheckIp(ip, u, s, res) => {
                    let k = self.state.check_ip(ip, u, s).await;
                    let _ = res.send(k);
                }
                MailboxCommand::NotifyUnknownIp { ip, username, server } => {
                    self.state.notify_unknown_ip(ip, username, server).await;
                }
                MailboxCommand::NotifyHeurisiticSolve(ip, h) => {
                    self.state.notify_heuristic(ip, h);
                }
                MailboxCommand::BtnIpClickedAllow(ip, ch, msg, u, ih) => {
                    self.state.btn_ip_clicked_allow(ip, ch, msg, u, ih);
                }
                MailboxCommand::BtnIpClickedDeny(ip, ch, msg, u, ih) => {
                    self.state.btn_ip_clicked_deny(ip, ch, msg, u, ih);
                }
                MailboxCommand::GetProfileOTP(p, res) => {
                    let k = self.state.get_profile_otp(p).await;
                    res.send(k).unwrap_or(())
                }
                MailboxCommand::GetDiscordManualLinkOTP(u, res) => {
                    let k = self.state.get_discord_manual_link_otp(u).await;
                    res.send(k).unwrap_or(())
                }
                MailboxCommand::TokensSubmitCsrf(u, c) => {
                    self.state.token_submit_csrf(u, c);
                }
                MailboxCommand::GetUserByCsrf(csrf, res) => {
                    let k = self.state.get_username_by_csrf(csrf).await;
                    res.send(k).unwrap_or(())
                }
                MailboxCommand::GetUserIdByToken(token, res) => {
                    let k = self.state.get_userid_by_token(token).await;
                    res.send(k).unwrap_or(())
                }
                MailboxCommand::TokenRevoke(token) => self.state.token_revoke(token),
                MailboxCommand::WsInitiate(uuid, ws) => {
                    self.state.ws_initiate(uuid, ws);
                }
                MailboxCommand::WsSendDiscordLink(discord_link) => {
                    self.state.ws_send_discord_link(&discord_link);
                }
                MailboxCommand::GrantPlayingRole(u) => self.state.grant_playing_role(u).await,
                MailboxCommand::RevokePlayingRole(u) => self.state.revoke_playing_role(u).await,
                MailboxCommand::GrantVerificationRole(u) => {
                    self.state.grant_verification_role(u).await
                }
                MailboxCommand::RevokeVerificationRole(u) => {
                    self.state.revoke_verification_role(u).await
                }
            }
        }
        debug!("[a:Mailbox] FINISH");
    }
}

#[derive(Clone)]
pub struct MailboxActorHandle {
    pub queue: mpsc::UnboundedSender<MailboxCommand>,
}

impl MailboxActorHandle {
    pub fn session_profile_update(&self, username: String, profile: Profile) {
        self.queue
            .send(MailboxCommand::SessionProfileUpdate(username, profile))
            .expect("Dropped actors have no handles.");
    }

    pub async fn session_authenticate(
        &self, username: String, password: String, server_id: Uuid,
    ) -> LoginAttempt {
        ask_actor!(self.queue, MailboxCommand::SessionAuthenticate {
            username,
            password,
            server_id
        });
    }

    pub async fn session_restore(&self, username: String) -> bool {
        ask_actor!(self.queue, MailboxCommand::SessionRestore(username));
    }

    pub async fn profile_check_activity(&self, username: String, server: Uuid) -> bool {
        ask_actor!(self.queue, MailboxCommand::ProfileCheckActivity(username, server));
    }

    pub async fn profile_change_password(
        &self, username: String, old: String, new: String,
    ) -> ChangePasswordAttempt {
        ask_actor!(self.queue, MailboxCommand::ProfileChangePassword { username, old, new });
    }

    pub fn profile_login(&self, username: String, server: Uuid) {
        notify_actor!(self.queue, MailboxCommand::ProfileLogin(username, server));
    }

    pub fn profile_logout(&self, username: String, server: Uuid) {
        notify_actor!(self.queue, MailboxCommand::ProfileLogout(username, server));
    }

    pub fn server_ping(&self, id: Uuid) {
        notify_actor!(self.queue, MailboxCommand::ServerPing(id));
    }

    pub fn server_keepalive(&self, id: Uuid, players: Vec<String>, motd: Option<String>) {
        notify_actor!(self.queue, MailboxCommand::ServerKeepAlive { id, players, motd });
    }

    pub fn cleanup_liveliness(&self, id: Uuid) {
        notify_actor!(self.queue, MailboxCommand::CleanupLiveliness(id));
    }

    pub fn cleanup_session(&self, username: String) {
        notify_actor!(self.queue, MailboxCommand::CleanupSession(username));
    }

    pub async fn check_ip(&self, ip: Ipv4Addr, username: String, server: Uuid) -> CidrResolution {
        ask_actor!(self.queue, MailboxCommand::CheckIp(ip, username, server));
    }

    pub fn btn_ip_clicked_allow(
        &self, ip: Ipv4Addr, channel: ChannelId, message: MessageId, author: UserId,
        interaction: InteractionHolder,
    ) {
        notify_actor!(
            self.queue,
            MailboxCommand::BtnIpClickedAllow(ip, channel, message, author, interaction)
        );
    }

    pub fn btn_ip_clicked_deny(
        &self, ip: Ipv4Addr, channel: ChannelId, message: MessageId, author: UserId,
        interaction: InteractionHolder,
    ) {
        notify_actor!(
            self.queue,
            MailboxCommand::BtnIpClickedDeny(ip, channel, message, author, interaction)
        );
    }

    pub fn notify_unknown_ip(&mut self, ip: Ipv4Addr, username: String, server: Uuid) {
        notify_actor!(self.queue, MailboxCommand::NotifyUnknownIp { ip, username, server });
    }

    pub async fn get_profile_otp(&self, profile: Uuid) -> String {
        ask_actor!(self.queue, MailboxCommand::GetProfileOTP(profile));
    }

    pub async fn get_discord_manual_link_otp(&self, user: UserId) -> String {
        ask_actor!(self.queue, MailboxCommand::GetDiscordManualLinkOTP(user));
    }

    pub fn tokens_submit_csrf(&self, username: String, csrf: String) {
        notify_actor!(self.queue, MailboxCommand::TokensSubmitCsrf(username, csrf));
    }

    pub async fn get_user_by_csrf(&self, csrf: String) -> Option<String> {
        ask_actor!(self.queue, MailboxCommand::GetUserByCsrf(csrf));
    }

    pub async fn get_userid_by_token(&self, token: String) -> Option<UserId> {
        ask_actor!(self.queue, MailboxCommand::GetUserIdByToken(token));
    }

    pub fn token_revoke(&self, token: String) {
        notify_actor!(self.queue, MailboxCommand::TokenRevoke(token));
    }

    pub fn grant_playing_role(&self, username: String) {
        notify_actor!(self.queue, MailboxCommand::GrantPlayingRole(username));
    }

    pub fn revoke_playing_role(&self, username: String) {
        notify_actor!(self.queue, MailboxCommand::RevokePlayingRole(username));
    }

    pub fn grant_verification_role(&self, username: String) {
        notify_actor!(self.queue, MailboxCommand::GrantVerificationRole(username));
    }

    pub fn revoke_verification_role(&self, username: String) {
        notify_actor!(self.queue, MailboxCommand::RevokeVerificationRole(username));
    }

    pub fn ws_initiate(&self, server: Uuid, ws: WebSocket<OutgoingMessage, IncomingMessage>) {
        notify_actor!(self.queue, MailboxCommand::WsInitiate(server, ws));
    }

    pub fn ws_send_discord_link(&self, link: DiscordLink) {
        notify_actor!(self.queue, MailboxCommand::WsSendDiscordLink(link));
    }
}
