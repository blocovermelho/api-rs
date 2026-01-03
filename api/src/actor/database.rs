use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use chrono::TimeDelta;
use serenity::all::UserId;
use uuid::Uuid;

use super::prelude::*;
use crate::{
    ask_actor,
    core::{
        trans::db::TryIngest,
        types::{
            consts::{self, cidr::MIN_V4_MASK},
            enums::ConnectionData,
            structs::{Connection, GameServer, Profile},
        },
    },
    db::{
        data::{Allowlist, BanIssuer, Blacklist},
        drivers::sqlite::Sqlite,
        interface::DataSource,
    },
    notify_actor,
};

/*
 * Database Actor
 */

pub struct DatabaseA(Arc<Sqlite>);

impl DatabaseA {
    pub async fn get_profile(&self, username: String) -> Option<Profile> {
        let db = self.0.clone();
        if let Ok(dbd) = db.get_profile(username).await {
            let p = Profile::from(dbd);

            let db_conn = db
                .get_connections_by_profile(&p.id)
                .await
                .unwrap_or_default();

            let mut known_connections = vec![];

            for conn in db_conn {
                if let Ok(valid) = Connection::try_ingest(conn, db.clone()).await {
                    known_connections.push(valid);
                };
            }
            Some(Profile { connections: known_connections, ..p })
        } else {
            None
        }
    }

    pub async fn get_profile_id(&self, profile_uuid: Uuid) -> Option<Profile> {
        let db = self.0.clone();
        if let Ok(dbd) = db.get_profile_by_id(&profile_uuid).await {
            let p = Profile::from(dbd);

            let db_conn = db
                .get_connections_by_profile(&p.id)
                .await
                .unwrap_or_default();

            let mut known_connections = vec![];

            for conn in db_conn {
                if let Ok(valid) = Connection::try_ingest(conn, db.clone()).await {
                    known_connections.push(valid);
                };
            }
            Some(Profile { connections: known_connections, ..p })
        } else {
            None
        }
    }

    async fn get_profiles(&self, discord_id: UserId) -> Vec<Profile> {
        let db = &self.0;
        let dbd = db
            .get_profiles_by_discord_id(discord_id.to_string())
            .await
            .unwrap_or_default();

        let mut profs = vec![];

        for d in dbd {
            let p = Profile::from(d);

            let db_conn = db
                .get_connections_by_profile(&p.id)
                .await
                .unwrap_or_default();

            let mut known_connections = vec![];

            for conn in db_conn {
                if let Ok(valid) = Connection::try_ingest(conn, db.clone()).await {
                    known_connections.push(valid);
                };
            }

            profs.push(Profile { connections: known_connections, ..p });
        }

        profs
    }

    pub async fn get_server(&self, server_uuid: Uuid) -> Option<GameServer> {
        let db = self.0.clone();
        if let Ok(dbd) = db.get_server(&server_uuid).await {
            Some(GameServer::from(dbd))
        } else {
            None
        }
    }

    pub async fn check_password(&self, profile_uuid: Uuid, password: String) -> Option<bool> {
        let db = self.0.clone();
        if let Ok(dbd) = db.get_profile_by_id(&profile_uuid).await {
            let check = bcrypt::verify(password, &dbd.password).unwrap_or(false);
            Some(check)
        } else {
            None
        }
    }

    pub async fn change_password(
        &self, username: String, old: String, new: String,
    ) -> ChangePasswordAttempt {
        let db = self.0.clone();
        if let Ok(dbd) = db.get_profile(username).await {
            if bcrypt::verify(old, &dbd.password).unwrap_or(false) {
                let hash = bcrypt::hash(new, 12).unwrap();
                db.update_password(&dbd.uuid, hash).await.unwrap_or(());
                ChangePasswordAttempt::Changed
            } else {
                ChangePasswordAttempt::InvalidPassword
            }
        } else {
            ChangePasswordAttempt::InvalidProfile
        }
    }

    pub async fn increase_playtime(
        &self, server_uuid: Uuid, profile_uuid: Uuid, delta: TimeDelta,
    ) -> Result<(), IncreasePlaytimeError> {
        let _ = self
            .get_server(server_uuid)
            .await
            .ok_or(IncreasePlaytimeError::UnknownServer)?;

        let profile = self
            .get_profile_id(profile_uuid)
            .await
            .ok_or(IncreasePlaytimeError::UnknownProfile)?;

        if let Ok(existing) = self
            .0
            .get_connection(&profile_uuid, consts::connection_ids::PLAYTIME)
            .await
        {
            if let Ok(valid) = Connection::try_ingest(existing, self.0.clone()).await {
                if let ConnectionData::Playtime(mut map) = valid.extra {
                    if let Some(existing) = map.remove(&server_uuid) {
                        let playtime = existing + delta.to_std().unwrap();
                        map.insert(server_uuid, playtime);

                        let _ = self
                            .0
                            .update_connection(
                                Connection {
                                    issuer: valid.issuer,
                                    profile: valid.profile,
                                    extra: ConnectionData::Playtime(map),
                                }
                                .into(),
                            )
                            .await;
                    } else {
                        map.insert(server_uuid, delta.to_std().unwrap());

                        let _ = self
                            .0
                            .create_connection(
                                Connection {
                                    issuer: valid.issuer,
                                    profile: valid.profile,
                                    extra: ConnectionData::Playtime(map),
                                }
                                .into(),
                            )
                            .await;
                    }
                }
            }
        } else {
            let mut map = HashMap::new();
            map.insert(server_uuid, delta.to_std().unwrap());

            let _ = self
                .0
                .create_connection(
                    Connection {
                        issuer: Some(server_uuid),
                        profile,
                        extra: ConnectionData::Playtime(map),
                    }
                    .into(),
                )
                .await;
        }

        Ok(())
    }

    async fn get_allowlists(&self, profile: &Uuid, ip: Ipv4Addr) -> Vec<Allowlist> {
        self.0
            .get_allowlists_with_range(profile, ip, MIN_V4_MASK)
            .await
            .unwrap_or_default()
    }

    async fn get_blacklists(&self, ip: Ipv4Addr) -> Vec<Blacklist> {
        self.0
            .get_blacklists_with_range(ip, MIN_V4_MASK)
            .await
            .unwrap_or_default()
    }

    async fn create_allowlist(&self, profile: &Uuid, ip: Ipv4Addr) -> Allowlist {
        if let Ok(ret) = self.0.create_allowlist(profile, ip).await {
            ret
        } else {
            self.get_allowlists(profile, ip)
                .await
                .first()
                .unwrap()
                .clone()
        }
    }

    async fn broaden_allowlist(&self, allowlist: Allowlist, mask: u8) {
        let _ = self.0.broaden_allowlist_mask(allowlist, mask).await;
    }

    async fn bump_allowlist(&self, allowlist: Allowlist) {
        let _ = self.0.bump_allowlist(allowlist).await;
    }

    async fn create_blacklist(&self, ip: Ipv4Addr, actor: BanIssuer) -> Blacklist {
        if let Ok(res) = self.0.create_blacklist(ip, actor).await {
            res
        } else {
            self.get_blacklists(ip).await.first().unwrap().clone()
        }
    }

    async fn broaden_blacklist(&self, blacklist: Blacklist, mask: u8) {
        let _ = self.0.broaden_blacklist_mask(blacklist, mask).await;
    }

    async fn bump_blacklist(&self, blacklist: Blacklist) {
        let _ = self.0.bump_blacklist(blacklist).await;
    }
}

pub enum IncreasePlaytimeError {
    UnknownProfile,
    UnknownServer,
}

pub enum DatabaseCommand {
    GetProfile(String, RespCell<Option<Profile>>),
    GetProfileId(Uuid, RespCell<Option<Profile>>),
    GetProfiles(UserId, RespCell<Vec<Profile>>),
    GetServer(Uuid, RespCell<Option<GameServer>>),
    CheckPassword(Uuid, String, RespCell<Option<bool>>),
    ChangePassword {
        username: String,
        old: String,
        new: String,
        tx: RespCell<ChangePasswordAttempt>,
    },
    IncreasePlaytime {
        server_uuid: Uuid,
        profile_uuid: Uuid,
        delta: TimeDelta,
    },
    GetAllowlists(Uuid, Ipv4Addr, RespCell<Vec<Allowlist>>),
    GetBlacklists(Ipv4Addr, RespCell<Vec<Blacklist>>),
    CreateAllowlist(Uuid, Ipv4Addr, RespCell<Allowlist>),
    BroadenAllowlist(Allowlist, u8),
    BumpAllowlist(Allowlist),
    CreateBlacklist(Ipv4Addr, BanIssuer, RespCell<Blacklist>),
    BroadenBlacklist(Blacklist, u8),
    BumpBlacklist(Blacklist),
}

pub struct DatabaseActor {
    state: DatabaseA,
    queue: mpsc::UnboundedReceiver<DatabaseCommand>,
}

impl DatabaseActor {
    pub fn spawn(db: Arc<Sqlite>) -> DatabaseActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor = Self { state: DatabaseA(db), queue: rx };

        tokio::spawn(async move { actor.run().await });

        DatabaseActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.queue.recv().await {
            match cmd {
                DatabaseCommand::GetProfile(name, res) => {
                    let k = self.state.get_profile(name).await;
                    let _ = res.send(k);
                }
                DatabaseCommand::GetProfileId(id, res) => {
                    let k = self.state.get_profile_id(id).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::GetProfiles(discord, res) => {
                    let k = self.state.get_profiles(discord).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::GetServer(id, res) => {
                    let k = self.state.get_server(id).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::CheckPassword(id, password, res) => {
                    let k = self.state.check_password(id, password).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::ChangePassword { username, old, new, tx } => {
                    let k = self.state.change_password(username, old, new).await;
                    tx.send(k).unwrap_or(());
                }
                DatabaseCommand::IncreasePlaytime { server_uuid, profile_uuid, delta } => {
                    let _ = self
                        .state
                        .increase_playtime(server_uuid, profile_uuid, delta)
                        .await;
                }
                DatabaseCommand::GetAllowlists(profile, ip, res) => {
                    let k = self.state.get_allowlists(&profile, ip).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::GetBlacklists(ip, res) => {
                    let k = self.state.get_blacklists(ip).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::CreateAllowlist(id, ip, res) => {
                    let k = self.state.create_allowlist(&id, ip).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::BroadenAllowlist(a, mask) => {
                    self.state.broaden_allowlist(a, mask).await
                }
                DatabaseCommand::BumpAllowlist(a) => self.state.bump_allowlist(a).await,
                DatabaseCommand::CreateBlacklist(ip, issuer, res) => {
                    let k = self.state.create_blacklist(ip, issuer).await;
                    res.send(k).unwrap_or(());
                }
                DatabaseCommand::BroadenBlacklist(b, mask) => {
                    self.state.broaden_blacklist(b, mask).await;
                }
                DatabaseCommand::BumpBlacklist(b) => self.state.bump_blacklist(b).await,
            }
        }
    }
}

#[derive(Clone)]
pub struct DatabaseActorHandle {
    queue: mpsc::UnboundedSender<DatabaseCommand>,
}

impl DatabaseActorHandle {
    pub async fn get_profile(&self, username: String) -> Option<Profile> {
        ask_actor!(self.queue, DatabaseCommand::GetProfile(username));
    }

    pub async fn get_profile_id(&self, profile_id: Uuid) -> Option<Profile> {
        ask_actor!(self.queue, DatabaseCommand::GetProfileId(profile_id));
    }

    pub async fn get_profiles(&self, discord_id: UserId) -> Vec<Profile> {
        ask_actor!(self.queue, DatabaseCommand::GetProfiles(discord_id));
    }

    pub async fn get_server(&self, server_id: Uuid) -> Option<GameServer> {
        ask_actor!(self.queue, DatabaseCommand::GetServer(server_id));
    }

    pub async fn check_password(&self, profile_id: Uuid, password: String) -> Option<bool> {
        ask_actor!(self.queue, DatabaseCommand::CheckPassword(profile_id, password));
    }

    pub async fn change_password(
        &self, username: String, old: String, new: String,
    ) -> ChangePasswordAttempt {
        ask_actor!(self.queue, DatabaseCommand::ChangePassword { username, old, new });
    }

    pub fn increase_playtime(&self, server_uuid: Uuid, profile_uuid: Uuid, delta: TimeDelta) {
        notify_actor!(self.queue, DatabaseCommand::IncreasePlaytime {
            server_uuid,
            profile_uuid,
            delta
        });
    }

    pub async fn create_allowlist(&self, profile_uuid: Uuid, ip: Ipv4Addr) -> Allowlist {
        ask_actor!(self.queue, DatabaseCommand::CreateAllowlist(profile_uuid, ip));
    }

    pub async fn get_allowlists(&self, profile_uuid: Uuid, ip: Ipv4Addr) -> Vec<Allowlist> {
        ask_actor!(self.queue, DatabaseCommand::GetAllowlists(profile_uuid, ip));
    }

    pub fn broaden_allowlist(&self, allowlist: Allowlist, mask: u8) {
        notify_actor!(self.queue, DatabaseCommand::BroadenAllowlist(allowlist, mask));
    }

    pub fn bump_allowlist(&self, allowlist: Allowlist) {
        notify_actor!(self.queue, DatabaseCommand::BumpAllowlist(allowlist));
    }

    pub async fn create_blacklist(&self, ip: Ipv4Addr, issuer: BanIssuer) -> Blacklist {
        ask_actor!(self.queue, DatabaseCommand::CreateBlacklist(ip, issuer));
    }

    pub async fn get_blacklists(&self, ip: Ipv4Addr) -> Vec<Blacklist> {
        ask_actor!(self.queue, DatabaseCommand::GetBlacklists(ip));
    }

    pub fn broaden_blacklist(&self, blacklist: Blacklist, mask: u8) {
        notify_actor!(self.queue, DatabaseCommand::BroadenBlacklist(blacklist, mask));
    }

    pub fn bump_blacklist(&self, blacklist: Blacklist) {
        notify_actor!(self.queue, DatabaseCommand::BumpBlacklist(blacklist));
    }

    pub async fn close(self) {
        drop(self.queue);
    }

    pub fn mock() -> (Self, mpsc::UnboundedReceiver<DatabaseCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { queue: tx }, rx)
    }
}

/*
 * Auxiliary Types
 */

pub enum ChangePasswordAttempt {
    InvalidProfile,
    InvalidPassword,
    Changed,
}
