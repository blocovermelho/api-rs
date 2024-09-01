use core::time;
use std::{fmt::Display, net::Ipv4Addr};

use chrono::Utc;
use sqlx::{types::Json, SqliteConnection};
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::{
    data::{
        self,
        result::{
            CIDRCheck, PardonAttempt, PasswordCheck, PasswordModify, PlaytimeUpdate, SessionCheck,
            SessionRevoke, SessionUpdate,
        },
        Account, Allowlist, BanActor, Blacklist, Loc, SaveData, Server, User, Viewport,
    },
    drivers::MAX_SESSION_TIME_MINUTE,
    helper::{check_cidr, CidrAction},
    interface::{DataSource, NetworkProvider},
};

#[derive(Debug)]
pub struct Sqlite {
    conn: SqliteConnection,
}

impl Sqlite {
    pub fn new(conn: SqliteConnection) -> Self {
        Self { conn }
    }
}

fn ok_or_log<T, E>(either: Result<T, E>) -> Option<T>
where
    E: Display,
{
    match either {
        Ok(value) => Some(value),
        Err(e) => {
            error!("{e}");
            None
        }
    }
}

impl DataSource for Sqlite {
    #[tracing::instrument]
    async fn get_user_by_uuid(&mut self, uuid: &uuid::Uuid) -> Option<User> {
        let query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE uuid = ?")
            .bind(uuid)
            .fetch_optional(&mut self.conn)
            .await;

        ok_or_log(query).flatten()
    }

    #[tracing::instrument]
    async fn get_users_by_discord_id(&mut self, discord_id: String) -> Vec<User> {
        let query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE discord_id = ?")
            .bind(discord_id)
            .fetch_all(&mut self.conn)
            .await;

        ok_or_log(query).unwrap_or_default()
    }

    #[tracing::instrument]
    async fn create_user(&mut self, stub: data::stub::UserStub) -> Option<User> {
        let query = sqlx::query_as::<_, User>("INSERT INTO users (uuid, username, discord_id, created_at, pronouns) VALUES ($1, $2, $3, $4, $5) RETURNING * ")
        .bind(stub.uuid)
        .bind(stub.username)
        .bind(stub.discord_id)
        .bind(Utc::now())
        .bind("[]")
        .fetch_one(&mut self.conn)
        .await;

        ok_or_log(query)
    }

    #[tracing::instrument]
    async fn delete_user(&mut self, uuid: &uuid::Uuid) -> Option<User> {
        let query = sqlx::query_as::<_, User>("DELETE FROM users WHERE uuid == ? RETURNING *")
            .bind(uuid)
            .fetch_one(&mut self.conn)
            .await;

        ok_or_log(query)
    }

    #[tracing::instrument]
    async fn migrate_user(&mut self, from: &uuid::Uuid, into: &uuid::Uuid) -> Option<User> {
        let fromUser = self.get_user_by_uuid(from).await?;
        let intoUser = self.get_user_by_uuid(into).await?;

        let query = sqlx::query_as::<_, User>(
            "UPDATE users SET created_at = $1, pronouns = $2 WHERE uuid = $3 RETURNING *",
        )
        .bind(fromUser.created_at)
        .bind(fromUser.pronouns)
        .bind(intoUser.uuid)
        .fetch_one(&mut self.conn)
        .await;

        ok_or_log(query)
    }

    #[tracing::instrument(skip(stub))]
    async fn create_account(&mut self, stub: data::stub::AccountStub) -> bool {
        let hash = bcrypt::hash(stub.password, 12);
        if let Some(pwd) = ok_or_log(hash) {
            let account = Account {
                uuid: stub.uuid,
                password: pwd.to_string(),
                current_join: Utc::now(),
            };

            let query = sqlx::query_as::<_,Account>("INSERT INTO accounts (uuid, password, current_join) VALUES ($1, $2, $3) RETURNING *")
            .bind(account.uuid)
            .bind(account.password)
            .bind(account.current_join)
            .fetch_one(&mut self.conn)
            .await;

            ok_or_log(query).is_some()
        } else {
            false
        }
    }

    #[tracing::instrument(skip(password))]
    async fn check_password(
        &mut self,
        player_uuid: &uuid::Uuid,
        password: String,
    ) -> PasswordCheck {
        let query = sqlx::query_as::<_, Account>("SELECT * FROM accounts WHERE uuid = ?")
            .bind(player_uuid)
            .fetch_one(&mut self.conn)
            .await;

        let acc = ok_or_log(query);
        match acc {
            Some(acc) => {
                let verify = bcrypt::verify(password, acc.password.as_str());
                let is_ok = ok_or_log(verify);

                match is_ok {
                    Some(is_ok) => {
                        if is_ok {
                            PasswordCheck::Correct
                        } else {
                            // TODO: Implement Attempt Counting
                            PasswordCheck::InvalidPassword(0)
                        }
                    }
                    None => PasswordCheck::Unregistered,
                }
            }
            None => PasswordCheck::Unregistered,
        }
    }

    #[tracing::instrument(skip(old_password, new_password))]
    async fn modify_password(
        &mut self,
        player_uuid: &uuid::Uuid,
        old_password: String,
        new_password: String,
    ) -> PasswordModify {
        let check = self.check_password(player_uuid, old_password).await;
        match check {
            PasswordCheck::Correct => {
                let hash = bcrypt::hash(new_password, 12);
                let pwd = ok_or_log(hash);
                match pwd {
                    Some(pwd) => {
                        let query =
                            sqlx::query("UPDATE accounts SET password = $1 WHERE uuid = $2")
                                .bind(pwd)
                                .bind(player_uuid)
                                .execute(&mut self.conn)
                                .await;

                        return if ok_or_log(query).is_some() {
                            PasswordModify::Modified
                        } else {
                            PasswordModify::Unregistered
                        };
                    }
                    None => PasswordModify::Unregistered,
                }
            }
            PasswordCheck::InvalidPassword(x) => PasswordModify::InvalidPassword(x),
            PasswordCheck::Unregistered => PasswordModify::Unregistered,
        }
    }

    #[tracing::instrument]
    /// Note: This *only* migrates the password of an account. Not its previous IP login history.
    async fn migrate_account(&mut self, from: &uuid::Uuid, to: &uuid::Uuid) -> bool {
        let query = sqlx::query("UPDATE accounts SET password = (SELECT password FROM accounts WHERE uuid = $1) WHERE uuid = $2")
        .bind(from)
        .bind(to)
        .execute(&mut self.conn)
        .await;

        ok_or_log(query).is_some()
    }

    #[tracing::instrument]
    async fn delete_account(&mut self, player_uuid: &uuid::Uuid) -> bool {
        let query = sqlx::query("DELETE FROM accounts WHERE uuid == ?")
            .bind(player_uuid)
            .execute(&mut self.conn)
            .await;

        ok_or_log(query).is_some()
    }

    async fn check_cidr(&mut self, player_uuid: &uuid::Uuid, ip: std::net::Ipv4Addr) -> CIDRCheck {
        // We first select from the allowlist, to know if the IP is valid for the given player.
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist WHERE uuid = $1 SORT BY last_join DESC",
        )
        .bind(player_uuid)
        .fetch_all(&mut self.conn)
        .await;

        match check_cidr(ok_or_log(query).unwrap_or_default(), ip) {
            CidrAction::Match(net) => {
                let allowlist = Allowlist {
                    uuid: net.uuid,
                    ip_range: net.ip_range,
                    last_join: Utc::now(),
                    hits: net.hits + 1,
                };

                // Increase the hit count.
                let update = sqlx::query_as::<_,Allowlist>("UPDATE allowlist SET hits = $1, last_join = $2 WHERE ip_range = $3 AND uuid = $4")
                    .bind(allowlist.hits)
                    .bind(allowlist.last_join)
                    .bind(allowlist.ip_range)
                    .bind(allowlist.uuid)
                    .fetch_one(&mut self.conn)
                    .await;

                ok_or_log(update);
                CIDRCheck::ValidIp(allowlist)
            }
            CidrAction::MaskUpdate(net, mask) => {
                // New netmask
                let new_net = net.with_mask(mask);

                let allowlist = Allowlist {
                    uuid: net.uuid,
                    ip_range: Json(new_net),
                    last_join: Utc::now(),
                    hits: net.hits + 1,
                };

                let update = sqlx::query("UPDATE allowlist SET hits = $1, last_join = $2, ip_range = $3 WHERE uuid = $4 AND ip_range = $5")
                    .bind(allowlist.hits)
                    .bind(allowlist.last_join)
                    .bind(allowlist.ip_range)
                    .bind(allowlist.uuid)
                    .bind(net.ip_range)
                    .execute(&mut self.conn)
                    .await;

                ok_or_log(update);

                CIDRCheck::ValidIp(allowlist)
            }
            CidrAction::Unmatched(net) => {
                // Now we need to check against all known bad actors
                let bad_actors =
                    sqlx::query_as::<_, Blacklist>("SELECT * FROM blacklist SORT BY hits DESC")
                        .fetch_all(&mut self.conn)
                        .await;

                match check_cidr(ok_or_log(bad_actors).unwrap_or_default(), ip) {
                    CidrAction::Match(inet) => {
                        let update =
                            sqlx::query("UPDATE blacklist SET hits = $1 WHERE subnet = $2")
                                .bind(inet.hits + 1)
                                .bind(inet.subnet)
                                .execute(&mut self.conn)
                                .await;

                        ok_or_log(update);

                        CIDRCheck::ThreatActor(inet)
                    }
                    CidrAction::MaskUpdate(inet, mask) => {
                        let new_subnet = inet.with_mask(mask);

                        let update = sqlx::query(
                            "UPDATE blacklist SET hits = $1, subnet = $2 WHERE subnet = $1",
                        )
                        .bind(inet.hits + 1)
                        .bind(Json(new_subnet))
                        .bind(inet.subnet)
                        .execute(&mut self.conn)
                        .await;

                        ok_or_log(update);

                        CIDRCheck::ThreatActor(inet)
                    }
                    CidrAction::Unmatched(_) => CIDRCheck::NewIp(player_uuid.clone()),
                }
            }
        }
    }

    async fn ban_ip(
        &mut self,
        ip: std::net::Ipv4Addr,
        reason: String,
        actor: BanActor,
    ) -> data::Blacklist {
        // We loop through all the banned cidrs, to see if an already existing ban matches the given IP address.
        let bad_actors =
            sqlx::query_as::<_, Blacklist>("SELECT * FROM blacklist ORDER BY hits DESC")
                .fetch_all(&mut self.conn)
                .await;

        match check_cidr(ok_or_log(bad_actors).unwrap_or_default(), ip) {
            CidrAction::Match(net) => net,
            CidrAction::MaskUpdate(net, mask) => {
                let new_net = net.with_mask(mask);
                let update = sqlx::query_as::<_, Blacklist>(
                    "UPDATE blacklist SET subnet = $1 WHERE subnet = $2 RETURNING *",
                )
                .bind(Json(new_net))
                .bind(net.subnet)
                .fetch_one(&mut self.conn)
                .await;

                ok_or_log(update).unwrap_or(net)
            }
            CidrAction::Unmatched(net) => {
                let blacklist = Blacklist {
                    when: Utc::now(),
                    actor: Json(actor),
                    hits: 1,
                    subnet: Json(net),
                };

                let insert = sqlx::query_as::<_, Blacklist>(
                    "INSERT INTO blacklist (when, actor, hits, subnet) VALUES ($1, $2, 1, $3) RETURNING *",
                )
                .bind(blacklist.when)
                .bind(blacklist.actor.clone())
                .bind(blacklist.subnet)
                .fetch_one(&mut self.conn)
                .await;

                ok_or_log(insert).unwrap_or(blacklist)
            }
        }
    }

    async fn pardon_ip(
        &mut self,
        ip: std::net::Ipv4Addr,
        actor: BanActor,
    ) -> data::result::PardonAttempt {
        let bad_actors =
            sqlx::query_as::<_, Blacklist>("SELECT * FROM blacklist ORDER BY hits DESC")
                .fetch_all(&mut self.conn)
                .await;

        return match check_cidr(ok_or_log(bad_actors).unwrap_or_default(), ip) {
            CidrAction::Match(mut net) => {
                // We're unbanning the block since thats the easiest way to unban an IP address.
                // Subtracting CIDRs to allow a single IP address explodes the number of subnets badly. We shouldn't do that.

                match net.actor.0 {
                    BanActor::AutomatedSystem(_) => {
                        // If the ban was originally issued by an automated system, it can be overridden by either a staff member or an automated system.
                        // If an automated system tries to pardon an IP adress, it wont override the hitcount.
                        // A staff call is a manual override which will with one attempt remove the whole block, overriding the hitcount.
                        match actor {
                            BanActor::AutomatedSystem(_) => {
                                let count = net.decrement_hitcount();
                                if count > 0 {
                                    let query = sqlx::query_as::<_, Blacklist>("UPDATE blacklist SET hits = $1 WHERE subnet = $2 RETURNING *")
                                        .bind(count)
                                        .bind(net.subnet)
                                        .fetch_optional(&mut self.conn)
                                        .await;

                                    ok_or_log(query);

                                    PardonAttempt::Decreased(count as usize)
                                } else {
                                    let query = sqlx::query_as::<_, Blacklist>(
                                        "DELETE from blacklist WHERE subnet = ? RETURNING *",
                                    )
                                    .bind(net.subnet)
                                    .fetch_optional(&mut self.conn)
                                    .await;

                                    ok_or_log(query);

                                    PardonAttempt::Accepted
                                }
                            }
                            BanActor::Staff(_) => {
                                let query = sqlx::query_as::<_, Blacklist>(
                                    "DELETE from blacklist WHERE subnet = ? RETURNING *",
                                )
                                .bind(net.subnet)
                                .fetch_optional(&mut self.conn)
                                .await;

                                ok_or_log(query);

                                PardonAttempt::Accepted
                            }
                        }
                    }
                    BanActor::Staff(_) => {
                        // A staff issued ban can only be modified by another staffer.
                        match actor {
                            BanActor::AutomatedSystem(_) => PardonAttempt::InsufficientPermissions,
                            BanActor::Staff(_) => {
                                let query = sqlx::query_as::<_, Blacklist>(
                                    "DELETE from blacklist WHERE subnet = ? RETURNING *",
                                )
                                .bind(net.subnet)
                                .fetch_optional(&mut self.conn)
                                .await;

                                ok_or_log(query);

                                PardonAttempt::Accepted
                            }
                        }
                    }
                }
            }
            CidrAction::MaskUpdate(_, _) => PardonAttempt::NotBanned,
            CidrAction::Unmatched(_) => PardonAttempt::NotBanned,
        };
    }

    async fn create_server(&mut self, stub: data::stub::ServerStub) -> Option<Server> {
        let query = sqlx::query_as::<_, Server>("INSERT INTO servers (uuid, name, supported_versions, current_modpack, online, players) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *")
            .bind(Uuid::new_v4())
            .bind(stub.name)
            .bind(Json(stub.supported_versions))
            .bind(Json(stub.current_modpack))
            .bind(Json(true))
            .bind(Json("[]"))
	    .fetch_optional(&mut self.conn).await;

        ok_or_log(query).flatten()
    }

    async fn delete_server(&mut self, server_uuid: &uuid::Uuid) -> Option<Server> {
        let query = sqlx::query_as::<_, Server>("DELETE FROM servers WHERE uuid = ? RETURNING *")
            .bind(server_uuid)
            .fetch_optional(&mut self.conn)
            .await;

        ok_or_log(query).flatten()
    }

    async fn get_server(&mut self, server_uuid: &uuid::Uuid) -> Option<Server> {
        let query = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE uuid = ? RETURNING *")
            .bind(server_uuid)
            .fetch_optional(&mut self.conn)
            .await;

        ok_or_log(query).flatten()
    }

    async fn get_server_by_name(&mut self, name: String) -> Option<Server> {
        let query = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE name = ? RETURNING *")
            .bind(name)
            .fetch_optional(&mut self.conn)
            .await;

        ok_or_log(query).flatten()
    }

    async fn join_server(
        &mut self,
        server_uuid: &uuid::Uuid,
        player_uuid: &uuid::Uuid,
    ) -> data::result::ServerJoin {
        todo!()
    }

    async fn leave_server(
        &mut self,
        server_uuid: &uuid::Uuid,
        player_uuid: &uuid::Uuid,
    ) -> data::result::ServerLeave {
        todo!()
    }

    async fn check_session(
        &mut self,
        player_uuid: &uuid::Uuid,
        ip: std::net::Ipv4Addr,
        when: chrono::DateTime<chrono::Utc>,
    ) -> data::result::SessionCheck {
        return match self.check_cidr(player_uuid, ip).await {
            CIDRCheck::ThreatActor(_) => SessionCheck::Denied,
            CIDRCheck::NewIp(_) => SessionCheck::Denied,
            CIDRCheck::ValidIp(net) => {
                // The IP is validated and refreshed if it could be merged with existing CIDRs
                let delta = when - net.last_join;
                if delta.num_minutes() >= MAX_SESSION_TIME_MINUTE {
                    SessionCheck::Accepted
                } else {
                    SessionCheck::Expired
                }
            }
        };
    }

    async fn update_session(
        &mut self,
        player_uuid: &uuid::Uuid,
        ip: Ipv4Addr,
        when: chrono::DateTime<chrono::Utc>,
    ) -> data::result::SessionUpdate {
        match self.check_cidr(player_uuid, ip).await {
            CIDRCheck::ThreatActor(_) => SessionUpdate::Error("Threat Actor detected on this IP address. Requires manual intervention. Please forward this to a staff member.".to_owned()),
            CIDRCheck::NewIp(_) => SessionUpdate::Error("Connection from a new IP address. Cannot update a session that wasn't created yet.".to_owned()),
            CIDRCheck::ValidIp(net) => {
                let query = sqlx::query_as::<_, Allowlist>("UPDATE allowlist SET last_join = $1 WHERE uuid = $2 AND ip_range = $3 RETURNING *")
                    .bind(when)
                    .bind(net.uuid)
                    .bind(net.ip_range)
                    .fetch_one(&mut self.conn)
                    .await;

                match ok_or_log(query) {
                    Some(_) => SessionUpdate::Updated,
                    None => SessionUpdate::Error("An database error happened while updating an session.".to_owned()),
                }
            },
        }
    }

    async fn revoke_session(
        &mut self,
        player_uuid: &uuid::Uuid,
        ip: Ipv4Addr,
    ) -> data::result::SessionRevoke {
        match self.check_cidr(player_uuid, ip).await {
            CIDRCheck::ThreatActor(_) => SessionRevoke::Error("Threat Actor detected on this IP address. Requires manual intervention. Please forward this to a staff member.".to_owned()),
            CIDRCheck::NewIp(_) => SessionRevoke::Error("Connection from a new IP address. Cannot revoke a session that wasn't created yet.".to_owned()),
            CIDRCheck::ValidIp(net) => {
                let query = sqlx::query_as::<_, Allowlist>("DELETE FROM allowlist WHERE uuid = $1 AND ip_range = $2 RETURNING *")
                    .bind(net.uuid)
                    .bind(net.ip_range)
                    .fetch_one(&mut self.conn)
                    .await;

                match ok_or_log(query) {
                    Some(_) => SessionRevoke::Revoked,
                    None => SessionRevoke::Error("An database error happened while revoking an session".to_owned()),
                }
            },
        }
    }

    async fn update_viewport(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
        viewport: data::Viewport,
    ) -> data::result::ViewportUpdate {
        todo!()
    }

    async fn get_viewport(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
    ) -> Option<data::Viewport> {
        todo!()
    }

    async fn update_playtime(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
        when: chrono::DateTime<chrono::Utc>,
    ) -> data::result::PlaytimeUpdate {
        // Get the last joined time for the user from their Allowlists.
        // diff = now - last_joined
        // playtime += diff
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist WHERE uuid = $1 SORT BY last_join DESC",
        )
        .bind(player_uuid)
        .fetch_one(&mut self.conn)
        .await;

        match query {
            Ok(session) => {
                let diff = when - session.last_join;
                let playtime = self.get_playtime(player_uuid, server_uuid).await;
                match playtime {
                    Some(time) => {
                        let query = sqlx::query_as::<_, SaveData>("UPDATE savedata SET playtime = $1 WHERE player_uuid = $2 AND server_uuid = $3")
                            .bind(Json(time + diff.abs().to_std().unwrap()))
                            .bind(player_uuid)
                            .bind(server_uuid)
                            .fetch_one(&mut self.conn)
                            .await;

                        match query {
                            Ok(_) => PlaytimeUpdate::Accepted,
                            Err(_) => PlaytimeUpdate::Error(
                                "A database error happened while updating a playtime".to_owned(),
                            ),
                        }
                    }
                    None => PlaytimeUpdate::InvalidServer,
                }
            }
            Err(_) => return PlaytimeUpdate::InvalidUser,
        }
    }

    async fn get_playtime(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
    ) -> Option<time::Duration> {
        let query = sqlx::query_as::<_, SaveData>(
            "SELECT * FROM savedata WHERE player_uuid = $1 AND server_uuid = $2",
        )
        .bind(player_uuid)
        .bind(server_uuid)
        .fetch_optional(&mut self.conn)
        .await;

        ok_or_log(query).flatten().map(|x| x.playtime.0)
    }

    async fn add_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        pronoun: data::Pronoun,
    ) -> Vec<data::Pronoun> {
        todo!()
    }

    async fn remove_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        pronoun: data::Pronoun,
    ) -> Vec<data::Pronoun> {
        todo!()
    }

    async fn update_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        old: &data::Pronoun,
        new: data::Pronoun,
    ) -> Vec<data::Pronoun> {
        todo!()
    }

    async fn create_savedata(
        &mut self,
        player_uuid: &Uuid,
        server_uuid: &Uuid,
    ) -> Option<SaveData> {
        let query = sqlx::query_as::<_, SaveData>("INSERT INTO savedata (server_uuid, player_uuid, playtime, viewport) VALUES ($1, $2, $3, $4) RETURNING *")
            .bind(server_uuid)
            .bind(player_uuid)
            .bind(Json(time::Duration::ZERO))
            .bind(Json(Viewport{ loc: Loc {
                dim: "minecraft:overworld".to_owned(),
                x: 0.0,
                y: 64.0,
                z: 0.0,
            }, yaw: 0.0, pitch: 0.0 }))
            .fetch_optional(&mut self.conn)
            .await;

        ok_or_log(query).flatten()
    }
}
