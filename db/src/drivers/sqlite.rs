use std::fmt::Display;

use chrono::Utc;
use sqlx::{types::Json, SqliteConnection};
use tracing::{debug, error, warn};

use crate::{
    data::{
        result::{CIDRCheck, PardonAttempt, PasswordCheck, PasswordModify}, Account, Allowlist, BanActor, Blacklist, User
    },
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
    async fn create_user(&mut self, stub: crate::data::stub::UserStub) -> Option<User> {
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
    async fn create_account(&mut self, stub: crate::data::stub::AccountStub) -> bool {
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
                // Increase the hit count.
                let update = sqlx::query("UPDATE allowlist SET hits = $1, last_join = $2 WHERE ip_range = $3 AND uuid = $4")
                    .bind(net.hits + 1)
                    .bind(Utc::now())
                    .bind(net.ip_range)
                    .bind(net.uuid)
                    .execute(&mut self.conn)
                    .await;

                ok_or_log(update);
                CIDRCheck::ValidIp(player_uuid.clone())
            }
            CidrAction::MaskUpdate(net, mask) => {
                // New netmask
                let new_net = net.with_mask(mask);
                let update = sqlx::query("UPDATE allowlist SET hits = $1, last_join = $2, ip_range = $3 WHERE uuid = $4 AND ip_range = $5")
                    .bind(net.hits + 1)
                    .bind(Utc::now())
                    .bind(Json(new_net))
                    .bind(player_uuid)
                    .bind(net.ip_range)
                    .execute(&mut self.conn)
                    .await;

                ok_or_log(update);

                CIDRCheck::ValidIp(player_uuid.clone())
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
                    CidrAction::Unmatched(_) => {
                        CIDRCheck::NewIp(player_uuid.clone())
                    }
                }
            }
        }
    }

    async fn ban_ip(
        &mut self,
        ip: std::net::Ipv4Addr,
        reason: String,
        actor: BanActor,
    ) -> crate::data::Blacklist {
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
    ) -> crate::data::result::PardonAttempt {
        let bad_actors = sqlx::query_as::<_, Blacklist>("SELECT * FROM blacklist ORDER BY hits DESC")
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
                                let count = net.decrement_hitcount() ;
                                if count > 0 {
                                    let query = sqlx::query_as::<_, Blacklist>("UPDATE blacklist SET hits = $1 WHERE subnet = $2 RETURNING *")
                                        .bind(count)
                                        .bind(net.subnet)
                                        .fetch_optional(&mut self.conn)
                                        .await;

                                    ok_or_log(query);

                                    PardonAttempt::Decreased(count as usize)
                                } else {
                                    let query = sqlx::query_as::<_, Blacklist>("DELETE from blacklist WHERE subnet = ? RETURNING *")
                                        .bind(net.subnet)
                                        .fetch_optional(&mut self.conn)
                                        .await;

                                    ok_or_log(query);

                                    PardonAttempt::Accepted
                                }
                            },
                            BanActor::Staff(_) => {
                                let query = sqlx::query_as::<_, Blacklist>("DELETE from blacklist WHERE subnet = ? RETURNING *")
                                        .bind(net.subnet)
                                        .fetch_optional(&mut self.conn)
                                        .await;

                                    ok_or_log(query);

                                    PardonAttempt::Accepted
                            },
                        }
                    },
                    BanActor::Staff(_) => {
                        // A staff issued ban can only be modified by another staffer.
                        match actor {
                            BanActor::AutomatedSystem(_) => PardonAttempt::InsufficientPermissions,
                            BanActor::Staff(_) => {
                                let query = sqlx::query_as::<_, Blacklist>("DELETE from blacklist WHERE subnet = ? RETURNING *")
                                        .bind(net.subnet)
                                        .fetch_optional(&mut self.conn)
                                        .await;

                                    ok_or_log(query);

                                    PardonAttempt::Accepted
                            },
                        }
                    },
                } 
            },
            CidrAction::MaskUpdate(_,_) => PardonAttempt::NotBanned,
            CidrAction::Unmatched(_) => PardonAttempt::NotBanned,
        };

    }

    async fn create_server(
        &mut self,
        stub: crate::data::stub::ServerStub,
    ) -> Option<crate::data::Server> {
        todo!()
    }

    async fn delete_server(&mut self, server_uuid: &uuid::Uuid) -> Option<crate::data::Server> {
        todo!()
    }

    async fn get_server_by_name(&mut self, name: String) -> Option<crate::data::Server> {
        todo!()
    }

    async fn join_server(
        &mut self,
        server_uuid: &uuid::Uuid,
        player_uuid: &uuid::Uuid,
    ) -> crate::data::result::ServerJoin {
        todo!()
    }

    async fn leave_server(
        &mut self,
        server_uuid: &uuid::Uuid,
        player_uuid: &uuid::Uuid,
    ) -> crate::data::result::ServerLeave {
        todo!()
    }

    async fn check_session(
        &mut self,
        player_uuid: &uuid::Uuid,
        ip: std::net::Ipv4Addr,
        when: chrono::DateTime<chrono::Utc>,
    ) -> crate::data::result::SessionCheck {
        todo!()
    }

    async fn update_session(
        &mut self,
        player_uuid: &uuid::Uuid,
        when: chrono::DateTime<chrono::Utc>,
    ) -> crate::data::result::SessionUpdate {
        todo!()
    }

    async fn revoke_session(
        &mut self,
        player_uuid: &uuid::Uuid,
    ) -> crate::data::result::SessionRevoke {
        todo!()
    }

    async fn update_viewport(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
        viewport: crate::data::Viewport,
    ) -> crate::data::result::ViewportUpdate {
        todo!()
    }

    async fn get_viewport(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
    ) -> Option<crate::data::Viewport> {
        todo!()
    }

    async fn update_playtime(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
        when: chrono::DateTime<chrono::Utc>,
    ) -> crate::data::result::PlaytimeUpdate {
        todo!()
    }

    async fn get_playtime(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
    ) -> Option<chrono::Duration> {
        todo!()
    }

    async fn add_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        pronoun: crate::data::Pronoun,
    ) -> Vec<crate::data::Pronoun> {
        todo!()
    }

    async fn remove_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        pronoun: crate::data::Pronoun,
    ) -> Vec<crate::data::Pronoun> {
        todo!()
    }

    async fn update_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        old: &crate::data::Pronoun,
        new: crate::data::Pronoun,
    ) -> Vec<crate::data::Pronoun> {
        todo!()
    }
}
