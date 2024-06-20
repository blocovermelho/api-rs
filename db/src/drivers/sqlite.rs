use chrono::Utc;
use sqlx::SqliteConnection;
use tracing::{debug, error, warn};

use crate::{data::User, interface::DataSource};

#[derive(Debug)]
pub struct Sqlite {
    conn: SqliteConnection
}

impl Sqlite {
    pub fn new(conn: SqliteConnection) -> Self {
        Self {
            conn
        }
    }
}

fn ok_or_log<T>(either: Result<T, sqlx::Error>) -> Option<T> {
    match either {
        Ok(value) =>  { Some(value) },
        Err(e) => { 
            error!("Database Error: {e}");
            None 
        },
    }
}

impl DataSource for Sqlite {

    #[tracing::instrument]
    async fn get_user_by_uuid(&mut self, uuid: &uuid::Uuid) -> Option<User> {
        let query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE uuid == ?")
        .bind(uuid)
        .fetch_optional(&mut self.conn)
        .await;
        
        ok_or_log(query).flatten()
    }

    #[tracing::instrument]
    async fn get_users_by_discord_id(&mut self, discord_id: String) -> Vec<User> {
        let query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE discord_id == ?")
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
        // Should take into consideration the parameters being fumbled. This code can be called from non-rust sources.
        // This is the reason why `created_at` exists. The old shall give way to the new.

        // An user migration is done in the case where a player decides to change their username.
        // This can happen for many reasons, one of them being transgender folk removing their deandnames from their old usernames.

        // An example of a migration would be:
        // ┏━━━━━━━━━━┓       ┏━━━━━━━━━━━━┓
        // ┃ roridev  ┣━━━━━━━┫ alikindsys ┃
        // ┗━━━━━━━━━━┛       ┗━━━━━━━━━━━━┛ 
        // ┋ f33d0bab ┋       ┋  3984dfa8  ┋

        // Where all data which was originally stored under f33d0bab will be transfered over to 3984dfa8 apart from username and uuid.
        
        // NOTE: This operation requires two existing accounts to be linked to the same discord account for it to be sucessful. 

        let fromUser = self.get_user_by_uuid(from).await?;
        let intoUser = self.get_user_by_uuid(into).await?;

        if fromUser.discord_id != intoUser.discord_id {
            warn!("Tried transfering accounts with mismatched ownership.");
            return None
        }
        
        // Fumbled! The data will be transfered from `intoUser`'s data, and update `fromUser`'s uuid.
        if fromUser.created_at > intoUser.created_at {
            let query = sqlx::query_as::<_,User>("UPDATE users SET created_at = $1, pronouns = $2 WHERE uuid = $3 RETURNING *")
            .bind(intoUser.created_at)
            .bind(intoUser.pronouns)
            .bind(fromUser.uuid)
            .fetch_one(&mut self.conn)
            .await;

            ok_or_log(query)
        } else {
            let query = sqlx::query_as::<_,User>("UPDATE users SET created_at = $1, pronouns = $2 WHERE uuid = $3 RETURNING *")
            .bind(fromUser.created_at)
            .bind(fromUser.pronouns)
            .bind(intoUser.uuid)
            .fetch_one(&mut self.conn)
            .await;

            ok_or_log(query)
        }
    }

    async fn create_account(&mut self, stub: crate::data::stub::AccountStub) -> bool {
        todo!()
    }

    async fn check_password(&mut self, player_uuid: &uuid::Uuid, password: String) -> crate::data::result::PasswordCheck {
        todo!()
    }

    async fn modify_password(&mut self, player_uuid: &uuid::Uuid, old_password: String, new_password: String) -> crate::data::result::PasswordModify {
        todo!()
    }

    async fn migrate_account(&mut self, from: &uuid::Uuid, to: &uuid::Uuid) -> bool {
        todo!()
    }
    
    async fn delete_accound(&mut self, player_uuid: &uuid::Uuid) -> bool {
        todo!()
    }

    async fn check_cidr(&mut self, player_uuid: &uuid::Uuid, ip: std::net::Ipv4Addr) -> crate::data::result::CIDRCheck {
        todo!()
    }

    async fn ban_ip(&mut self, ip: std::net::Ipv4Addr, reason: String, actor: crate::data::BanActor) -> crate::data::Blacklist {
        todo!()
    }

    async fn pardon_ip(&mut self, ip: std::net::Ipv4Addr, actor: crate::data::BanActor) -> crate::data::result::PardonAttempt {
        todo!()
    }

    async fn create_server(&mut self, stub: crate::data::stub::ServerStub) -> Option<crate::data::Server> {
        todo!()
    }

    async fn delete_server(&mut self, server_uuid: &uuid::Uuid) -> Option<crate::data::Server> {
        todo!()
    }

    async fn get_server_by_name(&mut self, name: String) -> Option<crate::data::Server> {
        todo!()
    }

    async fn join_server(&mut self, server_uuid: &uuid::Uuid, player_uuid: &uuid::Uuid) -> crate::data::result::ServerJoin {
        todo!()
    }

    async fn leave_server(&mut self, server_uuid: &uuid::Uuid, player_uuid: &uuid::Uuid) -> crate::data::result::ServerLeave {
        todo!()
    }

    async fn check_session(&mut self, player_uuid: &uuid::Uuid, ip: std::net::Ipv4Addr, when: chrono::DateTime<chrono::Utc>) -> crate::data::result::SessionCheck {
        todo!()
    }

    async fn update_session(&mut self, player_uuid: &uuid::Uuid, when: chrono::DateTime<chrono::Utc>) -> crate::data::result::SessionUpdate {
        todo!()
    }

    async fn revoke_session(&mut self, player_uuid: &uuid::Uuid) -> crate::data::result::SessionRevoke {
        todo!()
    }

    async fn update_viewport(&mut self, player_uuid: &uuid::Uuid, server_uuid: &uuid::Uuid, viewport: crate::data::Viewport) -> crate::data::result::ViewportUpdate {
        todo!()
    }

    async fn get_viewport(&mut self, player_uuid: &uuid::Uuid, server_uuid: &uuid::Uuid) -> Option<crate::data::Viewport> {
        todo!()
    }

    async fn update_playtime(&mut self, player_uuid: &uuid::Uuid, server_uuid: &uuid::Uuid, when: chrono::DateTime<chrono::Utc>) -> crate::data::result::PlaytimeUpdate {
        todo!()
    }

    async fn get_playtime(&mut self, player_uuid: &uuid::Uuid, server_uuid: &uuid::Uuid) -> Option<chrono::Duration> {
        todo!()
    }

    async fn add_pronoun(&mut self, player_uuid:&uuid::Uuid, pronoun: crate::data::Pronoun) -> Vec<crate::data::Pronoun> {
        todo!()
    }

    async fn remove_pronoun(&mut self, player_uuid: &uuid::Uuid, pronoun: crate::data::Pronoun) -> Vec<crate::data::Pronoun> {
        todo!()
    }

    async fn update_pronoun(&mut self, player_uuid: &uuid::Uuid, old: &crate::data::Pronoun, new: crate::data::Pronoun) -> Vec<crate::data::Pronoun> {
        todo!()
    }
}