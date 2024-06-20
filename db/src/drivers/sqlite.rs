use sqlx::SqliteConnection;
use tracing::{debug, error};

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

    async fn create_user(&mut self, stub: crate::data::stub::UserStub) -> Option<crate::data::User> {
        todo!()
    }

    async fn delete_user(&mut self, uuid: &uuid::Uuid) -> Option<crate::data::User> {
        todo!()
    }

    async fn migrate_user(&mut self, from: &uuid::Uuid, into: &uuid::Uuid) -> Option<crate::data::User> {
        todo!()
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