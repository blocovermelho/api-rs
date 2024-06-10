use std::net::Ipv4Addr;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use crate::data::{BanActor, BanEntry, result, Server, stub, User, Viewport, Pronoun};

pub trait DataSource {
    async fn get_user_by_uuid(&self, uuid: &Uuid) -> Option<User>;
    async fn get_users_by_discord_id(&self, discord_id: &usize) -> Vec<User>;

    async fn create_user(&mut self, stub: stub::UserStub) -> Option<User>;
    async fn delete_user(&mut self, uuid: &Uuid) -> Option<User>;

    async fn migrate_user(&mut self, from: &Uuid, into: &Uuid) -> Option<User>;

    async fn create_account(&mut self, stub: stub::AccountStub) -> bool;
    async fn check_password(&self, player_uuid: &Uuid, password: String) -> result::PasswordCheck;
    async fn modify_password(&mut self, player_uuid: &Uuid, old_password: String, new_password: String) -> result::PasswordModify;

    async fn check_cidr(&self, player_uuid: &Uuid, ip: Ipv4Addr) -> result::CIDRCheck;
    /// Network-wide ban of an IPV4 address
    async fn ban_ip(&mut self, ip: Ipv4Addr, reason: String, actor: BanActor) -> BanEntry;
    /// Network-wide pardon of an IPV4 address
    async fn pardon_ip(&mut self, ip: Ipv4Addr, actor: BanActor) -> result::PardonAttempt;

    async fn create_server(&mut self, stub: stub::ServerStub) -> Option<Server>;
    async fn delete_server(&mut self, server_uuid: &Uuid) -> Option<Server>;

    async fn get_server_by_name(&self, name: String) -> Option<Server>;

    async fn join_server(&mut self, server_uuid: &Uuid, player_uuid: &Uuid) -> result::ServerJoin;
    async fn leave_server(&mut self, server_uuid: &Uuid, player_uuid: &Uuid) -> result::ServerLeave;
    async fn check_session(&self, player_uuid: &Uuid, ip: Ipv4Addr, when: DateTime<Utc>) -> result::SessionCheck;

    async fn update_session(&mut self, player_uuid: &Uuid, when: DateTime<Utc>) -> result::SessionUpdate;
    async fn revoke_session(&mut self, player_uuid: &Uuid) -> result::SessionRevoke;

    async fn update_viewport(&mut self, player_uuid: &Uuid, server_uuid: &Uuid, viewport: Viewport) -> result::ViewportUpdate;
    async fn get_viewport(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Option<Viewport>;

    async fn update_playtime(&mut self, player_uuid: &Uuid, server_uuid: &Uuid, when: DateTime<Utc>) -> result::PlaytimeUpdate;
    async fn get_playtime(&mut self, player_uuid: &Uuid, server_uuid: &Uuid) -> Option<Duration>;

    async fn add_pronoun(&mut self, player_uuid:&Uuid, pronoun: String) -> Vec<String>;
    async fn remove_pronoun(&mut self, player_uuid: &Uuid, pronoun: String) -> Vec<String>;
    async fn update_pronoun(&mut self, player_uuid: &Uuid, old: &String, new: String) -> Vec<String>;
}