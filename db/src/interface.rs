use std::net::Ipv4Addr;
use std::time::Duration;
use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use uuid::Uuid;
use crate::{data::{result, stub, Account, Allowlist, BanActor, Blacklist, Pronoun, SaveData, Server, User, Viewport}, drivers::err::Response};

pub trait DataSource {
    async fn get_user_by_uuid(&mut self, uuid: &Uuid) -> Response<User>;
    async fn get_users_by_discord_id(&mut self, discord_id: String) -> Response<Vec<User>>;

    async fn create_user(&mut self, stub: stub::UserStub) -> Response<User>;
    async fn delete_user(&mut self, uuid: &Uuid) -> Response<User>;

    async fn migrate_user(&mut self, from: &Uuid, into: &Uuid) -> Response<User>;

    async fn create_account(&mut self, stub: stub::AccountStub) -> Response<()>;
    async fn get_account(&mut self, uuid: &Uuid) -> Response<Account>;
    async fn update_password(&mut self, player_uuid: &Uuid, new_password: String) -> Response<()>;
    async fn migrate_account(&mut self, from: &Uuid, to: &Uuid) -> Response<()>;
    async fn delete_account(&mut self, player_uuid: &Uuid) -> Response<()>;

    async fn create_allowlist(&mut self, player_uuid: &Uuid, ip: Ipv4Addr) -> Response<Allowlist>;
    async fn get_allowlists(&mut self, player_uuid: &Uuid) -> Response<Vec<Allowlist>>;
    async fn get_allowlists_with_ip(&mut self, player_uuid: &Uuid, ip: Ipv4Addr) -> Response<Vec<Allowlist>>;
    async fn get_allowlists_with_range(&mut self, player_uuid: &Uuid, ip: Ipv4Addr, mask: u8) -> Response<Vec<Allowlist>>;
    async fn bump_allowlist(&mut self, entry: Allowlist) -> Response<()>;
    async fn broaden_allowlist_mask(&mut self, entry: Allowlist, new_mask: u8) -> Response<()>;
    async fn delete_allowlist(&mut self, entry: Allowlist) -> Response<()>;
    
    async fn create_blacklist(&mut self, ip: Ipv4Addr, actor: BanActor) -> Response<Blacklist>;
    async fn get_blacklists(&mut self, ip: Ipv4Addr) -> Response<Vec<Blacklist>>;
    async fn get_blacklists_with_range(&mut self, ip: Ipv4Addr, mask: u8) -> Response<Vec<Blacklist>>;
    async fn bump_blacklist(&mut self, entry: Blacklist) -> Response<()>;
    async fn broaden_blacklist_mask(&mut self, entry: Blacklist, new_mask: u8) -> Response<()>;
    async fn delete_blacklist(&mut self, entry: Blacklist) -> Response<()>;

    async fn create_server(&mut self, stub: stub::ServerStub) -> Response<Server>;
    async fn delete_server(&mut self, server_uuid: &Uuid) -> Response<Server>;

    async fn get_server(&mut self, server_uuid: &Uuid) -> Response<Server>;
    async fn get_server_by_name(&mut self, name: String) -> Response<Server>;

    async fn join_server(&mut self, server_uuid: &Uuid, player_uuid: &Uuid) -> Response<result::ServerJoin>;
    async fn leave_server(&mut self, server_uuid: &Uuid, player_uuid: &Uuid) -> Response<result::ServerLeave>;

    async fn update_viewport(&mut self, player_uuid: &Uuid, server_uuid: &Uuid, viewport: Viewport) -> Response<Viewport>;
    async fn get_viewport(&mut self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<Viewport>;

    async fn update_playtime(&mut self, player_uuid: &Uuid, server_uuid: &Uuid, new_playtime: Duration) -> Response<()>;
    async fn get_playtime(&mut self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<Duration>;

    async fn add_pronoun(&mut self, player_uuid:&Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>>;
    async fn remove_pronoun(&mut self, player_uuid: &Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>>;
    async fn update_pronoun(&mut self, player_uuid: &Uuid, old: &Pronoun, new: Pronoun) -> Response<Vec<Pronoun>>;

    async fn create_savedata(&mut self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<SaveData>;
}

pub trait NetworkProvider {
    fn get_addr(&self) -> Ipv4Addr;
    fn get_mask(&self) -> u8;
    fn get_network(&self) -> Ipv4Net {
        Ipv4Net::new(self.get_addr(), self.get_mask()).unwrap()
    }
    fn with_mask(&self, new_mask: u8) -> Ipv4Net {
        Ipv4Net::new(self.get_addr(), new_mask).unwrap()
    }
}