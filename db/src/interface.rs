use std::net::Ipv4Addr;
use std::time::Duration;
use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use uuid::Uuid;
use crate::{data::{result, stub, Account, Allowlist, BanActor, Blacklist, Pronoun, SaveData, Server, User, Viewport}, drivers::err::Response};

#[async_trait::async_trait]
pub trait DataSource {
    async fn get_user_by_uuid(&self, uuid: &Uuid) -> Response<User>;
    async fn get_users_by_discord_id(&self, discord_id: String) -> Response<Vec<User>>;

    async fn create_user(&self, stub: stub::UserStub) -> Response<User>;
    async fn delete_user(&self, uuid: &Uuid) -> Response<User>;

    async fn migrate_user(&self, from: &Uuid, into: &Uuid) -> Response<User>;

    async fn create_account(&self, stub: stub::AccountStub) -> Response<()>;
    async fn get_account(&self, uuid: &Uuid) -> Response<Account>;
    async fn update_password(&self, player_uuid: &Uuid, new_password: String) -> Response<()>;
    async fn migrate_account(&self, from: &Uuid, to: &Uuid) -> Response<()>;
    async fn delete_account(&self, player_uuid: &Uuid) -> Response<()>;

    async fn create_allowlist(&self, player_uuid: &Uuid, ip: Ipv4Addr) -> Response<Allowlist>;
    async fn get_allowlists(&self, player_uuid: &Uuid) -> Response<Vec<Allowlist>>;
    async fn get_allowlists_with_ip(
        &self,
        player_uuid: &Uuid,
        ip: Ipv4Addr,
    ) -> Response<Vec<Allowlist>>;
    async fn get_allowlists_with_range(
        &self,
        player_uuid: &Uuid,
        ip: Ipv4Addr,
        mask: u8,
    ) -> Response<Vec<Allowlist>>;
    async fn bump_allowlist(&self, entry: Allowlist) -> Response<()>;
    async fn broaden_allowlist_mask(&self, entry: Allowlist, new_mask: u8) -> Response<()>;
    async fn delete_allowlist(&self, entry: Allowlist) -> Response<()>;

    async fn create_blacklist(&self, ip: Ipv4Addr, actor: BanActor) -> Response<Blacklist>;
    async fn get_blacklists(&self, ip: Ipv4Addr) -> Response<Vec<Blacklist>>;
    async fn get_blacklists_with_range(&self, ip: Ipv4Addr, mask: u8) -> Response<Vec<Blacklist>>;
    async fn bump_blacklist(&self, entry: Blacklist) -> Response<()>;
    async fn broaden_blacklist_mask(&self, entry: Blacklist, new_mask: u8) -> Response<()>;
    async fn delete_blacklist(&self, entry: Blacklist) -> Response<()>;

    async fn create_server(&self, stub: stub::ServerStub) -> Response<Server>;
    async fn delete_server(&self, server_uuid: &Uuid) -> Response<Server>;

    async fn get_server(&self, server_uuid: &Uuid) -> Response<Server>;
    async fn get_server_by_name(&self, name: String) -> Response<Server>;

    async fn join_server(
        &self,
        server_uuid: &Uuid,
        player_uuid: &Uuid,
    ) -> Response<result::ServerJoin>;
    async fn leave_server(&self, server_uuid: &Uuid, player_uuid: &Uuid) -> Response<result::ServerLeave>;

    async fn update_viewport(
        &self,
        player_uuid: &Uuid,
        server_uuid: &Uuid,
        viewport: Viewport,
    ) -> Response<Viewport>;
    async fn get_viewport(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<Viewport>;

    async fn update_playtime(
        &self,
        player_uuid: &Uuid,
        server_uuid: &Uuid,
        new_playtime: Duration,
    ) -> Response<()>;
    async fn get_playtime(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<Duration>;

    async fn add_pronoun(&self, player_uuid: &Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>>;
    async fn remove_pronoun(&self, player_uuid: &Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>>;
    async fn update_pronoun(&self, player_uuid: &Uuid, old: &Pronoun, new: Pronoun) -> Response<Vec<Pronoun>>;

    async fn create_savedata(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<SaveData>;
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
