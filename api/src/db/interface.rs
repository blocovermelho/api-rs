use std::{net::Ipv4Addr, time::Duration};

use ipnet::Ipv4Net;
use uuid::Uuid;

use super::data::{Profile, ServerV2, Token};
use crate::{
    core::types::structs::stub::{GameServerStub, ProfileStub},
    db::{
        data::{
            result::{self, PlaytimeEntry},
            stub, Account, Allowlist, BanIssuer, Blacklist, Connection, Pronoun, SaveData, Server,
            User, Viewport,
        },
        drivers::err::Response,
    },
};

#[async_trait::async_trait]
pub trait DataSource: Send + Sync {
    #[deprecated(since = "2.0.0", note = "The User object got replaced by Profile")]
    async fn get_user_by_uuid(&self, uuid: &Uuid) -> Response<User>;
    #[deprecated(since = "2.0.0", note = "The User object got replaced by Profile")]
    async fn get_all_users(&self) -> Response<Vec<Uuid>>;

    #[deprecated(
        since = "2.0.0",
        note = "Accounts, which only held the password of the user were merged into Profiles."
    )]
    async fn get_account(&self, uuid: &Uuid) -> Response<Account>;
    #[deprecated(
        since = "2.0.0",
        note = "Accounts, which only held the password of the user were merged into Profiles."
    )]
    async fn get_all_accounts(&self) -> Response<Vec<Uuid>>;

    async fn upcast_profile(&self, user: User, account: Account) -> Response<Profile>;

    async fn create_profile(
        &self, stub: ProfileStub, when: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Response<Profile>;

    async fn get_profile(&self, username: String) -> Response<Profile>;
    async fn get_profile_by_id(&self, profile_uuid: &Uuid) -> Response<Profile>;
    async fn get_profiles_by_discord_id(&self, discord_id: String) -> Response<Vec<Profile>>;

    async fn delete_profile(&self, profile_uuid: &Uuid) -> Response<Profile>;

    async fn update_password(&self, player_uuid: &Uuid, new_password: String) -> Response<()>;
    async fn update_username(&self, player_uuid: &Uuid, new_username: String) -> Response<()>;

    #[deprecated(
        since = "2.0.0",
        note = "Accounts, which only held the password of the user were merged into Profiles."
    )]
    async fn delete_account(&self, player_uuid: &Uuid) -> Response<()>;

    async fn create_allowlist(&self, player_uuid: &Uuid, ip: Ipv4Addr) -> Response<Allowlist>;
    async fn get_allowlists(&self, player_uuid: &Uuid) -> Response<Vec<Allowlist>>;
    async fn get_allowlists_with_ip(
        &self, player_uuid: &Uuid, ip: Ipv4Addr,
    ) -> Response<Vec<Allowlist>>;
    async fn get_allowlists_with_range(
        &self, player_uuid: &Uuid, ip: Ipv4Addr, mask: u8,
    ) -> Response<Vec<Allowlist>>;
    async fn bump_allowlist(&self, entry: Allowlist) -> Response<()>;
    async fn broaden_allowlist_mask(&self, entry: Allowlist, new_mask: u8) -> Response<()>;
    async fn delete_allowlist(&self, entry: Allowlist) -> Response<()>;

    async fn create_blacklist(&self, ip: Ipv4Addr, actor: BanIssuer) -> Response<Blacklist>;
    async fn get_blacklists(&self, ip: Ipv4Addr) -> Response<Vec<Blacklist>>;
    async fn get_blacklists_with_range(&self, ip: Ipv4Addr, mask: u8) -> Response<Vec<Blacklist>>;
    async fn bump_blacklist(&self, entry: Blacklist) -> Response<()>;
    async fn broaden_blacklist_mask(&self, entry: Blacklist, new_mask: u8) -> Response<()>;
    async fn delete_blacklist(&self, entry: Blacklist) -> Response<()>;

    async fn create_server(&self, stub: GameServerStub) -> Response<ServerV2>;
    async fn delete_server(&self, server_uuid: &Uuid) -> Response<ServerV2>;
    async fn upcast_server_v1(&self, v1: Server) -> Response<ServerV2>;

    async fn get_server(&self, server_uuid: &Uuid) -> Response<ServerV2>;
    async fn get_server_v1(&self, server_uuid: &Uuid) -> Response<Server>;
    async fn get_server_by_name(&self, name: String) -> Response<ServerV2>;
    async fn get_all_servers_v1(&self) -> Response<Vec<Uuid>>;
    async fn get_all_servers_v2(&self) -> Response<Vec<Uuid>>;

    async fn create_token(&self, server_uuid: &Uuid, scopes: Vec<String>) -> Response<String>;
    async fn reset_token(&self, server_uuid: &Uuid) -> Response<String>;
    async fn get_token(&self, token: String) -> Response<Token>;
    async fn revoke_token(&self, server_uuid: &Uuid) -> Response<()>;

    #[deprecated(since = "2.0.0", note = "Playtime is now an Connection.")]
    async fn update_playtime(
        &self, player_uuid: &Uuid, server_uuid: &Uuid, new_playtime: Duration,
    ) -> Response<()>;
    #[deprecated(since = "2.0.0", note = "Playtime is now an Connection.")]
    async fn get_playtime_v1(&self, player_uuid: &Uuid, server_uuid: &Uuid) -> Response<Duration>;
    #[deprecated(since = "2.0.0", note = "Playtime is now an Connection.")]
    async fn get_playtimes_v1(&self, server_uuid: &Uuid) -> Response<Vec<PlaytimeEntry>>;

    async fn upcast_savedata(&self, data: SaveData) -> Response<Connection>;

    async fn add_pronoun(&self, player_uuid: &Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>>;
    async fn remove_pronoun(&self, player_uuid: &Uuid, pronoun: Pronoun) -> Response<Vec<Pronoun>>;
    async fn update_pronoun(
        &self, player_uuid: &Uuid, old: &Pronoun, new: Pronoun,
    ) -> Response<Vec<Pronoun>>;

    #[deprecated(since = "2.0.0", note = "SaveData has been superceded by Connection")]
    async fn get_savedatas(&self, player_uuid: &Uuid) -> Response<Vec<SaveData>>;
    #[deprecated(since = "2.0.0", note = "SaveData has been superceded by Connection")]
    async fn delete_savedatas(&self, player_uuid: &Uuid) -> Response<Vec<SaveData>>;

    async fn create_connection(&self, connection: Connection) -> Response<Connection>;
    async fn get_connection(&self, profile: &Uuid, kind: &str) -> Response<Connection>;
    async fn get_connections_by_profile(&self, profile: &Uuid) -> Response<Vec<Connection>>;
    async fn get_connections_by_kind(&self, kind: &str) -> Response<Vec<Connection>>;
    async fn delete_connection(&self, profile: &Uuid, kind: &str) -> Response<Connection>;
    async fn update_connection(&self, connection: Connection) -> Response<Connection>;
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
