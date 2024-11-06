use core::time::{self, Duration};
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use crate::interface::NetworkProvider;

#[derive(sqlx::FromRow, Debug, Serialize)]
pub struct User {
    pub uuid: Uuid,
    pub username: String,
    pub discord_id: String,
    pub created_at: DateTime<Utc>,
    pub pronouns: Json<Vec<Pronoun>>,
    pub last_server: Option<Uuid>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct Account {
    pub uuid: Uuid,
    pub password: String,
    pub current_join: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct Allowlist {
    pub uuid: Uuid,
    pub base_ip: u32,
    pub mask: u8,
    pub last_join: DateTime<Utc>,
    pub hits: i64,
}

impl NetworkProvider for Allowlist {
    fn get_addr(&self) -> std::net::Ipv4Addr {
        Ipv4Addr::from_bits(self.base_ip)
    }

    fn get_mask(&self) -> u8 {
        self.mask
    }

    fn get_network(&self) -> Ipv4Net {
        Ipv4Net::new(self.get_addr(), self.mask).unwrap()
    }
}

#[derive(sqlx::FromRow, Debug)]
pub struct SaveData {
    pub player_uuid: Uuid,
    pub server_uuid: Uuid,
    pub viewport: Json<Viewport>,
    pub playtime: Json<Duration>,
}

#[derive(sqlx::FromRow, Debug, PartialEq, Serialize)]
pub struct Server {
    pub uuid: Uuid,
    pub name: String,
    pub supported_versions: Json<Vec<String>>,
    pub current_modpack: Json<Option<Modpack>>,
    pub online: Json<bool>,
    pub players: Json<Vec<Uuid>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Modpack {
    pub name: String,
    pub source: ModpackSource,
    pub version: String,
    pub uri: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ModpackSource {
    Modrinth,
    Curseforge,
    Other,
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct Blacklist {
    pub created_at: DateTime<Utc>,
    pub actor: Json<BanActor>,
    pub hits: i64,
    pub(crate) base_ip: u32,
    pub(crate) mask: u8,
}

impl NetworkProvider for Blacklist {
    fn get_addr(&self) -> std::net::Ipv4Addr {
        Ipv4Addr::from_bits(self.base_ip)
    }

    fn get_mask(&self) -> u8 {
        self.mask
    }

    fn get_network(&self) -> Ipv4Net {
        Ipv4Net::new(self.get_addr(), self.mask).unwrap()
    }
}

impl Blacklist {
    pub fn decrement_hitcount(&mut self) -> i64 {
        if self.hits > 0 {
            self.hits = self.hits - 1;
        }

        self.hits
    }

    pub fn increment_hitcount(&mut self) -> i64 {
        self.hits = self.hits + 1;

        self.hits
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BanActor {
    AutomatedSystem(String),
    Staff(Uuid),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Loc {
    pub dim: String,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Default for Loc {
    fn default() -> Self {
        Self {
            dim: "minecraft:overworld".to_owned(),
            x: 0.0,
            y: 64.0,
            z: 0.0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Viewport {
    pub loc: Loc,
    pub yaw: f64,
    pub pitch: f64,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            loc: Loc::default(),
            yaw: 0.0,
            pitch: 0.0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pronoun {
    pub pronoun: String,
    pub color: String,
}

pub mod stub {
    use crate::data::Modpack;
    use serde::Deserialize;
    use uuid::Uuid;

    use super::{Account, Server, User};

    #[derive(Debug, Clone, Deserialize)]
    pub struct UserStub {
        pub uuid: Uuid,
        pub username: String,
        pub discord_id: String,
    }

    impl PartialEq<User> for UserStub {
        fn eq(&self, other: &User) -> bool {
            self.uuid == other.uuid && self.discord_id == other.discord_id && self.username == other.username
        }
    }

    #[derive(Debug, Clone)]
    pub struct AccountStub {
        pub uuid: Uuid,
        pub password: String,
    }

    impl PartialEq<Account> for AccountStub {
        fn eq(&self, other: &Account) -> bool {
            self.uuid == other.uuid
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct ServerStub {
        pub name: String,
        pub supported_versions: Vec<String>,
        pub current_modpack: Option<Modpack>,
    }

    impl PartialEq<Server> for ServerStub {
        fn eq(&self, other: &Server) -> bool {
            self.name == other.name && self.supported_versions == other.supported_versions.0
        }
    }
}

pub mod result {
    use crate::data::{Allowlist, Blacklist, Viewport};
    use serde::Serialize;
    use uuid::Uuid;

    pub enum PasswordCheck {
        Correct,
        InvalidPassword(u64),
        Unregistered,
    }

    pub enum PasswordModify {
        Modified,
        InvalidPassword(u64),
        Unregistered,
    }

    pub enum CIDRCheck {
        /// A malicious actor with multiple join attempts
        ThreatActor(Blacklist),
        /// This happens when an ISP changes your IP, its a normal case
        /// and *should never* be displayed with a ban message.
        NewIp(Uuid),
        /// Valid login case for that user
        ValidIp(Allowlist),
    }

    pub enum PardonAttempt {
        /// The pardon was accepted since that IP only had one infraction remaining
        Accepted,
        /// The given IP wasn't banned
        NotBanned,
        /// The infraction count was reduced. This IP will only be unbanned after the count
        /// reaches zero, e.g. "Accepted" state.
        Decreased(usize),
        /// Permission Error: An automated system tried lifting a manually issued ban.
        InsufficientPermissions,
    }

    pub enum SessionCheck {
        Accepted,
        Expired,
        Denied,
    }

    pub enum SessionRevoke {
        Revoked,
        Error(String),
    }

    pub enum SessionUpdate {
        Updated,
        Error(String),
    }

    #[derive(Serialize)]
    pub enum ServerJoin {
        FirstJoin,
        Resume(Viewport),
    }

    pub enum ServerLeave {
        Accepted,
        NotJoined,
    }

    pub enum ViewportUpdate {
        InvalidServer,
        InvalidUser,
        Accepted,
        Error(String),
    }

    pub enum PlaytimeUpdate {
        InvalidServer,
        InvalidUser,
        Accepted,
        Error(String),
    }

    pub enum UserAction {
        InvalidUser,
        Accepted,
    }
}
