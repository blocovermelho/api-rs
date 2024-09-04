use core::time::{self, Duration};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use uuid::Uuid;

use crate::interface::NetworkProvider;

#[derive(sqlx::FromRow, Debug)]
pub struct User {
    pub uuid: Uuid,
    pub username: String,
    pub discord_id: String,
    pub created_at: DateTime<Utc>,
    pub pronouns: Json<Vec<Pronoun>>,
    pub last_server: Option<Uuid>,
}

#[derive(sqlx::FromRow, Debug)]
pub(crate) struct Account {
    pub(crate) uuid: Uuid,
    pub(crate) password: String,
    pub(crate) current_join: DateTime<Utc>,
}

#[derive(sqlx::FromRow, Debug)]
pub(crate) struct Allowlist {
    pub(crate) uuid: Uuid,
    pub(crate) ip_range: Json<Ipv4Net>,
    pub(crate) last_join: DateTime<Utc>,
    pub(crate) hits: i64,
}

impl NetworkProvider for Allowlist {
    fn get_addr(&self) -> std::net::Ipv4Addr {
        self.ip_range.0.addr()
    }

    fn get_mask(&self) -> u8 {
        self.ip_range.0.prefix_len()
    }

    fn get_network(&self) -> Ipv4Net {
        self.ip_range.0
    }
}

#[derive(sqlx::FromRow, Debug)]
pub struct SaveData {
    pub user_id: Uuid,
    pub server_id: Uuid,
    pub viewport: Json<Viewport>,
    pub playtime: Json<Duration>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct Server {
    pub uuid: Uuid,
    pub name: String,
    pub supported_versions: Json<Vec<String>>,
    pub current_modpack: Json<Option<Modpack>>,
    pub online: Json<bool>,
    pub players: Json<Vec<Uuid>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Modpack {
    pub name: String,
    pub source: ModpackSource,
    pub version: String,
    pub uri: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ModpackSource {
    Modrinth,
    Curseforge,
    Other,
}

#[derive(sqlx::FromRow, Debug)]
pub struct Blacklist {
    pub when: DateTime<Utc>,
    pub actor: Json<BanActor>,
    pub hits: i64,
    pub(crate) subnet: Json<Ipv4Net>,
}

impl NetworkProvider for Blacklist {
    fn get_addr(&self) -> std::net::Ipv4Addr {
        self.subnet.0.addr()
    }

    fn get_mask(&self) -> u8 {
        self.subnet.0.prefix_len()
    }

    fn get_network(&self) -> Ipv4Net {
        self.subnet.0
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Loc {
    pub dim: String,
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Viewport {
    pub loc: Loc,
    pub yaw: f64,
    pub pitch: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Pronoun {
    pub pronoun: String,
    pub color: String,
}

pub mod stub {
    use crate::data::Modpack;
    use uuid::Uuid;

    use super::{Account, User};

    #[derive(Debug)]
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

    #[derive(Debug)]
    pub struct AccountStub {
        pub uuid: Uuid,
        pub password: String,
    }

    impl PartialEq<Account> for AccountStub {
        fn eq(&self, other: &Account) -> bool {
            self.uuid == other.uuid
        }
    }

    pub struct ServerStub {
        pub name: String,
        pub supported_versions: Vec<String>,
        pub current_modpack: Option<Modpack>,
    }
}

pub mod result {
    use crate::data::{Allowlist, Blacklist, Viewport};
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

    pub enum ServerJoin {
        FirstJoin,
        Resume(Viewport),
        InvalidServer,
        InvalidUser
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
