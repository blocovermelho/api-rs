use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub struct User {
    pub uuid: Uuid,
    pub username: String,
    pub discord_id: u64,
    pub pronouns: Vec<String>,
    pub last_server: Option<Uuid>
}

pub(crate) struct Account {
    pub(crate) uuid: Uuid,
    pub(crate) password: String,
    pub(crate) current_join: DateTime<Utc>
}

pub(crate) struct Allowlist {
    pub(crate) uuid: Uuid,
    pub(crate) ip_range: Vec<Ipv4Net>,
    pub(crate) last_join: DateTime<Utc>
}

pub struct SaveData {
    pub user_id: Uuid,
    pub server_id: Uuid,
    pub viewport: Viewport,
    pub playtime: Duration
}

pub struct Server {
    pub uuid: Uuid,
    pub name: String,
    pub supported_versions: Vec<String>,
    pub current_modpack: Option<Modpack>,
    pub online: bool
}

#[derive(Serialize, Deserialize)]
pub struct Modpack {
    pub name: String,
    pub source: ModpackSource,
    pub version: String,
    pub uri: String
}

#[derive(Serialize, Deserialize)]
pub enum ModpackSource {
    Modrinth,
    Curseforge,
    Other
}

pub struct Blacklist {
    pub when: DateTime<Utc>,
    pub actor: BanActor,
    pub(crate) subnet: Ipv4Net
}

#[derive(Serialize, Deserialize)]
pub enum BanActor {
    AutomatedSystem(String),
    Staff(Uuid)
}

#[derive(Serialize, Deserialize)]
pub struct Loc {
    pub dim: String,
    pub x: f64,
    pub y: f64,
    pub z: f64
}

#[derive(Serialize, Deserialize)]
pub struct Viewport {
    pub loc: Loc,
    pub yaw: f64,
    pub pitch: f64
}

#[derive(Serialize, Deserialize)]
pub struct Pronoun {
    pub pronoun: String,
    pub color: String
}

pub mod stub {
    use uuid::Uuid;
    use crate::data::Modpack;

    pub struct UserStub {
        pub uuid: Uuid,
        pub username: String,
        pub discord_id: u64
    }

    pub struct AccountStub {
        pub uuid: Uuid,
        pub password: String
    }

    pub struct ServerStub {
        pub name: String,
        pub supported_versions: Vec<String>,
        pub current_modpack: Option<Modpack>,
    }
}

pub mod result {
    use uuid::Uuid;
    use crate::data::{Blacklist, Viewport};

    pub enum PasswordCheck {
        Correct,
        InvalidPassword(u64),
        Unregistered
    }

    pub enum PasswordModify {
        Modified,
        InvalidPassword(u64),
        Unregistered
    }

    pub enum CIDRCheck {
        /// A malicious actor with multiple join attempts
        ThreatActor(Vec<Blacklist>),
        /// This happens when an ISP changes your IP, its a normal case
        /// and *should never* be displayed with a ban message.
        NewIp(Uuid),
        /// Valid login case for that user
        ValidIp(Uuid)
    }

    pub enum PardonAttempt {
        /// The pardon was accepted since that IP only had one infraction remaining
        Accepted,
        /// The given IP wasn't banned
        NotBanned,
        /// The infraction count was reduced. This IP will only be unbanned after the count
        /// reaches zero, e.g. "Accepted" state.
        Decreased(usize)
    }

    pub enum SessionCheck {
        Accepted,
        Transfer(Uuid),
        Expired
    }

    pub enum SessionRevoke {
        Revoked,
        Error(String)
    }

    pub enum SessionUpdate {
        Updated,
        Error(String)
    }

    pub enum ServerJoin {
        FirstJoin,
        Resume(Viewport)
    }

    pub enum ServerLeave {
        Accepted,
        NotJoined
    }

    pub enum ViewportUpdate {
        InvalidServer,
        InvalidUser,
        Accepted
    }

    pub enum PlaytimeUpdate {
        InvalidServer,
        InvalidUser,
        Accepted
    }

    pub enum UserAction {
        InvalidUser,
        Accepted
    }
}