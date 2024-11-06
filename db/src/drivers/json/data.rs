use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    time::Duration,
};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::data;

// The "object".
// This afront to god which was called "Store" is what ends up being the sole json object
// that gets loaded into ram and reflushed on every single operation.
// It stores *way* more things, but for our purposes all of that can be re-added later.

#[derive(Deserialize, Serialize, Clone)]
pub struct Datum {
    pub users: HashMap<Uuid, User>,
    pub accounts: HashMap<Uuid, Account>,
    pub servers: HashMap<Uuid, Server>,
    pub ledger: HashMap<String, Vec<CidrKind>>,
}

// All of the legacy data objects from the legacy store.
// May god save us all.
// It's surprisingly little things *but* the pain point is that everything is scattered.

#[derive(Deserialize, Serialize, Clone)]
pub struct User {
    pub uuid: Uuid,
    pub username: String,
    pub discord_id: String,
    pub pronouns: Vec<String>,
    pub last_server: Option<Uuid>,
    pub last_pos: HashMap<Uuid, Pos>,
    pub playtime: HashMap<Uuid, Duration>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Account {
    pub uuid: Uuid,
    pub password: String,
    pub last_login: Option<DateTime<Utc>>,
    pub cidr: HashSet<Ipv4Net>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Server {
    pub uuid: Uuid,
    pub name: String,
    pub supported_versions: Vec<String>,
    pub current_modpack: Option<Modpack>,
    // places: Vec<Place>, The places API never went anywhere and we don't have support for it. It can be binned.
    pub available: bool,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Modpack {
    pub name: String,
    pub source: ModpackSource,
    pub version: String,
    pub uri: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub enum ModpackSource {
    Modrinth,
    Curseforge,
    Other,
}

impl From<ModpackSource> for data::ModpackSource {
    fn from(val: ModpackSource) -> Self {
        match val {
            ModpackSource::Modrinth => Self::Modrinth,
            ModpackSource::Curseforge => Self::Curseforge,
            ModpackSource::Other => Self::Other,
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Pos {
    pub x: i64,
    pub z: i64,
    pub y: i64,
    pub dim: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub enum CidrKind {
    Allowed {
        user_id: u64,
        self_registered: bool,
        time: DateTime<Utc>,
    },
    Banned {
        uuid: Uuid,
        time: DateTime<Utc>,
        issuer: BanIssuer,
        ip: Ipv4Addr,
    },
}

#[derive(Deserialize, Serialize, Clone)]
pub enum BanIssuer {
    Manual(Uuid),
    Automatic,
}
