use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    time::Duration,
};

use chrono::{DateTime, Utc};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
pub struct CreateUser {
    pub uuid: Uuid,
    pub username: String,
    pub discord_id: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Account {
    pub uuid: Uuid,
    pub password: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub current_join: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub previous_ips: HashSet<Ipv4Addr>,
    pub cidr: HashSet<Ipv4Net>
}

impl From<CreateUser> for User {
    fn from(value: CreateUser) -> Self {
        Self {
            uuid: value.uuid,
            username: value.username,
            discord_id: value.discord_id,
            pronouns: vec![],
            last_server: None,
            last_pos: HashMap::new(),
            playtime: HashMap::new(),
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct CreateAccount {
    pub uuid: Uuid,
    pub password: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Server {
    pub uuid: Uuid,
    pub name: String,
    pub supported_versions: Vec<String>,
    pub current_modpack: Option<Modpack>,
    pub places: Vec<Place>,
    pub available: bool,
}

impl From<CreateServer> for Server {
    fn from(value: CreateServer) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: value.name,
            supported_versions: value.supported_versions,
            current_modpack: value.current_modpack,
            places: vec![],
            available: true,
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct CreateServer {
    pub name: String,
    pub supported_versions: Vec<String>,
    pub current_modpack: Option<Modpack>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Modpack {
    pub name: String,
    pub source: ModpackSource,
    pub version: String,
    pub uri: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Place {
    pub pos: Pos,
    pub name: String,
    pub tags: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Pos {
    pub x: i64,
    pub z: i64,
    pub y: i64,
    pub dim: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub enum ModpackSource {
    Modrinth,
    Curseforge,
    Other,
}

#[derive(Serialize)]
pub enum CidrResponse {
    Allowed,
    Banned,
    Unknown
}

#[derive(Deserialize, Serialize, Clone)]
pub enum CidrKind {
    /// Iff this CIDR was manually allowed by either the user or an admin.
    Allowed {
        user_id: u64,
        self_registered: bool,
        time: DateTime<Utc>
    },
    /// Iff this CIDR was banned
    Banned {
        uuid: Uuid,
        time: DateTime<Utc>,
        issuer: BanIssuer,
        ip: Ipv4Addr
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub enum BanIssuer {
    Manual(Uuid),
    Automatic
}

#[derive(Serialize, Clone)]
pub enum BanResponse {
    Existing,
    Merged,
    New,
    Invalid
}


#[derive(Serialize, Clone)]
pub enum GraceResponse {
    Invalid,
    Grace(Ipv4Addr)
}