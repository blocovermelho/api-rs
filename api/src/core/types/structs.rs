use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use ipnet::Ipv4Net;
use uuid::Uuid;

use super::{
    consts::session::{self, LEASE_TIME},
    enums::{ConnectionData, PlayerState},
};

#[derive(Debug, Clone)]
pub struct Profile {
    pub id: Uuid,
    pub username: String,
    pub discord_id: String,
    pub(crate) hash_password: String,
    pub connections: Vec<Connection>,
    // Derived from UUID v7.
    // This field exists on the database but will be removed after the new ids are in place.
    // This will require a manual migration of all user data.
    pub created_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Player {
    pub profile: Option<Profile>,
    pub status: PlayerState,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub issuer: Option<Uuid>,
    pub profile: Profile,
    pub extra: ConnectionData,
}

#[derive(Debug, Clone)]
pub struct GameServer {
    pub id: Uuid,
    pub name: String,
    pub game: String,
    pub versions: Vec<String>,
    pub max_players: i32,
    // Derived from keep-alive packets
    pub players: HashMap<String, Player>,
    // Derived from UUID v7 Datetime.
    pub created_at: DateTime<Utc>,
    // Derived from keep-alive packets
    pub last_seen: DateTime<Utc>,
    pub staff: Vec<Uuid>,
}

pub(crate) struct Session {
    pub(crate) profile: Uuid,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) last_seen: DateTime<Utc>,
    pub(crate) network: Ipv4Net,
}

impl Session {
    pub fn get_expiry(&self) -> DateTime<Utc> {
        self.last_seen + LEASE_TIME
    }
}

pub mod packet {
    use uuid::Uuid;

    pub struct GameServerKeepAlive {
        server_id: Uuid,
        players: Vec<String>,
        motd: Option<String>,
    }
}

pub mod stub {
    use uuid::Uuid;
    pub struct ProfileStub {
        pub username: String,
        pub discord_id: String,
        pub password: String,
    }

    pub struct GameServerStub {
        pub name: String,
        pub game: String,
        pub versions: Vec<String>,
        pub max_players: usize,
        pub staff: Vec<Uuid>,
    }
}
