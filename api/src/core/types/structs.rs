use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::enums::{ConnectionData, PlayerState};

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

#[allow(clippy::suspicious_operation_groupings)]
impl PartialEq<stub::ProfileStub> for Profile {
    fn eq(&self, other: &stub::ProfileStub) -> bool {
        self.username == other.username &&
            self.hash_password == other.password &&
            self.discord_id == other.discord_id
    }
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

impl PartialEq<stub::GameServerStub> for GameServer {
    fn eq(&self, other: &stub::GameServerStub) -> bool {
        self.game == other.game &&
            self.name == other.name &&
            self.versions == other.versions &&
            self.max_players == other.max_players &&
            self.staff == other.staff
    }
}

pub mod packet {
    use serde::Deserialize;
    #[derive(Debug, Clone, Deserialize)]
    pub struct GameServerKeepAlive {
        pub players: Vec<String>,
        pub motd: Option<String>,
    }
}

pub mod connection_types {
    use std::{collections::HashMap, time::Duration};

    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Deserialize, Serialize)]
    pub struct BedrockLink {
        pub name: String,
        pub xuid: Option<u64>,
    }

    #[derive(Deserialize, Serialize)]
    pub struct MojangLink {
        pub name: String,
        pub id: Uuid,
    }

    #[derive(Deserialize, Serialize)]
    pub struct PlaytimeMap(HashMap<uuid::Uuid, Duration>);
}

pub mod stub {
    use serde::Deserialize;
    use uuid::Uuid;
    #[derive(Debug, Clone, Deserialize)]
    pub struct ProfileStub {
        pub username: String,
        pub discord_id: String,
        pub password: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct GameServerStub {
        pub name: String,
        pub game: String,
        pub versions: Vec<String>,
        pub max_players: i32,
        pub staff: Vec<Uuid>,
    }
}
