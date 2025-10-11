use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::types::enums::Connection;

struct Profile {
    id: Uuid,
    username: String,
    discord_id: String,
    password: String,
    connections: Vec<Connection>,
    created_at: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

struct GameServer {
    id: Uuid,
    name: String,
    // game: String,
    versions: String,
    max_players: usize,
    created_at: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}
