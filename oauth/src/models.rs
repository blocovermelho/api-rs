use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Member {
    pub user: User,
    pub joined_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub guild_id: String,
}

impl Config {
    pub fn empty() -> Self {
        Self {
            client_id: "".to_owned(),
            client_secret: "".to_owned(),
            redirect_url: "".to_owned(),
            guild_id: "".to_owned(),
        }
    }
}
