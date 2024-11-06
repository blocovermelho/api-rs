use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use traits::json::JsonSync;

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
    pub role_id: String,
}

impl JsonSync for Config {
    type T = Self;

    fn new() -> Self::T {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            redirect_url: String::new(),
            guild_id: String::new(),
            role_id: String::new(),
        }
    }

    fn is_empty(this: &Self::T) -> bool {
        this.client_id.is_empty() && this.client_secret.is_empty()
    }
}
