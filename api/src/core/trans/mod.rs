use chrono::{DateTime, Utc};
use tokio::time::Instant;

pub mod db;

pub fn to_monotonic(dt: DateTime<Utc>) -> Instant {
    let now = Utc::now();
    let distance = dt - now;
    let std = distance.to_std().unwrap_or(std::time::Duration::ZERO);
    Instant::now() + std
}
