use base64::prelude::*;
use chbs::{config::BasicConfig, probability::Probability, scheme::ToScheme, word::WordSampler};
use chrono::{DateTime, Utc};
use rand::prelude::*;
use uuid::Uuid;

pub const PTBR_WORDLIST: &str = include_str!("res/ptbr_short");
pub fn get_scheme(words: Vec<String>) -> chbs::scheme::Scheme {
    let config = BasicConfig {
        words: 4,
        word_provider: WordSampler::new(words),
        separator: " ".into(),
        capitalize_first: Probability::Always,
        capitalize_words: Probability::Never,
    };
    config.to_scheme()
}

pub fn ptbr_wordlist() -> chbs::scheme::Scheme {
    get_scheme(
        PTBR_WORDLIST
            .split_whitespace()
            .map(std::string::ToString::to_string)
            .collect(),
    )
}

pub fn server_token(server_id: &Uuid, when: &DateTime<Utc>) -> String {
    let first = BASE64_URL_SAFE_NO_PAD.encode(server_id.into_bytes());
    let second = BASE64_URL_SAFE_NO_PAD.encode(when.timestamp().to_be_bytes());
    let mut key = [0u8; 32];

    // Generate Randomized Key
    rand::rng().fill(&mut key);

    let third = BASE64_URL_SAFE_NO_PAD.encode(key);

    format!("{first}.{second}.{third}")
}
