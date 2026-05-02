#![feature(duration_constructors)]

use std::{env, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use actor::mailbox::{MailboxActor, MailboxActorHandle};
use axum::{
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use futures::channel::mpsc::{channel, Receiver, Sender};
use http::StatusCode;
use json::JsonSync;
use migrate::{migrate, migrate_v2};
use oauth::models::Config;
use reqwest::{header, Client};
use serenity::all::GatewayIntents;
use tower::ServiceBuilder;
use tower_http::{timeout::TimeoutLayer, ServiceBuilderExt};
use tracing::warn;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::{db::drivers::sqlite::Sqlite, discord::framework, oauth::routes::OAuthClient};

pub mod actor;
#[allow(clippy::future_not_send)]
pub mod bus;
pub mod core;
pub mod db;
pub mod discord;
pub mod json;
pub mod middleware;
#[allow(deprecated)] pub mod migrate;
pub mod models;
pub mod oauth;
pub mod routes;

pub struct AuthServer {
    pub db: Arc<Sqlite>,
    pub clients: Arc<Clients>,
    pub config: Arc<Config>,
    pub mailbox: MailboxActorHandle,
    pub bad_names: Vec<String>,
    pub event_bus: MpscChannel<Event>,
}

impl AuthServer {
    fn new(
        db: Arc<Sqlite>, config: Arc<Config>, serenity: Arc<serenity::Client>,
        mailbox: MailboxActorHandle, names: Vec<String>,
    ) -> Self {
        Self {
            db,
            clients: Arc::new(Clients::new(serenity, &config)),
            config,
            mailbox,
            bad_names: names,
            event_bus: channel(128),
        }
    }
}

pub enum Event {
    Motd {
        server_id: Uuid,
        text: String,
    },
    DiscordLink {
        profile: String,
        discord_id: String,
        discord_username: String,
        when: Option<DateTime<Utc>>,
    },
}

type MpscChannel<T> = (Sender<T>, Receiver<T>);

pub struct Clients {
    pub reqwest: reqwest::Client,
    pub serenity: Arc<serenity::Client>,
    pub oauth: OAuthClient,
}

impl Clients {
    fn new(serenity: Arc<serenity::Client>, cfg: &Config) -> Self {
        Self {
            reqwest: Client::new(),
            serenity,
            oauth: oauth::routes::get_client(cfg).unwrap(),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let base_path = env::var("BASE_PATH").unwrap_or_else(|_| ".".to_string());

    let no_discord = env::var("NO_DISCORD").ok();

    let db_path = PathBuf::from(format!("{}/data.db", base_path));
    let old_data = PathBuf::from(format!("{}/data.json", base_path));
    let config_path = PathBuf::from(format!("{}/config.json", base_path));
    let bad_path = PathBuf::from(format!("{}/blacklist.json", base_path));

    let db = if old_data.exists() {
        // We will migrate the data then move it to data.json.old
        if let Ok(db) = migrate(&db_path, &old_data).await {
            match fs::rename(old_data.clone(), "data.json.bak") {
                Ok(()) => println!("Sucessfully moved old data file."),
                Err(_) => panic!(
                    "Manual intervention required.
                Old json-backed store refused to be moved.
                Please manually move \"{:?}\" to another location.",
                    old_data
                        .canonicalize()
                        .unwrap_or_else(|_| PathBuf::from("data.json"))
                ),
            }
            Arc::new(db)
        } else {
            Arc::new(Sqlite::new(&db_path).await)
        }
    } else {
        Arc::new(Sqlite::new(&db_path).await)
    };

    let _ = migrate_v2(&db_path).await;

    db.run_migrations().await;

    let config = Config::from_file_or_default(&config_path);

    if Config::is_empty(&config) {
        Config::to_file(&config, &config_path)
            .expect("Error happened while saving config to file.");
        panic!("Please change the configuration file on {:?}.", config_path)
    }
    let token = std::env::var("DISCORD_BOT_TOKEN").expect("Expected a discord bot token in path.");

    let bad_text = fs::read_to_string(bad_path).unwrap_or_else(|_| "[\"fail2ban\"]".to_string());
    let bad_names: Vec<String> = serde_json::from_str(&bad_text).unwrap();

    let http_client = serenity::Client::builder(&token, GatewayIntents::GUILD_MODERATION)
        .await
        .expect("Error while building client");

    let shared = Arc::new(http_client);

    let mailbox = MailboxActor::spawn(
        db.clone(),
        shared.clone(),
        config.server_status_channel_id.parse().unwrap(),
        config.verification_channel_id.parse().unwrap(),
        config.verification_role_id.parse().unwrap(),
        config.playing_role_id.parse().unwrap(),
        config.guild_id.parse().unwrap(),
        bad_names.clone(),
    );

    let auth_server = Arc::new(AuthServer::new(
        db.clone(),
        Arc::new(config),
        shared,
        mailbox.clone(),
        bad_names,
    ));

    let bot_fw = framework(db.clone(), mailbox.clone()).await;

    let mut gateway_client = serenity::Client::builder(&token, GatewayIntents::GUILD_MODERATION)
        .framework(bot_fw)
        .await
        .expect("Error while building client");

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    let stack = ServiceBuilder::new()
        .sensitive_request_headers(sensitive_headers)
        .layer(TimeoutLayer::with_status_code(StatusCode::OK, Duration::from_secs(20)))
        .compression();

    let server = Router::new()
        .route("/@me", get(routes::game_server::get_self))
        .route("/@me/ws", get(routes::game_server::websocket))
        .route("/@me/heartbeat", post(routes::game_server::keepalive))
        .route("/@me/versions", post(routes::game_server::update_versions));

    let profile = Router::new()
        .route("/", get(routes::profile::get_profile))
        .route("/resolve_discord", get(routes::profile::resolve_discord))
        .route("/resolve_mojang", get(routes::profile::resolve_mojang))
        .route("/resolve_bedrock", get(routes::profile::resolve_bedrock))
        .route("/:username", post(routes::profile::create_profile))
        .route("/:username/mojang", post(routes::profile::connect_mojang))
        .route("/:username/bedrock", post(routes::profile::connect_bedrock))
        .route("/:username/authenticate", post(routes::profile::authenticate))
        .route("/:username/session", get(routes::profile::session))
        .route("/:username/login", post(routes::profile::login))
        .route("/:username/logout", post(routes::profile::logout))
        .route("/:username/password_change", post(routes::profile::password_change));

    let link = Router::new()
        .route("/new", get(routes::discord::get_link))
        .route("/manual", get(routes::discord::manual))
        .route("/", get(routes::discord::link));

    let router = Router::new()
        .nest("/profile", profile)
        .nest("/link", link)
        .nest("/server", server)
        .route("/get_version_ranges", post(routes::utils::get_version_ranges))
        .route("/bad_names", get(routes::utils::get_bad_names))
        .with_state(auth_server)
        .layer(stack);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    let api_listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    // Threads
    let api = axum::serve(api_listener, router);

    if no_discord.is_none() {
        let bot = gateway_client.start();
        // Spawn the threads
        let _ = tokio::join!(api, bot);
    } else {
        warn!("Disabling Discord Bot. Only running the API.");
        let _ = tokio::join!(api);
    }
}
