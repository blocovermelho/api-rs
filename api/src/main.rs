use core::{
    trans::db::TryIngest,
    types::{
        enums::PlayerState,
        structs::{packet::GameServerKeepAlive, GameServer, Player, Profile, Session},
    },
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use bimap::BiHashMap;
use chrono::{DateTime, Utc};
use db::interface::DataSource;
use futures::{
    channel::mpsc::{self, channel, Receiver, Sender},
    SinkExt,
};
use json::JsonSync;
use migrate::{migrate, migrate_v2};
use oauth::models::Config;
use reqwest::{header, Client};
// use routes::LinkResult;
use serenity::all::GatewayIntents;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::{
    timeout::TimeoutLayer, trace::TraceLayer, validate_request::ValidateRequestHeaderLayer,
    ServiceBuilderExt,
};
use uuid::Uuid;

// use websocket::MessageOut;
use crate::{db::drivers::sqlite::Sqlite, discord::framework};

// use crate::store::Store;

#[allow(clippy::future_not_send)]
pub mod bus;
pub mod core;
pub mod db;
pub mod discord;
pub mod json;
pub mod middleware;
pub mod migrate;
pub mod models;
pub mod oauth;
pub mod routes;

pub struct AuthServer {
    pub db: Arc<Sqlite>,
    pub clients: Arc<Clients>,
    pub config: Arc<Config>,
    pub state: Arc<Mutex<Ephemeral>>,
    pub event_bus: MpscChannel<Event>,
}

impl AuthServer {
    fn new(db: Arc<Sqlite>, config: Arc<Config>, serenity: serenity::Client) -> Self {
        Self {
            db,
            clients: Arc::new(Clients::new(serenity)),
            config,
            state: Arc::new(Mutex::new(Ephemeral::new())),
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

// Ephemeral Data
pub struct Ephemeral {
    pub servers: HashMap<Uuid, GameServer>,
    pub(crate) sessions: HashMap<Uuid, Session>,
    pub(crate) tokens: BiHashMap<Uuid, String>,
    pub(crate) nonces: BiHashMap<String, String>,
    pub(crate) bad_password_count: HashMap<Uuid, i32>,
}

impl Ephemeral {
    fn new() -> Self {
        Self {
            servers: HashMap::new(),
            sessions: HashMap::new(),
            tokens: BiHashMap::new(),
            nonces: BiHashMap::new(),
            bad_password_count: HashMap::new(),
        }
    }
}

pub struct Clients {
    pub reqwest: reqwest::Client,
    pub serenity: serenity::Client,
}

impl Clients {
    fn new(serenity: serenity::Client) -> Self {
        Self { reqwest: Client::new(), serenity }
    }
}

#[tokio::main]
async fn main() {
    let db_path = PathBuf::from("data.db");
    let old_data = PathBuf::from("data.json");
    let config_path = PathBuf::from("config.json");

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

    let http_client = serenity::Client::builder(&token, GatewayIntents::GUILD_MODERATION)
        .await
        .expect("Error while building client");

    let auth_server = Arc::new(AuthServer::new(db.clone(), Arc::new(config), http_client));

    let bot_fw = framework(db.clone(), auth_server.state.clone()).await;

    let mut gateway_client = serenity::Client::builder(&token, GatewayIntents::GUILD_MODERATION)
        .framework(bot_fw)
        .await
        .expect("Error while building client");

    tracing_subscriber::fmt::init();

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    let stack = ServiceBuilder::new()
        .sensitive_request_headers(sensitive_headers)
        .layer(TimeoutLayer::new(Duration::from_secs(20)))
        .compression();

    let server = Router::new()
        .route("/@me", get(routes::game_server::get_self))
        .route("/@me/heartbeat", post(routes::game_server::keepalive));

    let profile = Router::new()
        .route("/", get(routes::profile::get_profile))
        .route("/resolve_mojang", get(routes::profile::resolve_mojang))
        .route("/resolve_bedrock", get(routes::profile::resolve_bedrock))
        .route("/:username/mojang", post(routes::profile::connect_mojang))
        .route("/:username/bedrock", post(routes::profile::connect_bedrock))
        .route("/:username/login", post(routes::profile::login))
        .route("/:username/logout", post(routes::profile::logout))
        .route("/:username/password_change", post(routes::profile::password_change));

    let link = Router::new()
        .route("/new", get(routes::discord::get_link))
        .route("/", get(routes::discord::link));

    let router = Router::new()
        .nest("/profile", profile)
        .nest("/link", link)
        .nest("/server", server)
        .with_state(auth_server);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    // Threads
    let api = axum::Server::bind(&addr).serve(router.into_make_service());
    let bot = gateway_client.start();

    // Spawn the threads
    let _ = tokio::join!(api, bot);
}
