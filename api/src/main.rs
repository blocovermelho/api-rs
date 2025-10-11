use std::{collections::HashMap, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use bimap::BiHashMap;
use bus::OneshotBus;
use bv_discord::framework;
use db::drivers::sqlite::Sqlite;
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use migrate::migrate;
use oauth::models::Config;
use reqwest::{header, Client};
use routes::LinkResult;
use serenity::all::GatewayIntents;
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::{
    timeout::TimeoutLayer, trace::TraceLayer, validate_request::ValidateRequestHeaderLayer,
    ServiceBuilderExt,
};
use traits::json::JsonSync;
use uuid::Uuid;
use websocket::MessageOut;

// use crate::store::Store;

#[allow(clippy::future_not_send)]
pub mod bus;
pub mod cidr;
pub mod migrate;
pub mod models;
pub mod routes;
// pub mod store;
pub mod websocket;

#[allow(clippy::type_complexity)]
struct Channels {
    links: OneshotBus<Uuid, LinkResult>,
    messages: Arc<(Mutex<UnboundedSender<MessageOut>>, Mutex<UnboundedReceiver<MessageOut>>)>,
}

impl Channels {
    fn new() -> Self {
        Self {
            links: OneshotBus::new(),
            messages: {
                let (tx, rx) = mpsc::unbounded();
                Arc::new((Mutex::new(tx), Mutex::new(rx)))
            },
        }
    }
}

// AppState2
// Should be Sync.
pub struct AppState {
    db: Arc<Sqlite>,
    config: Arc<Config>,
    ephemeral: Arc<Mutex<Ephemeral>>,
    client: Arc<Clients>,
    channel: Arc<Channels>,
}

impl AppState {
    fn new(db: Arc<Sqlite>, config: Arc<Config>, serenity: serenity::Client) -> Self {
        Self {
            db,
            ephemeral: Arc::new(Mutex::new(Ephemeral::new())),
            config,
            client: Arc::new(Clients::new(serenity)),
            channel: Arc::new(Channels::new()),
        }
    }
}

// Ephemeral Data
pub struct Ephemeral {
    /// A map containing all this session's pending discord links.
    /// Mapping: Minecraft UUID <-> Discord Nonce (State Parameter).
    pub links: BiHashMap<Uuid, String>,
    /// A map containing every logged users' username.  
    /// Mapping: Minecraft UUID <-> Minecraft Username
    pub names: BiHashMap<Uuid, String>,
    /// A map containing bad password attempts
    pub password: HashMap<Uuid, i32>,
}

impl Ephemeral {
    fn new() -> Self {
        Self {
            links: BiHashMap::new(),
            names: BiHashMap::new(),
            password: HashMap::new(),
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

    db.run_migrations().await;

    let config = Config::from_file_or_default(&config_path);

    if Config::is_empty(&config) {
        Config::to_file(&config, &config_path)
            .expect("Error happened while saving config to file.");
        panic!("Please change the configuration file on {:?}.", config_path)
    }

    let bot_fw = framework(db.clone()).await;

    let token = std::env::var("DISCORD_BOT_TOKEN").expect("Expected a discord bot token in path.");

    let http_client = serenity::Client::builder(&token, GatewayIntents::GUILD_MODERATION)
        .await
        .expect("Error while building client");

    let mut gateway_client = serenity::Client::builder(&token, GatewayIntents::GUILD_MODERATION)
        .framework(bot_fw)
        .await
        .expect("Error while building client");

    let state = Arc::new(AppState::new(db, Arc::new(config), http_client));

    tracing_subscriber::fmt::init();

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    let stack = ServiceBuilder::new()
        .sensitive_request_headers(sensitive_headers)
        .layer(TimeoutLayer::new(Duration::from_secs(20)))
        .compression();

    let token =
        std::env::var("API_AUTH_TOKEN").expect("API_AUTH_TOKEN Environment variable is NOT SET.");

    let authenticated = stack
        .clone()
        .layer(ValidateRequestHeaderLayer::bearer(&token));

    let server = Router::new()
        .route("/:server_id/enable", patch(routes::enable).layer(authenticated.clone()))
        .route("/:server_id/disable", patch(routes::disable).layer(authenticated.clone()))
        .route("/:server_id", get(routes::get_server))
        .route("/:server_id", delete(routes::delete_server).layer(authenticated.clone()))
        .route("/", post(routes::create_server).layer(authenticated.clone()));

    let user = Router::new()
        .route("/exists", get(routes::user_exists))
        .route("/:user_id", get(routes::get_user))
        .route("/by-name/:username", get(routes::get_user_by_name))
        .route("/by-discord/:discord_id", get(routes::get_user_by_discord))
        .route("/:user_id", delete(routes::delete_user).layer(authenticated.clone()))
        .route("/", post(routes::create_user).layer(authenticated.clone()));

    let auth = Router::new()
        // .route("/handshake", post(routes::cidr_handshake))
        // .route("/grace", post(routes::cidr_grace))
        .route("/ban", post(routes::ban_cidr))
        .route("/allow", post(routes::allow_cidr))
        // .route("/disallow", post(routes::disallow_cidr))
        // .route("/disallow-ingame", post(routes::disallow_cidr_ingame))
        .route("/cidr", get(routes::cidr_check))
        .route("/exists", get(routes::account_exists))
        .route("/:server_id/logoff", post(routes::logoff))
        .route("/:server_id/login", post(routes::login))
        .route("/:user_id", delete(routes::delete_account))
        .route("/resume", patch(routes::resume))
        .route("/session", get(routes::get_session))
        .route("/changepw", patch(routes::changepw))
        .route("/ws", get(websocket::handle_socket))
        .route("/", post(routes::create_account))
        .layer(authenticated);

    let app = Router::new()
        .route("/link", get(routes::link))
        .route("/oauth", get(routes::discord))
        .route("/servers", get(routes::get_servers))
        .route("/users", get(routes::get_users))
        .nest("/server", server)
        .nest("/user", user)
        .nest("/auth", auth)
        .with_state(state)
        .layer(stack)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    // Threads
    let api = axum::Server::bind(&addr).serve(app.into_make_service());
    let bot = gateway_client.start();

    // Spawn the threads
    let _ = tokio::join!(tokio::spawn(api), bot);
}
