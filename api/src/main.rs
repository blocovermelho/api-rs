use std::net::SocketAddr;
use std::time::Duration;
use std::{path::PathBuf, sync::Arc};

use axum::{
    routing::{delete, get, patch, post},
    Router,
};

use bus::OneshotBus;
use futures::channel::mpsc::{self, UnboundedSender, UnboundedReceiver};
use routes::LinkResult;
use serenity::all::GatewayIntents;
use tokio::sync::Mutex;

use oauth::models::Config;
use reqwest::{header, Client};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tower_http::{timeout::TimeoutLayer, ServiceBuilderExt};
use traits::json::JsonSync;
use uuid::Uuid;
use websocket::MessageOut;

use crate::store::Store;

pub mod bus;
pub mod cidr;
pub mod migrate;
pub mod models;
pub mod routes;
pub mod store;
pub mod websocket;

// TODO: Replace usages of `OneshotBus` with a more tested channel implementation.
struct Channels {
    links: OneshotBus<Uuid, LinkResult>,
    verify: OneshotBus<String, u64>,
    messages: Arc<(Mutex<UnboundedSender<MessageOut>>, Mutex<UnboundedReceiver<MessageOut>>)>
}

impl Channels {
    fn new() -> Self {
        Self {
            links: OneshotBus::new(),
            verify: OneshotBus::new(),
            messages: {
                let (tx, rx) = mpsc::unbounded();
                Arc::new((Mutex::new(tx), Mutex::new(rx)))
            }
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    // TODO: Migrate to the new Sqlite Backend.
    data: Arc<Mutex<Store>>,
    path: Option<PathBuf>,
    config: Arc<Mutex<Config>>,
    config_path: Option<PathBuf>,
    // TODO: Move discord related code to a separate crate.
    reqwest_client: Arc<Mutex<Client>>,
    discord_client: Arc<serenity::Client>,
    chs: Arc<Channels>
}

impl AppState {
    pub fn load(path: PathBuf, store: Store, config_path: PathBuf, config: Config, client: serenity::Client) -> AppState {
        AppState {
            data: Arc::new(Mutex::new(store)),
            path: Some(path),
            config: Arc::new(Mutex::new(config)),
            config_path: Some(config_path),
            reqwest_client: Arc::new(Mutex::new(Client::new())),
            chs: Arc::new(Channels::new()),
            discord_client: Arc::new(client)
        }
    }

    pub fn flush(&self, data: &Store) -> std::io::Result<()> {
        let path = self
            .path
            .clone()
            .expect("Cannot flush state without a path");
        Store::to_file(data, &path)?;

        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let path = ["data.json"].iter().collect();
    let config_path = ["config.json"].iter().collect();

    let store = Store::from_file_or_default(&path);
    let config = Config::from_file_or_default(&config_path);

    if Store::is_empty(&store) {
        Store::to_file(&store, &path).expect("Error happened while saving store to file.");
    }

    if Config::is_empty(&config) {
        Config::to_file(&config, &config_path)
            .expect("Error happened while saving config to file.");
        panic!("Please change the configuration file on {:?}.", config_path)
    }


    let token = std::env::var("DISCORD_BOT_TOKEN").expect("Expected a discord bot token in path.");

    let client = serenity::Client::builder(&token, GatewayIntents::GUILD_MODERATION).await.expect("Error while building client");

    let s = AppState::load(path, store, config_path, config, client);

    tracing_subscriber::fmt::init();

    let sensitive_headers: Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    let stack = ServiceBuilder::new()
        .sensitive_request_headers(sensitive_headers.clone())
        .layer(TimeoutLayer::new(Duration::from_secs(20)))
        .compression();

    let token =
        std::env::var("API_AUTH_TOKEN").expect("API_AUTH_TOKEN Environment variable is NOT SET.");

    // TODO: Make a better way to authenticate requests.
    // TODO: We'd likely need a flow for distributing new tokens to servers.
    let authenticated = stack
        .clone()
        .layer(ValidateRequestHeaderLayer::bearer(&token));

    let server = Router::new()
        .route(
            "/:server_id/enable",
            patch(routes::enable).layer(authenticated.clone()),
        )
        .route(
            "/:server_id/disable",
            patch(routes::disable).layer(authenticated.clone()),
        )
        .route("/:server_id", get(routes::get_server))
        .route(
            "/:server_id",
            delete(routes::delete_server).layer(authenticated.clone()),
        )
        .route(
            "/",
            post(routes::create_server).layer(authenticated.clone()),
        );

    let user = Router::new()
        .route("/exists", get(routes::user_exists))
        .route("/:user_id", get(routes::get_user))
        .route(
            "/:user_id",
            delete(routes::delete_user).layer(authenticated.clone()),
        )
        .route("/", post(routes::create_user).layer(authenticated.clone()));

    let auth = Router::new()
        .route("/handshake", post(routes::cidr_handshake))
        .route("/grace", post(routes::cidr_grace))
        .route("/ban", post(routes::ban_cidr))
        .route("/allow", post(routes::allow_cidr))
        .route("/disallow", post(routes::disallow_cidr))
        .route("/disallow-ingame", post(routes::disallow_cidr_ingame))
        .route("/cidr", get(routes::cidr_check))        
        .route("/exists", get(routes::account_exists))
        .route("/:server_id/logoff", post(routes::logoff))
        .route("/:server_id/login", post(routes::login))
        .route("/:user_id", delete(routes::delete_account))
        .route("/:user_id/resume", patch(routes::resume))
        .route("/session", get(routes::get_session))
        .route("/changepw", patch(routes::changepw))
        .route("/ws", get(websocket::handle_socket))
        .route("/", post(routes::create_account))
        .layer(authenticated);

    let app = Router::new()
    // FIXME: This should use the `tower::timeout` middleware.
    // FIXME: Currently this uses some faulty handrolled timeout logic.
        .route("/link", get(routes::link))
        .route("/oauth", get(routes::discord))
        .route("/servers", get(routes::get_servers))
        .route("/users", get(routes::get_users))
        .nest("/server", server)
        .nest("/user", user)
        .nest("/auth", auth)
        .with_state(s)
        .layer(stack)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("server err")
}
