use std::fs::File;
use std::io::prelude::*;

use std::time::Duration;
use std::{sync::Arc, path::PathBuf};
use std::net::SocketAddr;

use axum::{
    routing::{get, post, patch},
    Router,
};

use bus::OneshotBus;
use routes::LinkResult;
use tokio::sync::Mutex;

use oauth::models::Config;
use reqwest::{Client, header};
use tower::ServiceBuilder;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tower_http::{ServiceBuilderExt, timeout::TimeoutLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::store::Store;

pub mod bus;
pub mod models;
pub mod routes;
pub mod store;
pub mod websocket;

struct Channels {
    links: OneshotBus<Uuid, LinkResult>,
}

impl Channels {
    fn new() -> Self {
        Self {
            links: OneshotBus::new(),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    data: Arc<Mutex<Store>>,
    path: Option<PathBuf>,
    config: Arc<Mutex<Config>>,
    config_path: Option<PathBuf>,
    reqwest_client: Arc<Mutex<Client>>,
    chs: Arc<Channels>,
}

impl AppState {
    pub fn load(store: Store, path: Option<PathBuf>, config: Config, config_path: Option<PathBuf>) -> AppState {
        AppState {
            data: Arc::new(Mutex::new(store)),
            path,
            config: Arc::new(Mutex::new(config)),
            config_path,
            reqwest_client: Arc::new(Mutex::new(Client::new())),
            chs: Arc::new(Channels::new()),
        }
    }

    pub fn new() -> AppState {
        AppState {
            data: Arc::new(Mutex::new(Store::new())),
            path: None,
            config: Arc::new(Mutex::new(Config::empty())),
            config_path: None,
            reqwest_client: Arc::new(Mutex::new(Client::new())),
            chs: Arc::new(Channels::new()),
        }
    }

    pub fn file(path: PathBuf, config_path: PathBuf) -> AppState {
        AppState {
            data: Arc::new(Mutex::new(Store::new())),
            path: Some(path),
            config: Arc::new(Mutex::new(Config::empty())),
            config_path: Some(config_path),
            reqwest_client: Arc::new(Mutex::new(Client::new())),
            chs: Arc::new(Channels::new()),
        }
    }

    pub fn flush(&self, data: &Store) -> std::io::Result<()> {
        let path = self.path.clone().expect("Cannot flush state without a path");
        let str = serde_json::to_string_pretty(data)?;
        std::fs::write(path, str)?;

        Ok(())
    }

    pub fn from(path: &PathBuf, config_path: &PathBuf) -> std::io::Result<AppState> {
        let mut file = File::open(path)?;
        let mut str = String::new();

        file.read_to_string(&mut str)?;

        let state = serde_json::from_str(&str)?;

        str = String::new();

        file = File::open(config_path)?;
        file.read_to_string(&mut str)?;

        let config = serde_json::from_str(&str)?;
        
        Ok(AppState::load(state, Some(path.to_owned()), config, Some(config_path.to_owned())))
    }
}

#[tokio::main]
async fn main() {
    let path = ["data.json"].iter().collect();
    let config_path = ["config.json"].iter().collect();

    let s = AppState::from(&path, &config_path).unwrap();

    tracing_subscriber::fmt::init();

    let sensitive_headers : Arc<[_]> = vec![header::AUTHORIZATION, header::COOKIE].into();

    let stack = ServiceBuilder::new()
        .sensitive_request_headers(sensitive_headers.clone())
        .layer(TimeoutLayer::new(Duration::from_secs(20)))
        .compression()
    ;

    let token = std::env::var("API_AUTH_TOKEN").expect("API_AUTH_TOKEN Environment variable is NOT SET.");

    let authenticated = stack.clone().layer(ValidateRequestHeaderLayer::bearer(&token));


    let server = Router::new()
        .route("/:server_id/enable", patch(routes::enable).layer(authenticated.clone()))
        .route("/:server_id/disable", patch(routes::disable).layer(authenticated.clone()))
        .route("/:server_id", get(routes::get_server))
        .route("/", post(routes::create_server).layer(authenticated.clone()))
        ;

    let user = Router::new()
        .route("/:user_id", get(routes::get_user))
        .route("/", post(routes::create_user)
            .layer(authenticated.clone())
        )
        ;

    let auth = Router::new()
        .route("/:server_id/logoff", post(routes::logoff))
        .route("/:server_id/login", post(routes::login))
        .route("/session", get(routes::get_session))
        .route("/changepw", patch(routes::changepw))
        .route("/", post(routes::create_account))
        .layer(authenticated)
        ;

    let app = Router::new()
        .route("/link", get(routes::link))
        .route("/oauth", get(routes::discord))
        .route("/servers", get(routes::get_servers))
        .route("/users", get(routes::get_users))
        .nest("/server", server)
        .nest("/user", user)
        .nest("/auth", auth)
        .with_state(s)
        .layer(stack)
        .layer(TraceLayer::new_for_http())
        ;

    let addr = SocketAddr::from(([127,0,0,1], 8080));
    
    axum::Server::bind(&addr)
    .serve(app.into_make_service())
    .await
    .expect("server err")

}
