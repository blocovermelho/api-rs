use std::fs::File;
use std::io::prelude::*;

use std::{sync::Arc, path::PathBuf};
use std::net::SocketAddr;

use axum::{
    routing::{get, post, patch},
    Router,
};

use std::sync::Mutex;
use crate::store::Store;

pub mod models;
pub mod routes;
pub mod store;

#[derive(Clone)]
pub struct AppState {
    data: Arc<Mutex<Store>>,
    path: Option<PathBuf>
}

impl AppState {
    pub fn load(store: Store, path: Option<PathBuf>) -> AppState {
        AppState {
            data: Arc::new(Mutex::new(store)),
            path
        }
    }

    pub fn new() -> AppState {
        AppState {
            data: Arc::new(Mutex::new(Store::new())),
            path: None
        }
    }

    pub fn file(path: PathBuf) -> AppState {
        AppState {
            data: Arc::new(Mutex::new(Store::new())),
            path: Some(path)
        }
    }

    pub fn flush(&self, data: &Store) -> std::io::Result<()> {
        let path = self.path.clone().expect("Cannot flush state without a path");
        let str = serde_json::to_string_pretty(data)?;
        std::fs::write(path, str)?;

        Ok(())
    }

    pub fn from(path: &PathBuf) -> std::io::Result<AppState> {
        let mut file = File::open(path)?;
        let mut str = String::new();

        file.read_to_string(&mut str)?;

        let state = serde_json::from_str(&str)?;
        
        Ok(AppState::load(state, Some(path.to_owned())))
    }
}

#[tokio::main]
async fn main() {
    let path = ["data.json"].iter().collect();

    let s = AppState::from(&path).unwrap_or_else(|_| AppState::file(path));

    let server = Router::new()
        .route("/:server_id/enable", patch(routes::enable))
        .route("/:server_id/disable", patch(routes::disable))
        .route("/:server_id", get(routes::get_server))
        .route("/", post(routes::create_server))
        ;

    let user = Router::new()
        .route("/:user_id", get(routes::get_user))
        .route("/", post(routes::create_user))
        ;

    let auth = Router::new()
        .route("/:server_id/logoff", post(routes::logoff))
        .route("/:server_id/login", post(routes::login))
        .route("/session", get(routes::get_session))
        .route("/changepw", patch(routes::changepw))
        .route("/", post(routes::create_account))
        ;

    let app = Router::new()
        .route("/servers", get(routes::get_servers))
        .route("/users", get(routes::get_users))
        .nest("/server", server)
        .nest("/user", user)
        .nest("/auth", auth)
        .with_state(s);

    let addr = SocketAddr::from(([127,0,0,1], 3000));
    
    axum::Server::bind(&addr)
    .serve(app.into_make_service())
    .await
    .expect("server err")

}
