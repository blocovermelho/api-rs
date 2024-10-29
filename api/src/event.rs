use std::{net::Ipv4Addr, sync::Arc};

use axum::async_trait;
use db::{data::Allowlist, drivers::sqlite::Sqlite};
use oauth2::basic::BasicClient;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;

use crate::{AppState2, Ephemeral};

pub mod generator;
pub mod link;
pub mod log;

#[derive(Clone, Debug)]
pub struct Event {
    module: String,
    inner: EventKind,
}

// All events to be sent over the Event Bus
#[derive(Clone, Debug)]
pub enum EventKind {
    // Discord Linking Subsystem
    PlayerRequestLink(Uuid, String),
    DiscordNonceReceived(String, String),
    PlayerLinkResponse(Uuid, LinkStatus),
    Error(String),
}

#[derive(Clone, Debug)]
pub enum LinkStatus {
    AlreadyLinked(String),
    Accepted(String),
    Nonce(String),
    NotInGuild,
    Invalid,
}

pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(128);

        Self { sender }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    pub fn publish(&self, event: Event) {
        let _ = self.sender.send(event);
    }
}

pub struct ModuleCtx {
    pub name: String,
    pub sender: broadcast::Sender<Event>,
    pub receiver: broadcast::Receiver<Event>,
    pub instance: Arc<AppState2>,
}

impl ModuleCtx {
    pub fn new(name: &str, bus: &EventBus, state: &Arc<AppState2>) -> Self {
        let sender = bus.sender.clone();
        let receiver = bus.subscribe();

        ModuleCtx {
            name: name.to_string(),
            sender,
            receiver,
            instance: state.clone(),
        }
    }
}

#[async_trait]
pub trait Module {
    fn new(ctx: ModuleCtx) -> Self;
    async fn run(&mut self) -> anyhow::Result<()>;
    async fn handle_event(&mut self, event: Event) -> anyhow::Result<()>;
}
