/*
 * Websocket server connection handling actor
 */

use axum::extract::ws;
use axum_typed_websockets::{Message, WebSocket};
use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serenity::all::UserId;
use uuid::Uuid;

use super::prelude::*;

// Also empty since there is no need for statefulness yet.
struct WebsocketA {
    server_id: Uuid,
    inner: WebSocket<OutgoingMessage, IncomingMessage>,
}

pub struct WebsocketActor {
    state: WebsocketA,
    queue: mpsc::UnboundedReceiver<WebsocketCommand>,
    self_hnd: mpsc::WeakUnboundedSender<WebsocketCommand>,
    parent_hnd: WeakMailboxSender,
}

impl WebsocketActor {
    pub fn spawn(
        ws: WebSocket<OutgoingMessage, IncomingMessage>, server_id: Uuid,
        mailbox: WeakMailboxSender,
    ) -> WebsocketActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();

        let hnd_tx = tx.clone();

        let actor = Self {
            state: WebsocketA { server_id, inner: ws },
            queue: rx,
            self_hnd: tx.downgrade(),
            parent_hnd: mailbox,
        };

        tokio::spawn(async move {
            actor.run().await;
        });
        WebsocketActorHandle { queue: hnd_tx }
    }

    async fn run(mut self) {
        let (mut send, mut recv) = self.state.inner.split();

        // Send Task
        tokio::spawn(async move {
            while let Some(cmd) = self.queue.recv().await {
                match cmd {
                    WebsocketCommand::SendDiscordLink(discord_link) => {
                        let _ = send
                            .send(Message::Item(OutgoingMessage::DiscordLink(discord_link)))
                            .await;
                    }
                    WebsocketCommand::Close(close_frame) => {
                        let _ = send.send(Message::Close(close_frame)).await;
                        break;
                    }
                }
            }
        });

        // Read Task
        tokio::spawn(async move {
            while let Some(msg) = recv.next().await {
                if let Ok(Message::Item(_msg)) = msg {}
            }
        });
    }
}

pub enum WebsocketCommand {
    SendDiscordLink(DiscordLink),
    Close(Option<ws::CloseFrame<'static>>),
}

#[derive(Clone)]
pub struct WebsocketActorHandle {
    queue: mpsc::UnboundedSender<WebsocketCommand>,
}

impl WebsocketActorHandle {
    pub fn send_discord_link(&self, link: DiscordLink) {
        notify_actor!(self.queue, WebsocketCommand::SendDiscordLink(link));
    }

    pub fn close(&self, frame: Option<ws::CloseFrame<'static>>) {
        notify_actor!(self.queue, WebsocketCommand::Close(frame));
    }

    pub fn mock() -> (Self, mpsc::UnboundedReceiver<WebsocketCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { queue: tx }, rx)
    }
}

// Currently Empty, the websocket will be an outgoing firehose for the time being.
// If other things require interaction from the server sending requests
// they will be added here.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IncomingMessage {}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutgoingMessage {
    DiscordLink(DiscordLink),
}

#[derive(Serialize, Clone)]
pub struct DiscordLink {
    pub username: String,
    pub discord_id: UserId,
    pub discord_handle: String,
    pub is_member: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_since: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<DiscordExtras>,
}

// Extra discord data if an user is a member of the server.
#[derive(Serialize, Clone)]
pub struct DiscordExtras {
    pub nickname: Option<String>,
    pub role_color: Option<String>,
    pub role_name: Option<String>,
}
