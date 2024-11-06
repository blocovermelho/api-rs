use std::sync::Arc;

use axum::{extract::State, response::IntoResponse};
use axum_typed_websockets::{Message, WebSocket, WebSocketUpgrade};
use db::data::User;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{routes::LinkResult, AppState};

pub async fn handle_socket(
    ws: WebSocketUpgrade<MessageOut, MessageIn>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| link_socket(socket, state))
}

async fn link_socket(socket: WebSocket<MessageOut, MessageIn>, state: Arc<AppState>) {
    println!("Handling connection to websocket");
    let (mut send, mut recv) = socket.split();
    let read_state = state.clone();

    let mut read_task = tokio::spawn(async move {
        while let Some(message) = recv.next().await {
            match message {
                Ok(Message::Item(message)) => match message {
                    MessageIn::LinkRequest(request) => {
                        handle_link_request(request, &read_state).await;
                    }
                    _ => { handle_unknown(&read_state).await; }
                },

                Ok(_) => {
                    handle_unknown(&read_state).await;
                }
                Err(e) => {
                    handle_error(e, &read_state).await;
                }
            }
        }
    });

    let mut send_task = tokio::spawn(async move {
        let mut messages = state.channel.messages.1.lock().await;
        while let Some(item) = messages.next().await {
            let _ = send.send(Message::Item(item)).await;
        }
    });

    // If any one of the tasks exit, abort the other.
    tokio::select! {
        _rv_a = (&mut send_task) => {
            read_task.abort();
        },
        _rv_b = (&mut read_task) => {
            send_task.abort();
        }
    }
}

async fn handle_error(e: axum_typed_websockets::Error<serde_json::Error>, state: &AppState) {
    let mut buff = state.channel.messages.0.lock().await;
    let _ = buff.send(MessageOut::Error {
        source_event: "generic".to_owned(),
        error: e.to_string(),
    })
    .await;
}

async fn handle_link_request(request: Uuid, state: &AppState) {
    let link = state.channel.links.recv(request).await;
    let mut buff = state.channel.messages.0.lock().await;
    if let Ok(result) = link {
        let _ = buff.send(MessageOut::LinkResponse(result)).await;
        return;
    }

    let _  = buff.send(MessageOut::Error {
        source_event: "link_request".to_owned(),
        error: "An error has occoured while processing your request".to_owned(),
    })
    .await;
}

async fn handle_unknown(state: &AppState) {
    let mut buff = state.channel.messages.0.lock().await;
    let _ = buff.send(MessageOut::Error {
        source_event: "generic".to_owned(),
        error: "Unknown Message".to_owned(),
    })
    .await;
}

#[derive(Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum MessageIn {
    LinkRequest(Uuid),
    CidrAwk(String),
}

#[derive(Serialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum MessageOut {
    LinkResponse(LinkResult),
    CidrSyn(Uuid),
    CidrSynAwk(User) ,
    Error { source_event: String, error: String },
}
