use std::time::Duration;

use axum::{extract::State, response::IntoResponse};
use axum_typed_websockets::{Message, WebSocket, WebSocketUpgrade};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use uuid::Uuid;

use crate::{models::User, routes::LinkResult, AppState};

pub async fn handle_socket(
    ws: WebSocketUpgrade<MessageOut, MessageIn>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| link_socket(socket, state))
}

async fn link_socket(socket: WebSocket<MessageOut, MessageIn>, state: AppState) {
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

                    MessageIn::CidrAwk(nonce) => {
                        handle_cidr_awk(nonce, &read_state).await;
                    }
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
        let mut messages = state.chs.messages.1.lock().await;
        while let Some(item) = messages.next().await {
            let _ = send.send(Message::Item(item)).await;
        }
    });

    // If any one of the tasks exit, abort the other.
    tokio::select! {
        rv_a = (&mut send_task) => {
            read_task.abort();
        },
        rv_b = (&mut read_task) => {
            send_task.abort();
        }
    }
}

async fn handle_error(e: axum_typed_websockets::Error<serde_json::Error>, state: &AppState) {
    let mut buff = state.chs.messages.0.lock().await;
    let _ = buff.send(MessageOut::Error {
        source_event: "generic".to_owned(),
        error: e.to_string(),
    })
    .await;
}

async fn handle_cidr_awk(nonce: String, state: &AppState) {
    let user_id = timeout(Duration::from_secs(5), state.chs.verify.recv(nonce.clone())).await;
    let mut buff = state.chs.messages.0.lock().await;

    if let Err(_) = user_id {
        let _ = buff.send(MessageOut::Error { source_event: "cidr_awk".to_owned(), error: "Timed Out".to_owned() }).await;
        return;
    }

    if let Ok(Ok(user_id)) = user_id {
        let store = state.data.lock().await;
        let user = store.get_user_from_discord(user_id);
        
        if let Some(user) = user {
            let _ = buff.send(MessageOut::CidrSynAwk(user.clone())).await;
        } else {
            let _ = buff.send(MessageOut::Error { source_event: "cidr_awk".to_owned(), error: "User not found.".to_owned() }).await;
        }        
        return;
    }

    if let Ok(Err(_)) = user_id {
        // Tried reusing an expired channel. This can happen when users retry the command with the same token.
        // In this case we can't just rely on the channel to provide us the discord id, which requires an reach-around
        // to the store to get if that exists or not.

        let store = state.data.lock().await;
        let holder = store.get_handshake_holder(&nonce);

        if let Some(holder) = holder {
            let _ = buff.send(MessageOut::CidrSynAwk(holder)).await;
            return;
        } else {
            let _ = buff.send(MessageOut::Error { source_event: "cidr_awk".to_owned(), error: "Invalid Token.".to_owned() }).await;
            return;
        }
    }


    let _ = buff.send(MessageOut::Error { source_event: "cidr_awk".to_owned(), error: "Unreachable.".to_owned() }).await;
    return;
}

async fn handle_link_request(request: Uuid, state: &AppState) {
    let link = state.chs.links.recv(request).await;
    let mut buff = state.chs.messages.0.lock().await;
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
    let mut buff = state.chs.messages.0.lock().await;
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
