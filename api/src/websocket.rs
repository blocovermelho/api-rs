use axum::{extract::State, response::IntoResponse};
use axum_typed_websockets::{Message, WebSocket, WebSocketUpgrade};
use serde::Serialize;

use crate::{
    routes::{LinkResult, UuidQueryParam},
    AppState,
};

#[derive(Serialize)]
pub enum LinkStatusResponse {
    Exists(LinkResult),
    Error(String),
}

pub async fn handle_socket(
    ws: WebSocketUpgrade<LinkStatusResponse, UuidQueryParam>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| link_socket(socket, state))
}

async fn link_socket(mut socket: WebSocket<LinkStatusResponse, UuidQueryParam>, state: AppState) {
    if let Some(message) = socket.recv().await {
        match message {
            Ok(Message::Item(message)) => {
                let link = state.chs.links.recv(message.uuid).await;

                match link {
                    Ok(succ) => {
                        let _ = socket
                            .send(Message::Item(LinkStatusResponse::Exists(succ)))
                            .await;
                    }
                    Err(_) => {
                        let _ = socket
                            .send(Message::Item(LinkStatusResponse::Error(
                                "An error has occoured while processing your request".to_owned(),
                            )))
                            .await;
                    }
                }
            }

            Ok(_) => {
                let _ = socket
                    .send(Message::Item(LinkStatusResponse::Error(
                        "Unknown message.".to_owned(),
                    )))
                    .await;
            }
            Err(e) => {
                let _ = socket
                    .send(Message::Item(LinkStatusResponse::Error(e.to_string())))
                    .await;
            }
        }

        let _ = socket.close().await;
    }
}
