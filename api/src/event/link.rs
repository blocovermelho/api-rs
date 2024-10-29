use axum::async_trait;
use db::{data::stub::UserStub, interface::DataSource};
use oauth2::{reqwest::async_http_client, AuthorizationCode};

use crate::event::{Event, EventKind};

use super::{Module, ModuleCtx};

pub struct PlayerLinkModule {
    ctx: ModuleCtx,
}

#[async_trait]
impl Module for PlayerLinkModule {
    fn new(ctx: ModuleCtx) -> Self {
        PlayerLinkModule { ctx }
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                e =  self.ctx.receiver.recv() => {
                   match e {
                       Ok(event) => { let _ = self.handle_event(event).await; },
                       Err(e) => println!("Error: {}", e),
                   }
                }
            }
        }
    }

    async fn handle_event(&mut self, event: Event) -> anyhow::Result<()> {
        let db = &self.ctx.instance.db;
        let mut ephemeral = self.ctx.instance.ephemeral_data.lock().await;
        let client = &self.ctx.instance.oauth_client;
        let module_name = self.ctx.name.clone();
        match event.inner {
            EventKind::PlayerRequestLink(uuid, name) => {
                if let Ok(user) = db.get_user_by_uuid(&uuid).await {
                    let _ = self.ctx.sender.send(Event {
                        module: module_name,
                        inner: EventKind::PlayerLinkResponse(
                            uuid,
                            crate::event::LinkStatus::AlreadyLinked(user.discord_id),
                        ),
                    });
                } else {
                    let (uri, nonce) = oauth::routes::authorize(client).url();
                    ephemeral.links.insert(nonce.secret().clone(), uuid.clone());
                    ephemeral.names.insert(name, uuid.clone());

                    let _ = self.ctx.sender.send(Event {
                        module: module_name,
                        inner: EventKind::PlayerLinkResponse(
                            uuid,
                            crate::event::LinkStatus::Nonce(uri.to_string()),
                        ),
                    });
                }

                return Ok(());
            }
            EventKind::DiscordNonceReceived(code, nonce) => {
                if let Some(uuid) = ephemeral.links.get_by_left(&nonce) {
                    let name = ephemeral.names.get_by_right(uuid).unwrap();
                    let response = client
                        .exchange_code(AuthorizationCode::new(code))
                        .request_async(async_http_client)
                        .await;

                    if let Ok(response) = response {
                        if let Ok(member) = oauth::routes::get_guild(
                            &reqwest::Client::new(),
                            &response,
                            &self.ctx.instance.config,
                        )
                        .await
                        {
                            if let Ok(_) = db
                                .create_user(UserStub {
                                    uuid: uuid.clone(),
                                    username: name.clone(),
                                    discord_id: member.user.id.clone(),
                                })
                                .await
                            {
                                let _ = self.ctx.sender.send(Event {
                                    module: module_name,
                                    inner: EventKind::PlayerLinkResponse(
                                        uuid.clone(),
                                        crate::event::LinkStatus::Accepted(member.user.id),
                                    ),
                                });
                            }
                        } else {
                            let _ = self.ctx.sender.send(Event {
                                module: module_name,
                                inner: EventKind::PlayerLinkResponse(
                                    uuid.clone(),
                                    crate::event::LinkStatus::NotInGuild,
                                ),
                            });
                        }
                    } else {
                        let _ = self.ctx.sender.send(Event {
                            module: module_name,
                            inner: EventKind::PlayerLinkResponse(
                                uuid.clone(),
                                crate::event::LinkStatus::Invalid,
                            ),
                        });
                    }
                } else {
                    return Ok(());
                }

                return Ok(());
            }
            EventKind::PlayerLinkResponse(_, _) => return Ok(()),
            EventKind::Error(_) => return Ok(()),
        }
    }
}

impl PlayerLinkModule {}
