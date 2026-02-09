use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use chrono::{DateTime, TimeDelta, Utc};
use serenity::all::{ChannelId, CreateEmbed, CreateEmbedFooter, CreateMessage, EditMessage};
use tokio::time::Instant;
use uuid::Uuid;

use super::{
    discord::DiscordActorHandle,
    livemessage::{LiveMessageActor, LiveMessageActorHandle},
    mailbox::MailboxCommand,
    prelude::*,
    session::SessionState,
};
use crate::{
    core::trans::to_monotonic,
    discord::render::embed::{self, info, BV_GITHUB_ICON},
};

/*
 * Server Liveliness Actor.
 * Keeps track of game server state, including capabilities to send
 * messages to a discord channel with a formatted display of said state
 */

pub struct ServerLivelinessA {
    pub uuid: Uuid,
    pub name: String,
    pub game: String,
    pub versions: Vec<String>,
    pub max_players: i32,
    pub profiles: HashMap<String, SessionState>,
    pub visitors: HashSet<String>,
    pub motd: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub update_count: i32,
    pub missed_count: i32,
    message_hnd: LiveMessageActorHandle,
    mailbox_hnd: WeakUnboundedSender<MailboxCommand>,
}

impl ServerLivelinessA {
    fn deadline(&self) -> Instant {
        let target = self.last_seen + TimeDelta::minutes(1);
        to_monotonic(target)
    }

    fn ping(&mut self) {
        debug!(
            "[a:ServerLiveliness({})] Event:Ping RECV | update={}, miss={} ",
            self.uuid, self.update_count, self.missed_count
        );

        self.missed_count = 0;
        self.update_count += 1;
        self.last_seen = Utc::now();

        self.message_hnd
            .submit_change(EditMessage::new().embed(self.message_from()));

        debug!(
            "[a:ServerLiveliness({})] Event:Ping HANDLE | update={}, miss={} ",
            self.uuid, self.update_count, self.missed_count
        );
    }

    fn keep_alive(
        &mut self, visitors: Vec<String>, profiles: Vec<SessionState>, motd: Option<String>,
    ) {
        debug!(
            "[a:ServerLiveliness({})] Event:KeepAlive RECV |  update={}, miss={} | visitor={}, profile={} | motd={:?}",
            self.uuid, self.update_count, self.missed_count, self.visitors.len(), self.profiles.len(), self.motd
        );

        self.missed_count = 0;
        self.update_count += 1;
        self.last_seen = Utc::now();
        self.visitors = visitors.into_iter().collect();

        self.profiles.clear();

        for prof in profiles {
            match prof {
                SessionState::Visitor => continue,
                SessionState::PendingLogin { ref profile } => {
                    self.profiles.insert(profile.username.clone(), prof.clone());
                }
                SessionState::LoggedIn { ref profile } => {
                    self.profiles.insert(profile.username.clone(), prof.clone());
                }
            }
        }

        self.motd = motd;

        self.message_hnd
            .submit_change(EditMessage::new().embed(self.message_from()));

        debug!(
            "[a:ServerLiveliness({})] Event:KeepAlive HANDLE |  update={}, miss={} | visitor={}, profile={} | motd={:?}",
            self.uuid, self.update_count, self.missed_count, self.visitors.len(), self.profiles.len(), self.motd
        );
    }

    async fn poll(&mut self) {
        debug!(
            "[a:ServerLiveliness({})] Event:Poll RECV | update={}, miss={} ",
            self.uuid, self.update_count, self.missed_count
        );

        self.update_count = 0;
        self.missed_count += 1;
        self.last_seen = Utc::now();

        self.message_hnd
            .edit_instantly(EditMessage::new().embed(self.message_from()));

        debug!(
            "[a:ServerLiveliness({})] Event:Poll HANDLE | update={}, miss={} ",
            self.uuid, self.update_count, self.missed_count
        );
    }

    fn update_versions(&mut self, versions: Vec<String>) {
        self.versions = versions;
    }

    fn message_from(&self) -> CreateEmbed {
        let (color, footer) = if self.missed_count == 0 {
            (
                embed::colors::SERVER_ONLINE,
                format!(
                    "Servidor Online | Recebeu {} atualizações desde {}",
                    self.update_count, self.last_seen
                ),
            )
        } else if self.missed_count <= 4 {
            (embed::colors::SERVER_WARN, format!("Servidor Inativo | Perdeu {}/5 atualizações | Será retirado da lista em {} minutos", self.missed_count, 5i32.saturating_sub(self.missed_count)))
        } else {
            (
                embed::colors::ERROR,
                "Servidor Offline | Perdeu 4/5 atualizações | Será retirado da lista em instantes."
                    .to_owned(),
            )
        };

        let player_count = self.profiles.len() + self.visitors.len();

        // Since it could be very large, we need to do "And x more" at the end.
        // Lets assume 20 digits per snowflake + 1 emoji + 1 space + 1 newline
        // 1024 / 23 = ~44 , if there are more then 40 members add "And x more at the end"

        let member_field: Vec<String> = self
            .profiles
            .values()
            .map(|it| match it {
                SessionState::Visitor => String::new(),
                SessionState::PendingLogin { profile } => format!("🟨 <@{}>", profile.discord_id),
                SessionState::LoggedIn { profile } => format!("🟢 <@{}>", profile.discord_id),
            })
            .take(40)
            .collect();

        let member_contents = if self.profiles.len() > 40 {
            format!(
                "{}\n... e mais {} membros",
                member_field.join("\n"),
                self.profiles.len().saturating_sub(40)
            )
        } else {
            member_field.join("\n")
        };

        let description = if let Some(motd) = &self.motd {
            format!(
                "**MOTD:** {}\n**Versão(es):**{}\n**Última Atualização:** <t:{}:R>",
                motd,
                self.versions.join(", "),
                self.last_seen.timestamp()
            )
        } else {
            format!(
                "**Versão(es):**{}\n**Última Atualização:** <t:{}:R>",
                self.versions.join(", "),
                self.last_seen.timestamp()
            )
        };

        let mut embed = embed::base()
            .color(color)
            .title(format!(
                "[{}] {} - {}/{} players",
                self.game, self.name, player_count, self.max_players
            ))
            .description(description)
            .footer(CreateEmbedFooter::new(footer).icon_url(BV_GITHUB_ICON));

        if !member_field.is_empty() {
            embed = embed.field("Membros", member_contents, false);
        }

        if !self.visitors.is_empty() {
            embed = embed.field(
                "Visitantes",
                self.visitors.iter().cloned().collect::<Vec<_>>().join(", "),
                false,
            );
        }

        embed
    }
}

pub enum ServerLivelinessCommand {
    Ping, /* Empty Keep-alive */
    KeepAlive {
        visitors: Vec<String>,
        profiles: Vec<SessionState>,
        motd: Option<String>,
    },
    Poll,
    UpdateVersions(Vec<String>),
}

pub struct ServerLivelinessActor {
    state: ServerLivelinessA,
    queue: mpsc::UnboundedReceiver<ServerLivelinessCommand>,
}

pub struct ServerSpawn {
    pub uuid: Uuid,
    pub name: String,
    pub game: String,
    pub versions: Vec<String>,
    pub max_players: i32,
}

impl ServerLivelinessActor {
    pub async fn spawn(
        server_spawn: ServerSpawn, channel_id: ChannelId, discord: DiscordActorHandle,
        mailbox: WeakUnboundedSender<MailboxCommand>,
    ) -> ServerLivelinessActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();

        // Create temporary message
        let message = discord
            .send_message(
                channel_id,
                CreateMessage::new().embed(info(
                    format!("Status - {}", server_spawn.name),
                    "Carregando informações...",
                )),
            )
            .await
            .expect("Need to have gotten a message to start the live message actor.");

        let livemessage_hnd = LiveMessageActor::spawn(
            Duration::from_mins(1),
            message.id,
            channel_id,
            true,
            discord.clone(),
        );

        debug!(
            "[a:ServerLiveliness({})] Spawn:Self SPAWN LiveMessageActor({})",
            server_spawn.uuid, message.id
        );

        let actor = Self {
            state: ServerLivelinessA {
                uuid: server_spawn.uuid,
                name: server_spawn.name,
                game: server_spawn.game,
                max_players: server_spawn.max_players,
                versions: server_spawn.versions,
                profiles: HashMap::new(),
                visitors: HashSet::new(),
                motd: None,
                update_count: 0,
                missed_count: 0,
                last_seen: Utc::now(),
                mailbox_hnd: mailbox,
                message_hnd: livemessage_hnd.clone(),
            },
            queue: rx,
        };

        livemessage_hnd.edit_instantly(EditMessage::new().embed(actor.state.message_from()));

        tokio::spawn(async move { actor.run().await });

        ServerLivelinessActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        while !self.queue.is_closed() {
            tokio::select! {
                cmd = self.queue.recv() => match cmd {
                    Some(cmd) => {
                        match cmd {
                            ServerLivelinessCommand::Ping => {
                                self.state.ping();
                            }
                            ServerLivelinessCommand::KeepAlive { visitors, profiles, motd } => {
                                self.state.keep_alive(visitors, profiles, motd);
                            }
                            ServerLivelinessCommand::Poll => {
                                if self.state.missed_count == 5 {
                                    break;
                                }

                                self.state.poll().await;
                            },
                            ServerLivelinessCommand::UpdateVersions(versions) => self.state.update_versions(versions)
                        }
                    },
                    None => {
                        break;
                    }
                },
                _ = tokio::time::sleep_until(self.state.deadline()) => {
                    if self.state.missed_count == 5 {
                        break;
                    }

                    self.state.poll().await;
                }
            }
        }

        if let Some(hnd) = self.state.mailbox_hnd.upgrade() {
            let _ = hnd.send(MailboxCommand::CleanupLiveliness(self.state.uuid));
        }
    }
}

#[derive(Clone)]
pub struct ServerLivelinessActorHandle {
    queue: mpsc::UnboundedSender<ServerLivelinessCommand>,
}

impl ServerLivelinessActorHandle {
    pub fn ping(&self) {
        notify_actor!(self.queue, ServerLivelinessCommand::Ping);
    }

    pub fn keep_alive(
        &self, visitors: Vec<String>, profiles: Vec<SessionState>, motd: Option<String>,
    ) {
        notify_actor!(self.queue, ServerLivelinessCommand::KeepAlive { visitors, profiles, motd });
    }

    pub fn poll(&self) {
        notify_actor!(self.queue, ServerLivelinessCommand::Poll);
    }

    pub fn modify_versions(&self, versions: Vec<String>) {
        notify_actor!(self.queue, ServerLivelinessCommand::UpdateVersions(versions));
    }

    pub fn mock() -> (Self, mpsc::UnboundedReceiver<ServerLivelinessCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { queue: tx }, rx)
    }
}
