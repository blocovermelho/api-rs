use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

use bimap::BiHashMap;
use serenity::all::{
    ChannelId, CreateInteractionResponseFollowup, CreateMessage, GuildId, InteractionId, MessageId,
    RoleId, UserId,
};

use super::{
    discord::DiscordActorHandle,
    ip_notification::{IpNotifActor, IpNotifActorHandle},
    livemessage::LiveMessageActor,
    mailbox::MailboxCommand,
    prelude::*,
};
use crate::{
    core::types::{enums::Heuristic, structs::Profile},
    discord::render::embed::{self, info},
};

/*
 * Actor that holds and manages all notifications sent per IP address
 */

struct NewConnectionA {
    ip: Ipv4Addr,
    fallback_channel: ChannelId,
    fallback_guild: GuildId,
    // Note: This is correct since users should only have *one* notification per IP address
    // Map from Username -> IpNotifHandle
    handles: HashMap<String, IpNotifActorHandle>,
    // BiMap from Username <-> MessageId
    message_ids: BiHashMap<String, MessageId>,
    discord_hnd: DiscordActorHandle,
    database_hnd: DatabaseActorHandle,
    self_hnd: WeakUnboundedSender<NewConnectionCommand>,
    parent_hnd: WeakMailboxSender,
}

impl NewConnectionA {
    pub async fn notify_new_user(&mut self, profile: Profile, server: String) {
        debug!(
            "[a:NewConnection({})] Event:NotifyNewUser RECV | profile={}, server={}",
            self.ip, profile.username, server
        );

        if let Some(hnd) = self.handles.get(&profile.username) {
            hnd.increase();
        } else {
            let user_id = profile.discord_id.parse().unwrap();

            let channel_id = self
                .discord_hnd
                .get_dm_channel(user_id)
                .await
                .unwrap_or(self.fallback_channel);

            if channel_id == self.fallback_channel {
                if let Some(mailbox) = self.parent_hnd.upgrade() {
                    mailbox
                        .send(MailboxCommand::GrantVerificationRole(profile.username.clone()))
                        .unwrap_or(());
                }
            }

            let message = self
                .discord_hnd
                .send_message(
                    channel_id,
                    CreateMessage::new().embed(info(
                        "Bloco Vermelho - Autenticação",
                        "Uma nova conexão foi feita na sua conta. Aguarde para mais informações.",
                    )),
                )
                .await
                .expect("Need an message for LiveMessageActor");

            let msg_hnd = LiveMessageActor::spawn(
                Duration::from_mins(1),
                message.id,
                channel_id,
                false,
                self.discord_hnd.clone(),
            );

            debug!(
                "[a:NewConnection({})] Event:NotifyNewUser SPAWN MessageHandle({})",
                self.ip, message.id,
            );

            let notif_hnd = IpNotifActor::spawn(
                self.ip,
                profile.username.clone(),
                server,
                self.database_hnd.clone(),
                msg_hnd,
                self.self_hnd.clone(),
                self.parent_hnd.clone(),
            );

            debug!(
                "[a:NewConnection({})] Event:NotifyNewUser SPAWN IpNotification({},{}) ",
                self.ip, self.ip, profile.username
            );

            self.handles
                .insert(profile.username.clone(), notif_hnd.clone());
            self.message_ids.insert(profile.username, message.id);

            notif_hnd.increase();
        }
    }

    pub fn notify_solve(&self, heuristic: &Heuristic) {
        for hnd in self.handles.values() {
            hnd.heuristic_solve(heuristic.clone());
        }
    }

    pub async fn btn_click_allow(
        &self, channel: ChannelId, message: MessageId,
        InteractionHolder(id, token): InteractionHolder, author: UserId,
    ) {
        debug!(
            "[a:NewConnection({})] Event:BtnClickAllow RECV | msg={}, author={}",
            self.ip, message, author
        );

        let profiles = self.database_hnd.get_profiles(author).await;
        if profiles.is_empty() {
            self.discord_hnd.create_interaction_followup(
                id,
                token,
                CreateInteractionResponseFollowup::new()
                    .add_embed(embed::error(
                        "Sem perfil",
                        "Você não possui nenum perfil associado a sua conta do discord.
                            Esta mensagem provavelmente não foi direcionada à você.",
                    ))
                    .ephemeral(true),
            );
            return;
        }
        if let Some(target_profile) = self.message_ids.get_by_right(&message) {
            if !profiles.iter().any(|it| it.username == *target_profile) {
                self.discord_hnd.create_interaction_followup(id, token,
                    CreateInteractionResponseFollowup::new().add_embed(embed::error(
                        "Perfil não associado",
                        "Você possui perfis associados a sua conta do discord porém o perfil desta mensagem não é seu."))
                    .ephemeral(true));
                return;
            }

            let hnd = self.handles.get(target_profile).unwrap();
            hnd.handle_allow();
        } else {
            self.discord_hnd.delete_message(channel, message);
        }
    }

    pub async fn btn_click_deny(
        &self, channel: ChannelId, message: MessageId,
        InteractionHolder(id, token): InteractionHolder, author: UserId,
    ) {
        debug!(
            "[a:NewConnection({})] Event:BtnClickDeny RECV | msg={}, author={}",
            self.ip, message, author
        );
        let profiles = self.database_hnd.get_profiles(author).await;
        if profiles.is_empty() {
            self.discord_hnd.create_interaction_followup(
                id,
                token,
                CreateInteractionResponseFollowup::new()
                    .add_embed(embed::error(
                        "Sem perfil",
                        "Você não possui nenum perfil associado a sua conta do discord.
                            Esta mensagem provavelmente não foi direcionada à você.",
                    ))
                    .ephemeral(true),
            );
            return;
        }
        if let Some(target_profile) = self.message_ids.get_by_right(&message) {
            if !profiles.iter().any(|it| it.username == *target_profile) {
                self.discord_hnd.create_interaction_followup(id, token,
                    CreateInteractionResponseFollowup::new().add_embed(embed::error(
                        "Perfil não associado",
                        "Você possui perfis associados a sua conta do discord porém o perfil desta mensagem não é seu."))
                    .ephemeral(true));
                return;
            }

            let hnd = self.handles.get(target_profile).unwrap();
            hnd.handle_disallow();
        } else {
            self.discord_hnd.delete_message(channel, message);
        }
    }

    pub fn cleanup_handle(&mut self, username: &String) {
        debug!(
            "[a:NewConnection({})] Event:CleanupHandle RECV | username={}",
            self.ip, username
        );
        self.handles.remove(username);
        self.message_ids.remove_by_left(username);
    }
}

pub struct NewConnectionActor {
    state: NewConnectionA,
    queue: mpsc::UnboundedReceiver<NewConnectionCommand>,
}

impl NewConnectionActor {
    pub fn spawn(
        ip: Ipv4Addr, fallback_channel: ChannelId, fallback_role: RoleId, fallback_guild: GuildId,
        discord: DiscordActorHandle, database: DatabaseActorHandle, mailbox: WeakMailboxSender,
    ) -> NewConnectionActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();

        let actor = Self {
            state: NewConnectionA {
                ip,
                fallback_channel,
                fallback_guild,
                handles: HashMap::new(),
                message_ids: BiHashMap::new(),
                discord_hnd: discord,
                database_hnd: database,
                self_hnd: tx.downgrade(),
                parent_hnd: mailbox,
            },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        NewConnectionActorHandle { queue: tx }
    }

    async fn run(mut self) {
        while let Some(cmd) = self.queue.recv().await {
            match cmd {
                NewConnectionCommand::NotifyNewUser(p, s) => {
                    self.state.notify_new_user(p, s).await;
                }
                NewConnectionCommand::HeuristicSolve(h) => {
                    self.state.notify_solve(&h);
                    break;
                }
                NewConnectionCommand::BtnClickAllow(ch, msg, interaction, user) => {
                    self.state.btn_click_allow(ch, msg, interaction, user).await;
                    if self.state.handles.is_empty() {
                        break;
                    }
                }
                NewConnectionCommand::BtnClickDeny(ch, msg, interaction, user) => {
                    self.state.btn_click_deny(ch, msg, interaction, user).await;
                    if self.state.handles.is_empty() {
                        break;
                    }
                }
                NewConnectionCommand::CleanupHandle(user) => {
                    self.state.cleanup_handle(&user);
                    if self.state.handles.is_empty() {
                        break;
                    }
                }
            }
        }

        if let Some(hnd) = self.state.parent_hnd.upgrade() {
            let _ = hnd.send(MailboxCommand::CleanupNewIp(self.state.ip));
        }
    }
}

#[derive(Clone)]
pub struct NewConnectionActorHandle {
    queue: mpsc::UnboundedSender<NewConnectionCommand>,
}

impl NewConnectionActorHandle {
    pub fn notify_new_user(&self, profile: Profile, server: String) {
        notify_actor!(self.queue, NewConnectionCommand::NotifyNewUser(profile, server));
    }

    pub fn heuristic_solve(&self, heuristic: Heuristic) {
        notify_actor!(self.queue, NewConnectionCommand::HeuristicSolve(heuristic));
    }

    pub fn btn_click_allow(
        &self, channel: ChannelId, message: MessageId, interaction: InteractionHolder,
        author: UserId,
    ) {
        notify_actor!(
            self.queue,
            NewConnectionCommand::BtnClickAllow(channel, message, interaction, author)
        );
    }

    pub fn btn_click_deny(
        &self, channel: ChannelId, message: MessageId, interaction: InteractionHolder,
        author: UserId,
    ) {
        notify_actor!(
            self.queue,
            NewConnectionCommand::BtnClickDeny(channel, message, interaction, author)
        );
    }

    pub fn cleanup_handle(&self, username: String) {
        notify_actor!(self.queue, NewConnectionCommand::CleanupHandle(username));
    }
}

pub struct InteractionHolder(pub InteractionId, pub String);

pub enum NewConnectionCommand {
    NotifyNewUser(Profile, String),
    HeuristicSolve(Heuristic),
    BtnClickAllow(ChannelId, MessageId, InteractionHolder, UserId),
    BtnClickDeny(ChannelId, MessageId, InteractionHolder, UserId),

    /* Cleanup Messages */
    CleanupHandle(String),
}
