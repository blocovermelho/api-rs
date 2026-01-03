/* Discord Actor */

use std::sync::Arc;

use serenity::all::{
    ChannelId, CreateInteractionResponseFollowup, CreateMessage, EditMessage, GuildId,
    InteractionId, Member, Message, MessageId, PartialGuild, RoleId, UserId,
};

use super::prelude::*;

pub struct DiscordA(Arc<serenity::Client>);

impl DiscordA {
    pub async fn send_message(
        &self, channel_id: ChannelId, builder: CreateMessage,
    ) -> Option<Message> {
        self.0
            .http
            .send_message(channel_id, vec![], &builder)
            .await
            .ok()
    }

    pub async fn delete_message(&self, channel_id: ChannelId, message_id: MessageId) {
        self.0
            .http
            .delete_message(channel_id, message_id, None)
            .await
            .ok();
    }

    pub async fn edit_message(
        &self, channel_id: ChannelId, message_id: MessageId, message: EditMessage,
    ) -> Option<Message> {
        let msg = self
            .0
            .http
            .edit_message(channel_id, message_id, &message, vec![])
            .await
            .unwrap();

        Some(msg)
    }

    pub async fn get_dm_channel(&self, user_id: UserId) -> Option<ChannelId> {
        if let Ok(u) = self.0.http.get_user(user_id).await {
            if let Ok(ch) = u.create_dm_channel(&self.0.http).await {
                return Some(ch.id);
            }
            return None;
        }
        None
    }

    pub async fn get_member(&self, user_id: UserId, guild_id: GuildId) -> Option<Member> {
        self.0.http.get_member(guild_id, user_id).await.ok()
    }

    pub async fn get_guild(&self, guild_id: GuildId) -> Option<PartialGuild> {
        self.0.http.get_guild(guild_id).await.ok()
    }

    pub async fn grant_role(&self, user_id: UserId, guild_id: GuildId, role_id: RoleId) {
        if let Ok(m) = self.0.http.get_member(guild_id, user_id).await {
            let _ = m.add_role(&self.0.http, role_id).await;
        }
    }

    pub async fn revoke_role(&self, user_id: UserId, guild_id: GuildId, role_id: RoleId) {
        if let Ok(m) = self.0.http.get_member(guild_id, user_id).await {
            let _ = m.remove_role(&self.0.http, role_id).await;
        }
    }

    pub async fn create_interaction_followup(
        &self, id: InteractionId, token: String, follow_up: CreateInteractionResponseFollowup,
    ) {
        let _ = self
            .0
            .http
            .create_interaction_response(id, &token, &follow_up, vec![])
            .await;
    }
}

pub enum DiscordCommand {
    SendMessage(ChannelId, CreateMessage, RespCell<Option<Message>>),
    DeleteMessage(ChannelId, MessageId),
    EditMessage(ChannelId, MessageId, EditMessage, RespCell<Option<Message>>),
    GetDmChannel(UserId, RespCell<Option<ChannelId>>),
    GetMember(UserId, GuildId, RespCell<Option<Member>>),
    GetGuild(GuildId, RespCell<Option<PartialGuild>>),
    GrantRole(UserId, GuildId, RoleId),
    RevokeRole(UserId, GuildId, RoleId),
    CreateInteractionFollowup(InteractionId, String, CreateInteractionResponseFollowup),
}

pub struct DiscordActor {
    state: DiscordA,
    queue: mpsc::UnboundedReceiver<DiscordCommand>,
}

#[derive(Clone)]
pub struct DiscordActorHandle {
    queue: mpsc::UnboundedSender<DiscordCommand>,
}

impl DiscordActor {
    pub fn spawn(serenity: Arc<serenity::Client>) -> DiscordActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor = Self { state: DiscordA(serenity), queue: rx };
        tokio::spawn(async move { actor.run().await });
        DiscordActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.queue.recv().await {
            match cmd {
                DiscordCommand::SendMessage(ch, msg, res) => {
                    let k = self.state.send_message(ch, msg).await;
                    let _ = res.send(k);
                }
                DiscordCommand::DeleteMessage(ch, msg) => {
                    self.state.delete_message(ch, msg).await;
                }
                DiscordCommand::EditMessage(ch, msgid, msg, res) => {
                    let k = self.state.edit_message(ch, msgid, msg).await;
                    let _ = res.send(k);
                }
                DiscordCommand::GetDmChannel(id, res) => {
                    let k = self.state.get_dm_channel(id).await;
                    let _ = res.send(k);
                }
                DiscordCommand::GetMember(user_id, guild_id, res) => {
                    let k = self.state.get_member(user_id, guild_id).await;
                    let _ = res.send(k);
                }
                DiscordCommand::GetGuild(guild_id, res) => {
                    let k = self.state.get_guild(guild_id).await;
                    let _ = res.send(k);
                }
                DiscordCommand::GrantRole(u, g, r) => {
                    self.state.grant_role(u, g, r).await;
                }
                DiscordCommand::RevokeRole(u, g, r) => {
                    self.state.revoke_role(u, g, r).await;
                }
                DiscordCommand::CreateInteractionFollowup(id, token, followup) => {
                    self.state
                        .create_interaction_followup(id, token, followup)
                        .await;
                }
            }
        }
    }
}

impl DiscordActorHandle {
    pub async fn send_message(
        &self, channel_id: ChannelId, message: CreateMessage,
    ) -> Option<Message> {
        ask_actor!(self.queue, DiscordCommand::SendMessage(channel_id, message));
    }

    pub async fn edit_message(
        &self, channel_id: ChannelId, message_id: MessageId, message: EditMessage,
    ) -> Option<Message> {
        ask_actor!(self.queue, DiscordCommand::EditMessage(channel_id, message_id, message));
    }

    pub fn delete_message(&self, channel_id: ChannelId, message_id: MessageId) {
        notify_actor!(self.queue, DiscordCommand::DeleteMessage(channel_id, message_id));
    }

    pub async fn get_dm_channel(&self, user_id: UserId) -> Option<ChannelId> {
        ask_actor!(self.queue, DiscordCommand::GetDmChannel(user_id));
    }

    pub async fn get_member(&self, user_id: UserId, guild_id: GuildId) -> Option<Member> {
        ask_actor!(self.queue, DiscordCommand::GetMember(user_id, guild_id));
    }

    pub async fn get_guild(&self, guild_id: GuildId) -> Option<PartialGuild> {
        ask_actor!(self.queue, DiscordCommand::GetGuild(guild_id));
    }

    pub fn grant_role(&self, user_id: UserId, guild_id: GuildId, role_id: RoleId) {
        notify_actor!(self.queue, DiscordCommand::GrantRole(user_id, guild_id, role_id));
    }

    pub fn revoke_role(&self, user_id: UserId, guild_id: GuildId, role_id: RoleId) {
        notify_actor!(self.queue, DiscordCommand::RevokeRole(user_id, guild_id, role_id));
    }

    pub fn create_interaction_followup(
        &self, id: InteractionId, token: String, followup: CreateInteractionResponseFollowup,
    ) {
        notify_actor!(self.queue, DiscordCommand::CreateInteractionFollowup(id, token, followup));
    }

    pub fn mock() -> (Self, mpsc::UnboundedReceiver<DiscordCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { queue: tx }, rx)
    }
}
