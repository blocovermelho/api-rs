use serenity::{
    all::{
        Channel, ChannelId, Client, CreateMessage, GuildId, Message, PermissionOverwrite,
        PermissionOverwriteType, PrivateChannel, RoleId, User, UserId,
    },
    async_trait, Error,
};

#[async_trait]
pub trait DiscordAccess: Send + Sync {
    async fn add_member_role(
        &self, guild_id: GuildId, user_id: UserId, role_id: RoleId, reason: Option<&str>,
    ) -> Result<(), Error>;
    async fn remove_member_role(
        &self, guild_id: GuildId, user_id: UserId, role_id: RoleId, reason: Option<&str>,
    ) -> Result<(), Error>;
    async fn get_channel(&self, channel_id: ChannelId) -> Result<Channel, Error>;
    async fn get_user(&self, user_id: UserId) -> Result<User, Error>;
    async fn create_dm_channel(&self, user_id: UserId) -> Result<PrivateChannel, Error>;
    async fn send_message(
        &self, channel_id: ChannelId, message: CreateMessage,
    ) -> Result<Message, Error>;
    async fn create_permission(
        &self, channel_id: ChannelId, permission: PermissionOverwrite,
    ) -> Result<(), Error>;
    async fn remove_permission(
        &self, channel_id: ChannelId, permission: PermissionOverwriteType,
    ) -> Result<(), Error>;
}

#[async_trait]
impl DiscordAccess for Client {
    async fn add_member_role(
        &self, guild_id: GuildId, user_id: UserId, role_id: RoleId, reason: Option<&str>,
    ) -> Result<(), Error> {
        self.http
            .add_member_role(guild_id, user_id, role_id, reason)
            .await
    }

    async fn remove_member_role(
        &self, guild_id: GuildId, user_id: UserId, role_id: RoleId, reason: Option<&str>,
    ) -> Result<(), Error> {
        self.http
            .remove_member_role(guild_id, user_id, role_id, reason)
            .await
    }

    async fn get_channel(&self, channel_id: ChannelId) -> Result<Channel, Error> {
        self.http.get_channel(channel_id).await
    }

    async fn get_user(&self, user_id: UserId) -> Result<User, Error> {
        self.http.get_user(user_id).await
    }

    async fn create_dm_channel(&self, user_id: UserId) -> Result<PrivateChannel, Error> {
        user_id.create_dm_channel(&self.http).await
    }

    async fn send_message(
        &self, channel_id: ChannelId, message: CreateMessage,
    ) -> Result<Message, Error> {
        channel_id.send_message(&self.http, message).await
    }

    async fn create_permission(
        &self, channel_id: ChannelId, permission: PermissionOverwrite,
    ) -> Result<(), Error> {
        channel_id.create_permission(&self.http, permission).await
    }

    async fn remove_permission(
        &self, channel_id: ChannelId, permission: PermissionOverwriteType,
    ) -> Result<(), Error> {
        channel_id.delete_permission(&self.http, permission).await
    }
}

pub struct NoOpAccess;

#[async_trait]
impl DiscordAccess for NoOpAccess {
    async fn add_member_role(
        &self, _guild_id: GuildId, _user_id: UserId, _role_id: RoleId, _reason: Option<&str>,
    ) -> Result<(), Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }

    async fn remove_member_role(
        &self, _guild_id: GuildId, _user_id: UserId, _role_id: RoleId, _reason: Option<&str>,
    ) -> Result<(), Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }

    async fn get_channel(&self, _channel_id: ChannelId) -> Result<Channel, Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }

    async fn get_user(&self, _user_id: UserId) -> Result<User, Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }

    async fn create_dm_channel(&self, _user_id: UserId) -> Result<PrivateChannel, Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }

    async fn send_message(
        &self, _channel_id: ChannelId, _message: CreateMessage,
    ) -> Result<Message, Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }

    async fn create_permission(
        &self, _channel_id: ChannelId, _permission: PermissionOverwrite,
    ) -> Result<(), Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }

    async fn remove_permission(
        &self, _channel_id: ChannelId, _permission: PermissionOverwriteType,
    ) -> Result<(), Error> {
        Err(Error::Other("NoOpAccess does Nothing."))
    }
}
