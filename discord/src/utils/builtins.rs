use poise::{
    builtins::create_application_commands,
    serenity_prelude::{Context, Error, GuildId, Permissions, Ready, UserId},
    Command,
};

pub async fn clear_guild_commands(ctx: &Context, guild_id: GuildId) -> Result<(), Error> {
    guild_id.set_commands(ctx, vec![]).await?;
    Ok(())
}

pub async fn set_guild_commands<U, E>(
    ctx: &Context, ready: &Ready, commands: &[Command<U, E>], guild_id: GuildId, dev_id: UserId,
) -> Result<(), Error> {
    let pre_register = create_application_commands(commands);
    // TODO: Add something like "dev_bot_id" to the config and use it here.
    let cmds = if ready.user.id == dev_id {
        pre_register
            .into_iter()
            .map(|cmd| cmd.default_member_permissions(Permissions::ADMINISTRATOR))
            .collect()
    } else {
        pre_register
    };

    guild_id.set_commands(ctx, cmds).await?;

    Ok(())
}
