use poise::CreateReply;

use crate::{
    db::interface::DataSource,
    discord::{render::embed, AppContext, Error},
};

/// Create an One-Time Passphrase for joining the server with.
#[poise::command(
    slash_command,
    name_localized("pt-BR", "otp"),
    description_localized("pt-BR", "Cria uma senha de uso único para entrar no servidor.")
)]
pub async fn otp(
    ctx: AppContext<'_>,
    #[description = "O username da conta do Minecraft"]
    #[autocomplete = "crate::discord::autocomplete::username"]
    username: String,
) -> Result<(), Error> {
    let db = ctx.data.db.clone();
    let profile = db.get_profile(username).await?;

    let pass = ctx.data.mailbox.get_profile_otp(profile.uuid).await;
    let embed = embed::one_time_passphrase(&profile, &pass);

    let reply = CreateReply::default().embed(embed).ephemeral(true);

    let _ = ctx.send(reply).await;

    Ok(())
}
