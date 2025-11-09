use poise::{serenity_prelude::Mentionable, CreateReply, Modal};

use crate::{
    core::utils::generation::ptbr_wordlist,
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
    let mut state = ctx.data.state.lock().await;
    let pass = ptbr_wordlist().generate();
    let embed = embed::one_time_passphrase(&profile, &pass);
    state.tokens.insert(profile.uuid, pass);

    let reply = CreateReply::default().embed(embed).ephemeral(true);

    let _ = ctx.send(reply).await;

    Ok(())
}
