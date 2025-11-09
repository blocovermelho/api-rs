use poise::CreateReply;

use crate::discord::{render::embed, AppContext, Error};

#[poise::command(
    slash_command,
    description_localized(
        "pt-BR",
        "Cria um código para conectar sua conta do discord manualmente à um username."
    )
)]
/// Creates an code to manually link your discord account to an username.
pub async fn link(ctx: AppContext<'_>) -> Result<(), Error> {
    let token = ctx
        .data()
        .mailbox
        .get_discord_manual_link_otp(ctx.author().id)
        .await;

    let _ = ctx
        .send(
            CreateReply::default()
                .embed(embed::link(&token))
                .ephemeral(true),
        )
        .await;

    Ok(())
}
