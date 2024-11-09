use poise::serenity_prelude::{
    self, async_trait, ComponentInteraction, Context, CreateActionRow, CreateEmbed,
    CreateInteractionResponse, CreateInteractionResponseMessage,
};

pub mod notify;

#[async_trait]
pub trait CompInterExt {
    async fn update_message(
        &self, ctx: &Context, embed: CreateEmbed, components: Vec<CreateActionRow>,
    ) -> Result<(), serenity_prelude::Error>;
}

#[async_trait]
impl CompInterExt for ComponentInteraction {
    async fn update_message(
        &self, ctx: &Context, embed: CreateEmbed, components: Vec<CreateActionRow>,
    ) -> Result<(), serenity_prelude::Error> {
        self.create_response(
            ctx,
            CreateInteractionResponse::UpdateMessage(
                CreateInteractionResponseMessage::new()
                    .embed(embed)
                    .components(components),
            ),
        )
        .await
    }
}
