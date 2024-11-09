use std::sync::Arc;

use db::drivers::sqlite::Sqlite;
use handler::event_handler;
use poise::serenity_prelude::GuildId;

pub mod autocomplete;
pub mod commands;
pub mod handler;
pub mod id;
pub mod render;
#[allow(unused_imports)] mod test;
pub mod utils;

pub struct Data {
    db: Arc<Sqlite>,
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Context<'a> = poise::Context<'a, Data, Error>;
pub type AppContext<'a> = poise::ApplicationContext<'a, Data, Error>;

pub async fn framework(db: Arc<Sqlite>) -> poise::Framework<Data, Error> {
    let options = poise::FrameworkOptions {
        commands: vec![
            commands::change_password::changepw(),
            render::embed::embed_test(),
        ],
        event_handler: |ctx, event, fw, _data| Box::pin(event_handler(ctx, fw, event)),
        on_error: |e| {
            Box::pin(async move {
                let _ = poise::builtins::on_error(e).await;
            })
        },
        ..Default::default()
    };

    poise::Framework::builder()
        .setup(|ctx, _ready, fw| {
            Box::pin(async move {
                poise::builtins::register_in_guild(
                    ctx,
                    &fw.options().commands,
                    GuildId::new(1038487852662661223),
                )
                .await?;

                Ok(Data { db })
            })
        })
        .options(options)
        .build()
}
