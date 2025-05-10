use std::sync::Arc;

use db::drivers::sqlite::Sqlite;
use handler::event_handler;
use poise::serenity_prelude::{GuildId, UserId};

pub mod autocomplete;
pub mod commands;
pub mod handler;
pub mod id;
pub mod render;
#[allow(unused_imports)] mod test;
pub mod utils;

pub struct Data {
    db: Arc<Sqlite>,
    info: Arc<ClientInfo>,
}

pub struct ClientInfo {
    /// The developer bot user id
    pub dev_id: UserId,
    /// Production bot user id
    pub prod_id: UserId,
    /// The guild the commands will be registered to
    pub guild_id: GuildId,
}

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Context<'a> = poise::Context<'a, Data, Error>;
pub type AppContext<'a> = poise::ApplicationContext<'a, Data, Error>;

pub async fn framework(db: Arc<Sqlite>, info: ClientInfo) -> poise::Framework<Data, Error> {
    let options = poise::FrameworkOptions {
        commands: vec![
            commands::change_password::changepw(),
            commands::stats::stats(),
	    commands::rank::rank(),
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
        .setup(|ctx, ready, fw| {
            Box::pin(async move {
                utils::builtins::clear_guild_commands(ctx, info.guild_id).await?;
                utils::builtins::set_guild_commands(
                    ctx,
                    ready,
                    &fw.options().commands,
                    info.guild_id,
                    info.dev_id,
                )
                .await?;

                Ok(Data { db, info: Arc::new(info) })
            })
        })
        .options(options)
        .build()
}
