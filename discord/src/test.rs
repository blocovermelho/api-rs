use std::{
    env::{self, var},
    path::PathBuf,
    sync::Arc,
};

use db::{data::stub::UserStub, drivers::sqlite::Sqlite, interface::DataSource};
use poise::serenity_prelude::{ClientBuilder, GatewayIntents};

use crate::framework;

#[tokio::test]
pub async fn run_bot() {
    let db_path = PathBuf::from("migrated.db");

    let db: Arc<Sqlite> = Arc::new(Sqlite::new(&db_path).await);
    db.run_migrations().await;

    let fw = framework(db).await;
    let token = env::var("DISCORD_BOT_TOKEN").unwrap();
    let intents = GatewayIntents::non_privileged() | GatewayIntents::MESSAGE_CONTENT;

    let client = ClientBuilder::new(token, intents).framework(fw).await;

    client.unwrap().start().await.unwrap();
}
