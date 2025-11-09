use std::{
    env::{self, var},
    path::PathBuf,
    sync::Arc,
};

use poise::serenity_prelude::{ClientBuilder, GatewayIntents};

use crate::{
    actor::mailbox::MailboxActor,
    db::{data::stub::UserStub, drivers::sqlite::Sqlite, interface::DataSource},
    discord::framework,
};
