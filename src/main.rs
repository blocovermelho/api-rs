mod entities;
mod migrator;
mod types;

use futures::executor::block_on;
use migrator::Migrator;
use sea_orm::*;
use sea_orm_migration::prelude::*;

use entities::{prelude::*, session::*, *};

const DB_URL: &str = "sqlite:./database.db";

async fn run() -> Result<(), DbErr> {
    let db = Database::connect(DB_URL).await?;
    Migrator::refresh(&db).await?;
    Ok(())
}

fn main() {
    if let Err(err) = block_on(run()) {
        panic!("{}", err);
    }

    println!("Hello, world!");
}
