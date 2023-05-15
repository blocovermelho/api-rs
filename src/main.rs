mod entities;
mod migrator;

use futures::executor::block_on;
use migrator::Migrator;
use sea_orm::*;
use sea_orm_migration::prelude::*;

use entities::{prelude::*, session::*, *};

const DB_URL: &str = "sqlite:./database.db";

async fn run() -> Result<(), DbErr> {
    let db = Database::connect(DB_URL).await?;
    Migrator::refresh(&db).await?;

    let alice_session = session::ActiveModel {
        player: ActiveValue::Set("e4a218c8-7043-4dc6-b561-4ca013a73c69".to_owned()),
        pos: ActiveValue::Set(WorldPos {
            pos: BlockPos {
                x: 120,
                y: 64,
                z: 120,
            },
            dim: "minecraft:overworld".to_owned(),
        }),
        looking_at: ActiveValue::Set(LookVector {
            yaw: "180.00".to_string(),
            pitch: "90.00".to_string(),
        }),
        ip_addr: ActiveValue::Set("192.168.0.102".to_owned()),
        server: ActiveValue::Set("whatever".to_owned()),
        expires_at: ActiveValue::Set("Dia de são nunca".to_owned()),
    };

    Session::insert(alice_session).exec(&db).await?;

    Ok(())
}

fn main() {
    if let Err(err) = block_on(run()) {
        panic!("{}", err);
    }

    println!("Hello, world!");
}
