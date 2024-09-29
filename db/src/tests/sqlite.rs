use std::{net::Ipv4Addr, time::Duration};

// Unit Tests for the Sqlite Driver.
use test_log::test;
use uuid::Uuid;

use crate::{
    data::{
        result::{ServerJoin, ServerLeave},
        stub::{AccountStub, ServerStub, UserStub},
        BanActor, Loc, Pronoun, Server, User, Viewport,
    },
    drivers::{
        err::{DriverError, Response},
        sqlite::Sqlite,
    },
    interface::{DataSource, NetworkProvider},
};

async fn get_wrapper(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<Sqlite> {
    Ok(pool.into())
}

fn offline_uuid(name: &'static str) -> Uuid {
    let string = "OfflinePlayer:".to_owned() + name;
    let mut hash = md5::compute(string).0;

    hash[6] = hash[6] & 0x0f | 0x30; // uuid version 3
    hash[8] = hash[8] & 0x3f | 0x80; // RFC4122 variant

    Uuid::from_bytes(hash)
}

async fn mock_user(db: &Sqlite) -> User {
    let stub = UserStub {
        uuid: Uuid::new_v4(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    db.create_user(stub.clone()).await.unwrap()
}

async fn mock_server(db: &Sqlite) -> Server {
    let stub = ServerStub {
        name: "Servidor de Teste".to_owned(),
        supported_versions: vec!["1.21.0".to_owned()],
        current_modpack: None,
    };

    db.create_server(stub).await.unwrap()
}

async fn mock_account(db: &Sqlite, uuid: uuid::Uuid) {
    db.create_account(AccountStub {
        uuid,
        password: "SuperSecretSettings".to_owned(),
    })
    .await
    .unwrap()
}

// CREATE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let save = db.create_user(stub.clone()).await.unwrap();

    assert_eq!(stub, save);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let stub = ServerStub {
        name: "Servidor de Teste".to_owned(),
        supported_versions: vec!["1.21.0".to_owned()],
        current_modpack: None,
    };

    let db = get_wrapper(pool).await.unwrap();

    let save = db.create_server(stub.clone()).await.unwrap();

    assert_eq!(stub, save);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_savedata(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    let server = mock_server(&db).await;

    let savedata = db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    assert_eq!(savedata.server_uuid, server.uuid);
    assert_eq!(savedata.player_uuid, user.uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_account(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    // We first need to create an user, in order to satisfy the foreign key constraint.
    let user = mock_user(&db).await;

    // Creating an account with the same uuid should now work.
    let stub = AccountStub {
        uuid: user.uuid,
        password: "TotallyMyPassword123".to_owned(),
    };

    let save = db.create_account(stub).await.unwrap();
    assert_eq!(save, ());
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_blacklist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let res = db
        .create_blacklist(
            ip,
            crate::data::BanActor::AutomatedSystem("Database Testing".to_owned()),
        )
        .await
        .unwrap();

    assert_eq!(res.get_addr(), ip);
    assert_eq!(res.hits, 1);
    assert_eq!(res.mask, 32);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_allowlist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let ip = Ipv4Addr::new(127, 0, 0, 1);

    // Allowlists are only created when an account exists.
    // But an account can only exist if an user exists.
    let user = mock_user(&db).await;
    mock_account(&db, user.uuid).await;

    let res = db.create_allowlist(&user.uuid, ip).await.unwrap();

    assert_eq!(res.uuid, user.uuid);
    assert_eq!(res.get_addr(), ip);
    assert_eq!(res.hits, 1);
    assert_eq!(res.mask, 32);
    Ok(())
}

// READ
#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_user_by_uuid(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    db.create_user(stub.clone()).await.unwrap();
    let save = db.get_user_by_uuid(&uuid).await.unwrap();

    assert_eq!(stub, save);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_users_by_discord_id(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let discord_id = "-Discord ID-".to_owned();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: Uuid::new_v4(),
        username: "alikindsys".to_owned(),
        discord_id: discord_id.clone(),
    };

    let stub2 = UserStub {
        uuid: Uuid::new_v4(),
        username: "another_user".to_owned(),
        discord_id: discord_id.clone(),
    };


    db.create_user(stub).await.unwrap();
    db.create_user(stub2).await.unwrap();
    let save = db.get_users_by_discord_id(discord_id).await.unwrap();

    assert_eq!(save.len(), 2);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_server_by_uuid(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let stub = ServerStub {
        name: "Servidor de Teste".to_owned(),
        supported_versions: vec!["1.21.0".to_owned()],
        current_modpack: None,
    };

    let db = get_wrapper(pool).await.unwrap();

    let save = db.create_server(stub.clone()).await.unwrap();
    let read = db.get_server(&save.uuid).await.unwrap();

    assert_eq!(save, read);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_server_by_name(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let stub = ServerStub {
        name: "Servidor de Teste".to_owned(),
        supported_versions: vec!["1.21.0".to_owned()],
        current_modpack: None,
    };

    let db = get_wrapper(pool).await.unwrap();

    let save = db.create_server(stub.clone()).await.unwrap();
    let read = db.get_server_by_name(stub.name).await.unwrap();

    assert_eq!(save, read);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_viewport(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    let server = mock_server(&db).await;

    db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    let viewport = db.get_viewport(&user.uuid, &server.uuid).await.unwrap();

    assert_eq!(viewport, Viewport::default());

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_playtime(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    let server = mock_server(&db).await;

    db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    let playtime = db.get_playtime(&user.uuid, &server.uuid).await.unwrap();

    assert_eq!(playtime, std::time::Duration::ZERO);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_account(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    db.create_account(AccountStub {
        uuid: user.uuid,
        password: "TotallyMyPassword123".to_owned(),
    })
    .await
    .unwrap();

    let acc = db.get_account(&user.uuid).await.unwrap();

    assert_eq!(acc.password, "TotallyMyPassword123".to_owned());
    assert_eq!(acc.uuid, user.uuid);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_blacklists(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let actor = BanActor::AutomatedSystem("Database Testing".to_owned());
    db.create_blacklist(Ipv4Addr::new(127, 0, 0, 1), actor)
        .await
        .unwrap();
    let read = db
        .get_blacklists(Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    // There should be one result, which matches the query perfectly.
    assert_eq!(read.len(), 1);
    // And the lone entry should have 127.0.0.1 as the IP address
    assert_eq!(read.get(0).unwrap().get_addr(), Ipv4Addr::new(127, 0, 0, 1));
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_blacklists_with_range(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let actor = BanActor::AutomatedSystem("Database Testing".to_owned());

    db.create_blacklist(Ipv4Addr::new(127, 0, 0, 1), actor.clone())
        .await
        .unwrap();

    // This would match with *literally* anything smaller then /31.
    db.create_blacklist(Ipv4Addr::new(127, 0, 0, 2), actor)
        .await
        .unwrap();

    let read = db
        .get_blacklists_with_range(Ipv4Addr::new(127, 0, 0, 1), 30)
        .await
        .unwrap();

    // Should match both of them.
    assert_eq!(read.len(), 2);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_allowlists(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    mock_account(&db, user.uuid).await;
    db.create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.get(0).unwrap().uuid, user.uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_allowlists_with_ip(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    mock_account(&db, user.uuid).await;
    db.create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    let read = db
        .get_allowlists_with_ip(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.get(0).unwrap().uuid, user.uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_allowlists_with_range(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    mock_account(&db, user.uuid).await;
    db.create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    db.create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 2))
        .await
        .unwrap();

    let read = db
        .get_allowlists_with_range(&user.uuid, Ipv4Addr::new(127, 0, 0, 1), 30)
        .await
        .unwrap();

    assert_eq!(read.len(), 2);
    assert_eq!(read.get(0).unwrap().uuid, user.uuid);
    assert_eq!(read.get(1).unwrap().uuid, user.uuid);

    Ok(())
}

// UPDATE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn migrate_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let old_uuid = offline_uuid("roridev");
    let new_uuid = offline_uuid("alikindsys");
    let db = get_wrapper(pool).await.unwrap();

    let old_stub = UserStub { uuid: old_uuid, username: "roridev".to_owned(), discord_id: "-Discord ID-".to_owned() };
    let new_stub = UserStub { uuid: new_uuid, username: "alikindsys".to_owned(), discord_id: "-Discord ID-".to_owned() };

    let old = db.create_user(old_stub).await.unwrap();
    db.create_user(new_stub).await.unwrap();
    let migrated = db.migrate_user(&old_uuid, &new_uuid).await.unwrap();

    assert_eq!(migrated.created_at, old.created_at);
    assert_eq!(migrated.uuid, new_uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn add_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun { pronoun: "ela/dela".to_owned(), color: "#F5A9B8".to_owned() };

    db.create_user(stub.clone()).await.unwrap();
    let pronouns = db.add_pronoun(&uuid, pronoun).await.unwrap();

    assert_eq!(pronouns.len(), 1);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn remove_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun { pronoun: "ela/dela".to_owned(), color: "#F5A9B8".to_owned() };

    db.create_user(stub.clone()).await.unwrap();
    db.add_pronoun(&uuid, pronoun.clone()).await.unwrap();

    let pronouns = db.remove_pronoun(&uuid, pronoun).await.unwrap();

    assert_eq!(pronouns.len(), 0);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun { pronoun: "ela/dela".to_owned(), color: "#F5A9B8".to_owned() };
    let update = Pronoun { pronoun: "ela/dela".to_owned(), color: "#5BCEFA".to_owned()};

    db.create_user(stub.clone()).await.unwrap();
    db.add_pronoun(&uuid, pronoun.clone()).await.unwrap();

    let pronouns = db.update_pronoun(&uuid, &pronoun, update.clone()).await.unwrap();

    assert_eq!(pronouns.get(0).unwrap().color, update.color);
    assert_eq!(pronouns.len(), 1);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn join_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    // This is moderately annoying since we have to create both an user and a server.
    let user_stub = UserStub {
        uuid: Uuid::new_v4(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let server_stub = ServerStub {
        name: "Servidor de Teste".to_owned(),
        supported_versions: vec!["1.21.0".to_owned()],
        current_modpack: None,
    };

    let db = get_wrapper(pool).await.unwrap();

    let user = db.create_user(user_stub).await.unwrap();
    let server = db.create_server(server_stub).await.unwrap();

    let res = db.join_server(&server.uuid, &user.uuid).await.unwrap();
    let new_server = db.get_server(&server.uuid).await.unwrap();

    assert!(matches!(res, ServerJoin::FirstJoin));
    assert!(new_server.players.contains(&user.uuid));

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn leave_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    // This is moderately annoying since we have to create both an user and a server.
    let user_stub = UserStub {
        uuid: Uuid::new_v4(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let server_stub = ServerStub {
        name: "Servidor de Teste".to_owned(),
        supported_versions: vec!["1.21.0".to_owned()],
        current_modpack: None,
    };

    let db = get_wrapper(pool).await.unwrap();

    let user = db.create_user(user_stub).await.unwrap();
    let server = db.create_server(server_stub).await.unwrap();

    db.join_server(&server.uuid, &user.uuid).await.unwrap();
    let res = db.leave_server(&server.uuid, &user.uuid).await.unwrap();
    let new_server = db.get_server(&server.uuid).await.unwrap();

    assert!(matches!(res, ServerLeave::Accepted));
    assert!(!new_server.players.contains(&user.uuid));

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_viewport(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    let server = mock_server(&db).await;

    db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    let viewport = Viewport {
        loc: Loc {
            dim: "minecraft:overworld".to_owned(),
            x: 69.0,
            y: 69.0,
            z: 69.0,
        },
        yaw: 69.0,
        pitch: 69.0,
    };

    let save = db
        .update_viewport(&user.uuid, &server.uuid, viewport.clone())
        .await
        .unwrap();

    assert_eq!(save, viewport);
    assert_ne!(save, Viewport::default());

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_playtime(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    let server = mock_server(&db).await;

    db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    db.update_playtime(&user.uuid, &server.uuid, Duration::from_secs_f32(69.0))
        .await
        .unwrap();

    let save = db.get_playtime(&user.uuid, &server.uuid).await.unwrap();

    assert_ne!(save, Duration::ZERO);
    assert_eq!(save, Duration::from_secs_f32(69.0));

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_password(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_user(&db).await;

    db.create_account(AccountStub {
        uuid: user.uuid,
        password: "oldpass".to_owned(),
    })
    .await
    .unwrap();

    db.update_password(&user.uuid, "newpass".to_owned())
        .await
        .unwrap();

    let acc = db.get_account(&user.uuid).await.unwrap();

    assert_eq!(acc.password, "newpass".to_owned());

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn migrate_account(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let old_uuid = offline_uuid("roridev");
    let new_uuid = offline_uuid("alikindsys");

    let old_stub = UserStub {
        uuid: old_uuid,
        username: "roridev".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };
    let new_stub = UserStub {
        uuid: new_uuid,
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    db.create_user(old_stub).await.unwrap();
    db.create_user(new_stub).await.unwrap();

    db.create_account(AccountStub {
        uuid: old_uuid,
        password: "SuperSecurePassword".to_owned(),
    })
    .await
    .unwrap();

    db.migrate_account(&old_uuid, &new_uuid).await.unwrap();

    let old_acc = db.get_account(&old_uuid).await.unwrap_err();
    let new_acc = db.get_account(&new_uuid).await.unwrap();

    // The "old" account shouldn't be accessible.
    assert!(matches!(
        old_acc,
        DriverError::DatabaseError(crate::drivers::err::base::NotFoundError::Account(_))
    ));

    // The migrated account should match the new uuid and have the same password as before.
    assert_eq!(new_acc.uuid, new_uuid);
    assert_eq!(new_acc.password, "SuperSecurePassword".to_owned());

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn bump_blacklist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let entry = db
        .create_blacklist(
            Ipv4Addr::new(127, 0, 0, 1),
            BanActor::AutomatedSystem("Database Testing".to_owned()),
        )
        .await
        .unwrap();

    db.bump_blacklist(entry).await.unwrap();

    let read = db
        .get_blacklists(Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    assert_eq!(read.get(0).unwrap().hits, 2);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn broaden_blacklist_mask(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let entry = db
        .create_blacklist(
            Ipv4Addr::new(127, 0, 0, 1),
            BanActor::AutomatedSystem("Database Testing".to_owned()),
        )
        .await
        .unwrap();

    db.broaden_blacklist_mask(entry, 16).await.unwrap();

    let read = db
        .get_blacklists(Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    assert_eq!(read.get(0).unwrap().mask, 16);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn bump_allowlist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_user(&db).await;
    mock_account(&db, user.uuid).await;
    let entry = db
        .create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    db.bump_allowlist(entry).await.unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.get(0).unwrap().hits, 2);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn broaden_allowlist_mask(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_user(&db).await;
    mock_account(&db, user.uuid).await;
    let entry = db
        .create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    db.broaden_allowlist_mask(entry, 16).await.unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.get(0).unwrap().mask, 16);

    Ok(())
}

// DELETE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid: uuid.clone(),
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    db.create_user(stub.clone()).await.unwrap();
    let save = db.delete_user(&uuid).await.unwrap();

    assert_eq!(stub, save);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let stub = ServerStub {
        name: "Servidor de Teste".to_owned(),
        supported_versions: vec!["1.21.0".to_owned()],
        current_modpack: None,
    };

    let db = get_wrapper(pool).await.unwrap();

    let save = db.create_server(stub.clone()).await.unwrap();
    let read = db.delete_server(&save.uuid).await.unwrap();

    assert_eq!(stub, save);
    assert_eq!(save, read);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_account(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;

    db.create_account(AccountStub {
        uuid: user.uuid,
        password: "oldpass".to_owned(),
    })
    .await
    .unwrap();

    let res = db.delete_account(&user.uuid).await.unwrap();
    let read = db.get_account(&user.uuid).await.unwrap_err();

    assert_eq!(res, ());
    assert!(matches!(
        read,
        DriverError::DatabaseError(crate::drivers::err::base::NotFoundError::Account(_))
    ));

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_blacklist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let entry = db
        .create_blacklist(
            Ipv4Addr::new(127, 0, 0, 1),
            BanActor::AutomatedSystem("Database Testing".to_owned()),
        )
        .await
        .unwrap();

    db.delete_blacklist(entry).await.unwrap();

    let read = db
        .get_blacklists(Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    assert_eq!(read.len(), 0);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_allowlist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db).await;
    mock_account(&db, user.uuid).await;
    let entry = db
        .create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    db.delete_allowlist(entry).await.unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 0);

    Ok(())
}
