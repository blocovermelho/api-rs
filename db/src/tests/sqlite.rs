use std::{net::Ipv4Addr, time::Duration};

// Unit Tests for the Sqlite Driver.
use test_log::test;
use uuid::Uuid;

use crate::{
    data::{
        result::{NodeDeletion, ServerJoin, ServerLeave},
        stub::{AccountStub, ServerStub, UserStub},
        BanActor, Loc, Pronoun, Server, User, Viewport,
    },
    drivers::{
        err::{
            base::{self, InvalidError},
            DriverError, Response,
        },
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

async fn mock_user(db: &Sqlite, username: &'static str) -> User {
    let stub = UserStub {
        uuid: offline_uuid(username),
        username: username.to_owned(),
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
    db.create_account(AccountStub { uuid, password: "SuperSecretSettings".to_owned() })
        .await
        .unwrap()
}

// CREATE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid,
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

    let user = mock_user(&db, "alikindsys").await;
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
    let user = mock_user(&db, "alikindsys").await;

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
        .create_blacklist(ip, crate::data::BanActor::AutomatedSystem("Database Testing".to_owned()))
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
    let user = mock_user(&db, "alikindsys").await;
    mock_account(&db, user.uuid).await;

    let res = db.create_allowlist(&user.uuid, ip).await.unwrap();

    assert_eq!(res.uuid, user.uuid);
    assert_eq!(res.get_addr(), ip);
    assert_eq!(res.hits, 1);
    assert_eq!(res.mask, 32);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn create_migration(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let server = mock_server(&db).await;
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;

    // Creates a valid savedata for a server, linking an user to a server.
    // Without this no migrations can be done. You can't migrate from an empty account.
    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();

    let migration = db
        .create_migration(old.username.clone(), new.username.clone(), old.current_migration)
        .await
        .unwrap();

    assert_eq!(migration.old, old.username);
    assert_eq!(migration.new, new.username);
    assert_eq!(migration.affected_servers.0, vec![server.uuid]);
    assert_eq!(migration.finished_servers.0, vec![]);
    assert_eq!(migration.visible.0, false);
    assert_eq!(migration.finished_at, None);

    Ok(())
}

// READ
#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_user_by_uuid(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid,
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    db.create_user(stub.clone()).await.unwrap();
    let save = db.get_user_by_uuid(&uuid).await.unwrap();

    assert_eq!(stub, save);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_user_by_name(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_user(&db, "alikindsys").await;
    let test = db.get_user_by_name("alikindsys".to_string()).await.unwrap();

    assert_eq!(user.uuid, test.uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_all_users(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    mock_user(&db, "alikindsys").await;
    mock_user(&db, "CinderAesthethic").await;
    mock_user(&db, "SofiAzeda").await;

    let users = db.get_all_users().await.unwrap();
    assert_eq!(users.len(), 3);
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
async fn get_all_servers(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    mock_server(&db).await;

    let servers = db.get_all_servers().await.unwrap();
    assert_eq!(servers.len(), 1);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_viewport(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    let viewport = db.get_viewport(&user.uuid, &server.uuid).await.unwrap();

    assert_eq!(viewport, Viewport::default());

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_playtime(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    let playtime = db.get_playtime(&user.uuid, &server.uuid).await.unwrap();

    assert_eq!(playtime, std::time::Duration::ZERO);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_account(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db, "alikindsys").await;
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
async fn get_all_accounts(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let alikind = mock_user(&db, "alikindsys").await;
    let sofia = mock_user(&db, "SofiAzeda").await;

    mock_account(&db, alikind.uuid).await;
    mock_account(&db, sofia.uuid).await;

    let accounts = db.get_all_accounts().await.unwrap();

    assert_eq!(accounts.len(), 2);
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

    let user = mock_user(&db, "alikindsys").await;
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

    let user = mock_user(&db, "alikindsys").await;
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

    let user = mock_user(&db, "alikindsys").await;
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

#[test(sqlx::test(migrations = "src/migrations"))]
async fn get_migration(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let server = mock_server(&db).await;
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;

    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();

    let migration = db
        .create_migration(old.username.clone(), new.username.clone(), old.current_migration)
        .await
        .unwrap();

    let test = db.get_migration(&migration.id).await.unwrap();

    assert_eq!(test.id, migration.id);
    assert_eq!(test.old, migration.old);
    assert_eq!(test.new, migration.new);
    assert_eq!(test.new, new.username);
    assert_eq!(test.old, old.username);

    Ok(())
}

// UPDATE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn migrate_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let old_uuid = offline_uuid("roridev");
    let new_uuid = offline_uuid("alikindsys");
    let db = get_wrapper(pool).await.unwrap();

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
        uuid,
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun {
        pronoun: "ela/dela".to_owned(),
        color: "#F5A9B8".to_owned(),
    };

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
        uuid,
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun {
        pronoun: "ela/dela".to_owned(),
        color: "#F5A9B8".to_owned(),
    };

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
        uuid,
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
    };

    let pronoun = Pronoun {
        pronoun: "ela/dela".to_owned(),
        color: "#F5A9B8".to_owned(),
    };
    let update = Pronoun {
        pronoun: "ela/dela".to_owned(),
        color: "#5BCEFA".to_owned(),
    };

    db.create_user(stub.clone()).await.unwrap();
    db.add_pronoun(&uuid, pronoun.clone()).await.unwrap();

    let pronouns = db
        .update_pronoun(&uuid, &pronoun, update.clone())
        .await
        .unwrap();

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
async fn update_server_status(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    // Setup
    let server = mock_server(&db).await;
    let old = server.online.0;
    // Action
    let new = db.update_server_status(&server.uuid, !old).await.unwrap();
    let new_server = db.get_server(&server.uuid).await.unwrap();
    let check = new_server.online.0;
    // Test
    assert_eq!(check, new);
    assert_ne!(new, old);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_viewport(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_user(&db, "alikindsys").await;
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

    let user = mock_user(&db, "alikindsys").await;
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
    let user = mock_user(&db, "alikindsys").await;

    db.create_account(AccountStub { uuid: user.uuid, password: "oldpass".to_owned() })
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
async fn update_current_join(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    // Setup
    let user = mock_user(&db, "alikindsys").await;
    mock_account(&db, user.uuid).await;
    let account = db.get_account(&user.uuid).await.unwrap();

    // Action
    let old = account.current_join;
    db.update_current_join(&user.uuid).await.unwrap();

    let new_acc = db.get_account(&user.uuid).await.unwrap();
    let new = new_acc.current_join;

    // Test
    assert!(new > old);
    assert_ne!(new, old);
    assert_eq!(account.uuid, new_acc.uuid);

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
    let user = mock_user(&db, "alikindsys").await;
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
    let user = mock_user(&db, "alikindsys").await;
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

#[test(sqlx::test(migrations = "src/migrations"))]
async fn add_completed_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();
    let migration = db
        .create_migration(old.username, new.username, old.current_migration)
        .await
        .unwrap();

    assert_eq!(migration.finished_servers.len(), 0);

    let update = db
        .add_completed_server(&migration.id, &server.uuid)
        .await
        .unwrap();

    assert_eq!(update, vec![server.uuid]);

    // Try to update an already migrated server

    let err = db.add_completed_server(&migration.id, &server.uuid).await;

    assert!(matches!(
        err,
        Err(DriverError::InvalidInput(InvalidError::AlreadyMigrated))
    ));
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn set_current_migration(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();
    let migration = db
        .create_migration(old.username, new.username, old.current_migration)
        .await
        .unwrap();

    assert_eq!(new.current_migration, None);

    let update = db
        .set_current_migration(&new.uuid, Some(migration.id))
        .await
        .unwrap();

    let new_user = db.get_user_by_uuid(&new.uuid).await.unwrap();

    assert_eq!(new_user.current_migration, update);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_completion(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();
    let migration = db
        .create_migration(old.username, new.username, old.current_migration)
        .await
        .unwrap();

    assert_eq!(migration.finished_at, None);

    let change = db.update_completion(&migration.id).await.unwrap();

    let test = db.get_migration(&migration.id).await.unwrap();

    assert_ne!(test.finished_at, None);

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn update_visibility(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();
    let migration = db
        .create_migration(old.username, new.username, old.current_migration)
        .await
        .unwrap();

    assert_eq!(migration.visible.0, false);

    let change = db.update_visibility(&migration.id, true).await.unwrap();

    assert_eq!(change, true);

    let test = db.get_migration(&migration.id).await.unwrap();

    assert_eq!(test.visible.0, change);
    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn rebase_migration(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();
    let migration = db
        .create_migration(old.username, new.username, old.current_migration)
        .await
        .unwrap();

    assert_eq!(migration.parent, None);

    // This is a random uuid thats an invalid migration
    // Its fine for the test since there is no checks if the id is valid or not
    let new_id = Uuid::new_v4();

    let change = db
        .rebase_migration(&migration.id, Some(new_id))
        .await
        .unwrap();

    assert_eq!(change.parent, Some(new_id));

    // Reseting test

    let reset = db.rebase_migration(&migration.id, None).await.unwrap();

    assert_eq!(reset.parent, None);

    Ok(())
}

// DELETE

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_user(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let uuid = Uuid::new_v4();
    let db = get_wrapper(pool).await.unwrap();

    let stub = UserStub {
        uuid,
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

    let user = mock_user(&db, "alikindsys").await;

    db.create_account(AccountStub { uuid: user.uuid, password: "oldpass".to_owned() })
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

    let user = mock_user(&db, "alikindsys").await;
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

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_savedatas(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    let _ = db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

    let savedatas = db.get_savedatas(&user.uuid).await.unwrap();

    let deleted = db.delete_savedatas(&user.uuid).await.unwrap();

    assert_eq!(savedatas.len(), deleted.len());

    let test = db.get_savedatas(&user.uuid).await.unwrap();

    assert!(test.is_empty());

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_migration_simple(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let old = mock_user(&db, "roridev").await;
    let new = mock_user(&db, "alikindsys").await;
    let server = mock_server(&db).await;

    let _ = db.create_savedata(&old.uuid, &server.uuid).await.unwrap();
    let migration = db
        .create_migration(old.username, new.username, old.current_migration)
        .await
        .unwrap();

    let delete = db.delete_migration(&migration.id).await;

    // The delete is sucessful
    assert!(matches!(delete, Ok(NodeDeletion::First { is_orphan: true })));

    let error = db.get_migration(&migration.id).await;

    // Migration was deleted.
    assert!(matches!(
        error,
        Err(DriverError::DatabaseError(crate::drivers::err::base::NotFoundError::Migration(
            _
        )))
    ));

    Ok(())
}

#[test(sqlx::test(migrations = "src/migrations"))]
async fn delete_migration_complex(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    // Try checking the rebasing feature of migrations
    let db = get_wrapper(pool).await.unwrap();

    let a = mock_user(&db, "roridev").await;
    let b = mock_user(&db, "alikindsys").await;
    let c = mock_user(&db, "alikind").await;

    let server = mock_server(&db).await;

    let _ = db.create_savedata(&a.uuid, &server.uuid).await.unwrap();
    let _ = db.create_savedata(&b.uuid, &server.uuid).await.unwrap();

    let first = db
        .create_migration(a.username, b.username.clone(), None)
        .await
        .unwrap();

    let second = db
        .create_migration(b.username, c.username, Some(first.id))
        .await
        .unwrap();

    // We now will delete the first migration.
    let delete = db.delete_migration(&first.id).await;

    // It should be successful
    assert!(matches!(delete, Ok(NodeDeletion::First { is_orphan: false })));

    // It should also cause the second's parent to be set to it's parent. In this case "None".
    let update = db.get_migration(&second.id).await.unwrap();

    // This should be changed.
    assert_ne!(update.parent, second.parent);
    // And it should be changed to the first's parent.
    assert_eq!(update.parent, first.parent);

    // Now getting the first migration should fail.
    let error = db.get_migration(&first.id).await;

    // Migration was deleted.
    assert!(matches!(
        error,
        Err(DriverError::DatabaseError(crate::drivers::err::base::NotFoundError::Migration(
            _
        )))
    ));

    Ok(())
}
