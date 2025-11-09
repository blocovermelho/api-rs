use std::{net::Ipv4Addr, time::Duration};

use chrono::Utc;
use sqlx::types::Json;
// Unit Tests for the Sqlite Driver.
use test_log::test;
use uuid::Uuid;

use crate::{
    core::types::{
        enums::ConnectionData,
        structs::{
            stub::{GameServerStub, ProfileStub},
            GameServer,
        },
    },
    db::{
        data::{
            result::{NodeDeletion, ServerJoin, ServerLeave},
            stub::{AccountStub, ServerStub, UserStub},
            Account, BanActor, Loc, Profile, Pronoun, SaveData, Server, ServerV2, User, Viewport,
        },
        drivers::{
            err::{
                base::{self, InvalidError},
                DriverError, Response,
            },
            json::data::{Modpack, ModpackSource},
            sqlite::Sqlite,
        },
        interface::{DataSource, NetworkProvider},
    },
};

async fn get_wrapper(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<Sqlite> {
    Ok(pool.into())
}

async fn v1_mock_user(db: &Sqlite, username: &'static str) -> User {
    sqlx::query_as::<_,User>("INSERT INTO users (uuid, username, discord_id, created_at, pronouns, last_server) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *")
        .bind(Uuid::new_v4())
        .bind(username)
        .bind("-Discord ID-")
        .bind(Utc::now())
        .bind("[]")
        .bind(None::<Uuid>)
        .fetch_one(&db.0)
        .await.unwrap()
}

async fn v1_mock_account(db: &Sqlite, uuid: &Uuid) -> Account {
    sqlx::query_as::<_, Account>(
        "INSERT INTO accounts (uuid, password, current_join) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(uuid)
    .bind("password")
    .bind(Utc::now())
    .fetch_one(&db.0)
    .await
    .unwrap()
}

async fn v1_mock_server(db: &Sqlite) -> Server {
    let modpack = Modpack {
        name: "Teste".to_string(),
        source: ModpackSource::Modrinth,
        version: "0.0.1".to_string(),
        uri: "example.org".to_string(),
    };
    sqlx::query_as::<_, Server>(
        "INSERT INTO servers (uuid, name, supported_versions, current_modpack, online, players) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
    )
    .bind(Uuid::now_v7())
    .bind("Servidor de Testes - V1")
    .bind("[]")
    .bind(Json(modpack))
    .bind(Json(true))
    .bind("[]")
    .fetch_one(&db.0)
    .await.unwrap()
}

async fn v1_mock_savedata(db: &Sqlite, server: &Uuid, player: &Uuid) -> SaveData {
    sqlx::query_as::<_, SaveData>(
        "INSERT INTO savedata (server_uuid, player_uuid, playtime, viewport) VALUES ($1, $2, $3, $4) RETURNING *",
     )
     .bind(server)
     .bind(player)
     .bind(Json(Duration::ZERO))
     .bind(Json(Viewport::default()))
     .fetch_one(&db.0)
     .await
     .unwrap()
}

async fn mock_profile(db: &Sqlite, username: &'static str) -> Profile {
    let stub = ProfileStub {
        username: username.into(),
        discord_id: "-Discord ID-".into(),
        password: "password".into(),
    };

    db.create_profile(stub, None).await.unwrap()
}

async fn mock_server(db: &Sqlite) -> ServerV2 {
    let stub = GameServerStub {
        name: "Servidor de Teste".to_owned(),
        versions: vec!["1.21.0".to_owned()],
        staff: vec![],
        max_players: 32,
        game: "Minecraft".into(),
    };

    db.create_server(stub).await.unwrap()
}

// CREATE

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn create_profile(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let stub = ProfileStub {
        username: "alikindsys".to_owned(),
        discord_id: "-Discord ID-".to_owned(),
        password: "password".into(),
    };

    let save = db.create_profile(stub.clone(), None).await.unwrap();

    // assert_eq!(stub, save);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn create_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let stub = GameServerStub {
        name: "Servidor de Teste".to_owned(),
        versions: vec!["1.21.0".to_owned()],
        staff: vec![],
        max_players: 32,
        game: "Minecraft".into(),
    };

    let db = get_wrapper(pool).await.unwrap();

    let save = db.create_server(stub.clone()).await.unwrap();

    let gs = GameServer::from(save);

    assert_eq!(gs, stub);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn create_blacklist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let ip = Ipv4Addr::new(127, 0, 0, 1);
    let res = db
        .create_blacklist(
            ip,
            crate::db::data::BanActor::AutomatedSystem("Database Testing".to_owned()),
        )
        .await
        .unwrap();

    assert_eq!(res.get_addr(), ip);
    assert_eq!(res.hits, 1);
    assert_eq!(res.mask, 32);
    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn create_allowlist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let ip = Ipv4Addr::new(127, 0, 0, 1);

    // Allowlists are only created when an account exists.
    // But an account can only exist if an user exists.
    let user = mock_profile(&db, "alikindsys").await;

    let res = db.create_allowlist(&user.uuid, ip).await.unwrap();

    assert_eq!(res.uuid, user.uuid);
    assert_eq!(res.get_addr(), ip);
    assert_eq!(res.hits, 1);
    assert_eq!(res.mask, 32);
    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn create_token(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let server = mock_server(&db).await;
    let scopes = vec![
        "profiles.read".to_string(),
        "servers.self.modify".to_string(),
    ];

    let token = db.create_token(&server.uuid, scopes.clone()).await.unwrap();
    let test = db.get_token(token.clone()).await.unwrap();

    assert_eq!(test.token, token);
    assert_eq!(test.owner, server.uuid);
    assert_eq!(test.scopes.0, scopes);

    let new_token = db.create_token(&server.uuid, vec![]).await.unwrap();
    let new_test = db.get_token(new_token.clone()).await.unwrap();

    assert_eq!(new_test.token, new_token);
    assert_ne!(test.token, new_test.token);
    assert_eq!(test.owner, new_test.owner);
    assert_ne!(test.scopes, new_test.scopes);
    assert!(new_test.scopes.0.is_empty());

    Ok(())
}

// READ
#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_profile_by_id(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_profile(&db, "alikindsys").await;
    let save = db.get_profile_by_id(&user.uuid).await.unwrap();

    assert_eq!(user, save);
    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_profile(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_profile(&db, "alikindsys").await;
    let test = db.get_profile("alikindsys".to_string()).await.unwrap();

    assert_eq!(user.uuid, test.uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_profiles_by_discord_id(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let discord_id = "-Discord ID-".to_owned();
    let db = get_wrapper(pool).await.unwrap();

    let _ = mock_profile(&db, "alikindsys").await;
    let _ = mock_profile(&db, "other_user").await;

    let save = db.get_profiles_by_discord_id(discord_id).await.unwrap();

    assert_eq!(save.len(), 2);
    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let save = mock_server(&db).await;
    let read = db.get_server(&save.uuid).await.unwrap();

    assert_eq!(save, read);
    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_server_by_name(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let stub = GameServerStub {
        name: "Servidor de Teste".to_owned(),
        versions: vec!["1.21.0".to_owned()],
        staff: vec![],
        max_players: 32,
        game: "Minecraft".into(),
    };

    let name = stub.name.clone();

    let db = get_wrapper(pool).await.unwrap();

    let save = db.create_server(stub).await.unwrap();
    let read = db.get_server_by_name(name).await.unwrap();

    assert_eq!(save, read);

    Ok(())
}

// #[test(sqlx::test(migrations = "src/db/migrations"))]
// async fn get_all_servers(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
//     let db = get_wrapper(pool).await.unwrap();
//     mock_server(&db).await;

//     let servers = db.get_all_servers().await.unwrap();
//     assert_eq!(servers.len(), 1);
//     Ok(())
// }

#[test(sqlx::test(migrations = "src/db/migrations"))]
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
    assert_eq!(read.first().unwrap().get_addr(), Ipv4Addr::new(127, 0, 0, 1));
    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
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

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_allowlists(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_profile(&db, "alikindsys").await;

    db.create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.first().unwrap().uuid, user.uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_allowlists_with_ip(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_profile(&db, "alikindsys").await;

    db.create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    let read = db
        .get_allowlists_with_ip(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.first().unwrap().uuid, user.uuid);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn get_allowlists_with_range(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_profile(&db, "alikindsys").await;

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
    assert_eq!(read.first().unwrap().uuid, user.uuid);
    assert_eq!(read.get(1).unwrap().uuid, user.uuid);

    Ok(())
}
// UPCAST
#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn upcast_profile(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = v1_mock_user(&db, "alikindsys").await;
    let acc = v1_mock_account(&db, &user.uuid).await;

    let profile = db.upcast_profile(user.clone(), acc.clone()).await.unwrap();

    assert_eq!(profile.password, acc.password);
    assert_ne!(profile.uuid, user.uuid);
    assert_eq!(profile.username, user.username);
    assert_eq!(profile.discord_id, user.discord_id);

    Ok(())
}
#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn upcast_playtime(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = v1_mock_user(&db, "alikindsys").await;
    let account = v1_mock_account(&db, &user.uuid).await;

    let server = v1_mock_server(&db).await;
    let savedata = v1_mock_savedata(&db, &server.uuid, &user.uuid).await;

    let old_uuid = user.uuid;

    let p = db.upcast_profile(user, account).await.unwrap();
    let _ = db.upcast_server_v1(server).await.unwrap();
    let conn = db.upcast_savedata(savedata).await.unwrap();

    let playtime: ConnectionData = (conn.kind, conn.data).try_into().unwrap();

    assert_ne!(conn.profile, old_uuid);
    assert_eq!(conn.profile, p.uuid);

    assert!(matches!(playtime, ConnectionData::Playtime(_)));

    Ok(())
}
// UPDATE

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn reset_token(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let server = mock_server(&db).await;
    let scopes = vec![
        "profiles.read".to_string(),
        "servers.self.modify".to_string(),
    ];

    let token = db.create_token(&server.uuid, scopes.clone()).await.unwrap();
    let test = db.get_token(token.clone()).await.unwrap();

    let new_token = db.reset_token(&server.uuid).await.unwrap();
    let new_test = db.get_token(new_token.clone()).await.unwrap();

    assert_ne!(token, new_token);
    assert_eq!(test.owner, new_test.owner);
    assert_eq!(test.scopes, new_test.scopes);

    Ok(())
}

// #[test(sqlx::test(migrations = "src/db/migrations"))]
// async fn add_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
//     let uuid = Uuid::new_v4();
//     let db = get_wrapper(pool).await.unwrap();

//     let stub = UserStub {
//         uuid,
//         username: "alikindsys".to_owned(),
//         discord_id: "-Discord ID-".to_owned(),
//     };

//     let pronoun = Pronoun {
//         pronoun: "ela/dela".to_owned(),
//         color: "#F5A9B8".to_owned(),
//     };

//     db.create_user(stub.clone()).await.unwrap();
//     let pronouns = db.add_pronoun(&uuid, pronoun).await.unwrap();

//     assert_eq!(pronouns.len(), 1);

//     Ok(())
// }

// #[test(sqlx::test(migrations = "src/db/migrations"))]
// async fn remove_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
//     let uuid = Uuid::new_v4();
//     let db = get_wrapper(pool).await.unwrap();

//     let stub = UserStub {
//         uuid,
//         username: "alikindsys".to_owned(),
//         discord_id: "-Discord ID-".to_owned(),
//     };

//     let pronoun = Pronoun {
//         pronoun: "ela/dela".to_owned(),
//         color: "#F5A9B8".to_owned(),
//     };

//     db.create_user(stub.clone()).await.unwrap();
//     db.add_pronoun(&uuid, pronoun.clone()).await.unwrap();

//     let pronouns = db.remove_pronoun(&uuid, pronoun).await.unwrap();

//     assert_eq!(pronouns.len(), 0);

//     Ok(())
// }

// #[test(sqlx::test(migrations = "src/db/migrations"))]
// async fn update_pronoun(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
//     let uuid = Uuid::new_v4();
//     let db = get_wrapper(pool).await.unwrap();

//     let stub = UserStub {
//         uuid,
//         username: "alikindsys".to_owned(),
//         discord_id: "-Discord ID-".to_owned(),
//     };

//     let pronoun = Pronoun {
//         pronoun: "ela/dela".to_owned(),
//         color: "#F5A9B8".to_owned(),
//     };
//     let update = Pronoun {
//         pronoun: "ela/dela".to_owned(),
//         color: "#5BCEFA".to_owned(),
//     };

//     db.create_user(stub.clone()).await.unwrap();
//     db.add_pronoun(&uuid, pronoun.clone()).await.unwrap();

//     let pronouns = db
//         .update_pronoun(&uuid, &pronoun, update.clone())
//         .await
//         .unwrap();

//     assert_eq!(pronouns.first().unwrap().color, update.color);
//     assert_eq!(pronouns.len(), 1);

//     Ok(())
// }

// #[test(sqlx::test(migrations = "src/db/migrations"))]
// async fn update_playtime(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
//     let db = get_wrapper(pool).await.unwrap();

//     let user = mock_user(&db, "alikindsys").await;
//     let server = mock_server(&db).await;

//     db.create_savedata(&user.uuid, &server.uuid).await.unwrap();

//     db.update_playtime(&user.uuid, &server.uuid, Duration::from_secs_f32(69.0))
//         .await
//         .unwrap();

//     let save = db.get_playtime(&user.uuid, &server.uuid).await.unwrap();

//     assert_ne!(save, Duration::ZERO);
//     assert_eq!(save, Duration::from_secs_f32(69.0));

//     Ok(())
// }

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn update_password(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_profile(&db, "alikindsys").await;

    db.update_password(&user.uuid, "newpass".to_owned())
        .await
        .unwrap();

    let acc = db.get_profile_by_id(&user.uuid).await.unwrap();

    assert_eq!(acc.password, "newpass".to_owned());

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
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

    assert_eq!(read.first().unwrap().hits, 2);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
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

    assert_eq!(read.first().unwrap().mask, 16);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn bump_allowlist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_profile(&db, "alikindsys").await;

    let entry = db
        .create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    db.bump_allowlist(entry).await.unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.first().unwrap().hits, 2);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn broaden_allowlist_mask(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let user = mock_profile(&db, "alikindsys").await;

    let entry = db
        .create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    db.broaden_allowlist_mask(entry, 16).await.unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 1);
    assert_eq!(read.first().unwrap().mask, 16);

    Ok(())
}

// DELETE

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn delete_server(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let stub = GameServerStub {
        name: "Servidor de Teste".to_owned(),
        versions: vec!["1.21.0".to_owned()],
        staff: vec![],
        max_players: 32,
        game: "Minecraft".into(),
    };

    let db = get_wrapper(pool).await.unwrap();

    let save = db.create_server(stub.clone()).await.unwrap();

    let read = db.delete_server(&save.uuid).await.unwrap();

    let gs = GameServer::from(save);
    let gr = GameServer::from(read);

    assert_eq!(gs, stub);
    assert_eq!(gr, stub);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
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

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn delete_allowlist(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();

    let user = mock_profile(&db, "alikindsys").await;

    let entry = db
        .create_allowlist(&user.uuid, Ipv4Addr::new(127, 0, 0, 1))
        .await
        .unwrap();

    db.delete_allowlist(entry).await.unwrap();

    let read = db.get_allowlists(&user.uuid).await.unwrap();

    assert_eq!(read.len(), 0);

    Ok(())
}

#[test(sqlx::test(migrations = "src/db/migrations"))]
async fn revoke_token(pool: sqlx::Pool<sqlx::Sqlite>) -> sqlx::Result<()> {
    let db = get_wrapper(pool).await.unwrap();
    let server = mock_server(&db).await;
    let scopes = vec![
        "profiles.read".to_string(),
        "servers.self.modify".to_string(),
    ];

    let _ = db.create_token(&server.uuid, scopes.clone()).await.unwrap();
    db.revoke_token(&server.uuid).await.unwrap();

    // Attempt to reset a revoked token, should always fail.
    let test = db.reset_token(&server.uuid).await;
    assert!(test.is_err());

    Ok(())
}
