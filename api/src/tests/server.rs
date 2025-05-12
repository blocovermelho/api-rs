#![allow(unused_imports)]

use std::time::Duration;

use db::data::{stub::ServerStub, Loc, SaveData, Viewport};
use serenity::all::NsfwLevel::Default;

use crate::{
    routes::{server as R, server::MAX_ATTEMPTS_PER_ACC},
    tests::prelude::{query_params::MigrationUuid, *},
};

test_route!(get_all_servers, state, {
    let test = R::get_all_servers(state.clone()).await?;
    assert_eq!(test.len(), 0);

    let s = state
        .db
        .create_server(stub::server("Internal Testing Server"))
        .await?;
    let test = R::get_all_servers(state).await?;

    assert_eq!(test.0, vec![s.uuid]);
});

test_route!(get, state, {
    let s = state
        .db
        .create_server(stub::server("Internal Testing Server"))
        .await?;
    let test = R::get(state, Path(s.uuid)).await?;

    assert_eq!(test.uuid, s.uuid);
});

test_route!(delete, state, {
    let s = state
        .db
        .create_server(stub::server("Internal Testing Server"))
        .await?;
    let test = R::delete(state.clone(), Path(s.uuid)).await?;
    assert_eq!(test.uuid, s.uuid);

    let check = state.db.get_all_servers().await?;
    assert!(!check.contains(&s.uuid));
});

test_route!(create, state, {
    assert!(state
        .db
        .get_server_by_name("Internal Testing Server".into())
        .await
        .is_err());
    let test = R::create(state.clone(), Json(stub::server("Internal Testing Server"))).await?;
    let s = state
        .db
        .get_server_by_name("Internal Testing Server".into())
        .await?;
    assert_eq!(test.uuid, s.uuid);
});

test_route!(enable, state, {
    let s = state
        .db
        .create_server(stub::server("Internal Testing Server".into()))
        .await?;
    let _ = state.db.update_server_status(&s.uuid, false).await?;
    let s = state.db.get_server(&s.uuid).await?;
    assert_eq!(s.online.0, false);

    let test = R::enable(state.clone(), Path(s.uuid)).await?;
    assert_eq!(test.0, true);

    let s = state.db.get_server(&s.uuid).await?;
    assert_eq!(s.online.0, true);
});

test_route!(disable, state, {
    let s = state
        .db
        .create_server(stub::server("Internal Testing Server".into()))
        .await?;
    let _ = state.db.update_server_status(&s.uuid, true).await?;
    let s = state.db.get_server(&s.uuid).await?;
    assert_eq!(s.online.0, true);

    let test = R::disable(state.clone(), Path(s.uuid)).await?;
    assert_eq!(test.0, false);

    let s = state.db.get_server(&s.uuid).await?;
    assert_eq!(s.online.0, false);
});

test_route!(login, state, {
    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(u.uuid, "password123"))
        .await?;
    let s = state
        .db
        .create_server(stub::server("Internal Test Server"))
        .await?;

    // Wrong Password Attempt
    let wrong = R::login(
        state.clone(),
        Path(s.uuid),
        Json(stub::login_attempt("alikindsys", "password12")),
    )
    .await?;
    assert!(wrong.0.is_none());

    // Happy Path
    let right = R::login(
        state.clone(),
        Path(s.uuid),
        Json(stub::login_attempt("alikindsys", "password123")),
    )
    .await?;
    assert!(right.0.is_some());

    // Really wrong path
    let mut error = R::login(
        state.clone(),
        Path(s.uuid),
        Json(stub::login_attempt("alikindsys", "password12")),
    )
    .await;
    for _ in 0..MAX_ATTEMPTS_PER_ACC {
        error = R::login(
            state.clone(),
            Path(s.uuid),
            Json(stub::login_attempt("alikindsys", "password12")),
        )
        .await;
    }
    assert!(error.is_err());
});

test_route!(logoff, state, {
    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(u.uuid, "password123"))
        .await?;
    let s = state
        .db
        .create_server(stub::server("Internal Test Server"))
        .await?;

    let _ = R::login(
        state.clone(),
        Path(s.uuid),
        Json(stub::login_attempt("alikindsys", "password123")),
    )
    .await?;

    let viewport = Viewport {
        loc: Loc {
            dim: "minecraft:nether".to_string(),
            x: 123.0,
            y: 45.0,
            z: 678.0,
        },
        yaw: -90.0,
        pitch: 90.0,
    };

    let test = R::logoff(
        state.clone(),
        Path(s.uuid),
        Query(stub::login_attempt("alikindsys", "password123")),
        Json(viewport.clone()),
    )
    .await?;

    assert_eq!(test.0, true);

    let check = state.db.get_viewport(&u.uuid, &s.uuid).await?;
    let check2 = state.db.get_playtime(&u.uuid, &s.uuid).await?;

    assert_eq!(check, viewport);
    assert_ne!(check2, Duration::ZERO);
});

test_route!(migrate_user, state, {
    // Migration logic is a freaking mess.
    let old = state
        .db
        .create_user(stub::user("roridev", "155774074885242880"))
        .await?;
    let _ = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(old.uuid, "password123"))
        .await?;
    let old_acc = state.db.get_account(&old.uuid).await?;
    let server = state
        .db
        .create_server(stub::server("Internal Test Server"))
        .await?;

    let viewport = Viewport {
        loc: Loc {
            dim: "minecraft:nether".to_string(),
            x: 123.0,
            y: 45.0,
            z: 678.0,
        },
        yaw: -90.0,
        pitch: 90.0,
    };

    let _ = R::login(
        state.clone(),
        Path(server.uuid),
        Json(stub::login_attempt("roridev", "password123")),
    )
    .await?;
    let _ = R::logoff(
        state.clone(),
        Path(server.uuid),
        Query(stub::login_attempt("roridev", "password123")),
        Json(viewport.clone()),
    )
    .await?;
    let _ = state
        .db
        .update_playtime(&old.uuid, &server.uuid, Duration::from_secs(63))
        .await?;

    // Root Migration.
    // Created after the user is joined to populate the `affected_servers` field, otherwise the migration would happen instantaneously.
    let migration = state
        .db
        .create_migration("roridev".into(), "alikindsys".into(), None)
        .await?;

    let test = R::migrate_user(
        state.clone(),
        Path(server.uuid),
        Query(MigrationUuid { uuid: migration.id }),
    )
    .await?;
    assert_eq!(test.0, true);

    let new = state.db.get_user_by_name("alikindsys".into()).await?;
    let new_acc = state.db.get_account(&new.uuid).await?;
    let new_viewport = state.db.get_viewport(&new.uuid, &server.uuid).await?;
    let new_playtime = state.db.get_playtime(&new.uuid, &server.uuid).await?;

    assert_eq!(new.discord_id, old.discord_id);
    assert_eq!(new.created_at, old.created_at);
    assert_eq!(new_acc.password, old_acc.password);
    assert_eq!(new_viewport, viewport);
    assert_eq!(new_playtime, Duration::from_secs(63));

    assert!(state.db.get_user_by_uuid(&old.uuid).await.is_err());
    assert!(state.db.get_account(&old.uuid).await.is_err());

    // Merge two accounts with existing playtimes to a single one.
    let other_user = state
        .db
        .create_user(stub::user("viftw_", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(other_user.uuid, "password321"))
        .await?;

    let _ = R::login(
        state.clone(),
        Path(server.uuid),
        Json(stub::login_attempt("viftw_", "password321")),
    )
    .await?;
    let _ = R::logoff(
        state.clone(),
        Path(server.uuid),
        Query(stub::login_attempt("viftw_", "password321")),
        Json(viewport.clone()),
    )
    .await?;
    let _ = state
        .db
        .update_playtime(&other_user.uuid, &server.uuid, Duration::from_secs(10))
        .await?;
    let other_viewport = state
        .db
        .update_viewport(&other_user.uuid, &server.uuid, Viewport {
            yaw: -12.0,
            ..viewport.clone()
        })
        .await?;

    let merge_migration = state
        .db
        .create_migration("alikindsys".into(), "viftw_".into(), Some(migration.id))
        .await?;
    let test = R::migrate_user(
        state.clone(),
        Path(server.uuid),
        Query(MigrationUuid { uuid: merge_migration.id }),
    )
    .await?;

    assert_eq!(test.0, true);

    let merged = state.db.get_user_by_name("viftw_".into()).await?;
    let merged_acc = state.db.get_account(&merged.uuid).await?;
    let merged_viewport = state.db.get_viewport(&merged.uuid, &server.uuid).await?;
    let merged_playtime = state.db.get_playtime(&merged.uuid, &server.uuid).await?;

    assert_ne!(merged_acc.password, new_acc.password);
    assert_ne!(merged_viewport, new_viewport);
    assert_eq!(merged_viewport, other_viewport);
    assert_eq!(merged_playtime, Duration::from_secs(73));

    assert!(state.db.get_user_by_uuid(&new.uuid).await.is_err());
    assert!(state.db.get_account(&new.uuid).await.is_err());
});
