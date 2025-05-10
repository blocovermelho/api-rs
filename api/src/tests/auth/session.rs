#![allow(unused_imports)]

use db::{data::BanActor, drivers::json::data::BanIssuer};

use crate::{
    routes::auth::session as R,
    tests::prelude::{
        query_params::{AllowIp, BanIp},
        responses::{BanKind, IpKind},
        *,
    },
};

#[tokio::test]
async fn exists() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(u.uuid, "test_password"))
        .await?;

    let pre =
        R::exists(state.clone(), Query(stub::ip_check(u.uuid, [192, 168, 0, 10].into()))).await?;
    assert_eq!(pre.0, false);

    let alist = state
        .db
        .create_allowlist(&u.uuid, [192, 168, 0, 10].into())
        .await?;
    assert_eq!(alist.hits, 1);

    let test =
        R::exists(state.clone(), Query(stub::ip_check(u.uuid, [192, 168, 0, 10].into()))).await?;
    let next_alist = state
        .db
        .get_allowlists_with_ip(&u.uuid, [192, 168, 0, 10].into())
        .await?;

    assert_eq!(test.0, true);
    assert_eq!(next_alist.first().unwrap().hits, 2);

    Ok(())
}

#[tokio::test]
async fn resume() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(u.uuid, "test_password"))
        .await?;
    state
        .db
        .create_allowlist(&u.uuid, [192, 168, 0, 10].into())
        .await?;

    let prev = state.db.get_account(&u.uuid).await?;

    let test =
        R::resume(state.clone(), Query(stub::ip_check(u.uuid, [192, 168, 0, 10].into()))).await?;
    assert_eq!(test.0, true);

    let next = state.db.get_account(&u.uuid).await?;

    assert!(next.current_join > prev.current_join);

    Ok(())
}

#[tokio::test]
async fn ban_ip() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;
    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;

    let pre = state.db.get_blacklists([192, 168, 0, 10].into()).await?;
    assert!(pre.is_empty());

    let new = R::ban_ip(
        state.clone(),
        Query(BanIp {
            uuid: u.uuid,
            ip: [192, 168, 0, 10].into(),
            server: None,
        }),
        Json(BanIssuer::Automatic),
    )
    .await?;

    assert!(matches!(new.0, BanKind::New));

    let existing = R::ban_ip(
        state.clone(),
        Query(BanIp {
            uuid: u.uuid,
            ip: [192, 168, 0, 10].into(),
            server: None,
        }),
        Json(BanIssuer::Automatic),
    )
    .await?;

    assert!(matches!(existing.0, BanKind::Existing));

    let merged = R::ban_ip(
        state.clone(),
        Query(BanIp {
            uuid: u.uuid,
            ip: [192, 168, 0, 8].into(),
            server: None,
        }),
        Json(BanIssuer::Automatic),
    )
    .await?;

    assert!(matches!(merged.0, BanKind::Merged));

    let post = state.db.get_blacklists([192, 168, 0, 10].into()).await?;
    assert_eq!(post.len(), 1);

    Ok(())
}
#[tokio::test]
async fn whitelist_ip() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(u.uuid, "test_password"))
        .await?;

    let pre = state
        .db
        .get_allowlists_with_ip(&u.uuid, [127, 0, 0, 8].into())
        .await?;
    assert!(pre.is_empty());

    let test = R::whitelist_ip(
        state.clone(),
        Query(AllowIp {
            uuid: u.uuid,
            ip: [127, 0, 0, 8].into(),
            server: None,
        }),
    )
    .await?;
    assert_eq!(test.0, true);

    let next = state
        .db
        .get_allowlists_with_ip(&u.uuid, [127, 0, 0, 8].into())
        .await?;
    assert_eq!(next.len(), 1);

    Ok(())
}
#[tokio::test]
async fn check_ip() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    state
        .db
        .create_account(stub::account_hashed(u.uuid, "test_password"))
        .await?;

    state
        .db
        .create_blacklist([192, 123, 0, 8].into(), BanActor::AutomatedSystem("Test Ban".into()))
        .await?;

    let test =
        R::check_ip(state.clone(), Query(stub::ip_check(u.uuid, [127, 0, 0, 8].into()))).await?;
    assert!(matches!(test.0, IpKind::Unknown));

    let test =
        R::check_ip(state.clone(), Query(stub::ip_check(u.uuid, [192, 123, 0, 8].into()))).await?;
    assert!(matches!(test.0, IpKind::Banned));

    state
        .db
        .create_allowlist(&u.uuid, [127, 0, 0, 8].into())
        .await?;

    let test =
        R::check_ip(state.clone(), Query(stub::ip_check(u.uuid, [127, 0, 0, 8].into()))).await?;
    assert!(matches!(test.0, IpKind::Allowed));

    Ok(())
}
