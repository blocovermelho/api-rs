#![allow(unused_imports)]

use crate::{
    routes::user as R,
    tests::prelude::{query_params::OfflineUuid, *},
};

#[tokio::test]
async fn exists() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let test = R::exists(state.clone(), Query(OfflineUuid { uuid: Uuid::nil() })).await?;
    assert_eq!(test.0, false);

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;

    let test = R::exists(state.clone(), Query(OfflineUuid { uuid: u.uuid })).await?;
    assert_eq!(test.0, true);

    Ok(())
}

#[tokio::test]
async fn create() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    assert!(state
        .db
        .get_user_by_name("alikindsys".into())
        .await
        .is_err());

    let _ = R::create(state.clone(), Json(stub::user("alikindsys", "155774074885242880"))).await?;

    assert!(state.db.get_user_by_name("alikindsys".into()).await.is_ok());

    Ok(())
}
#[tokio::test]
async fn delete() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    let test = R::delete(state.clone(), Path(u.uuid)).await?;

    assert_eq!(u.uuid, test.uuid);

    let check = state.db.get_user_by_uuid(&test.uuid).await;

    assert!(check.is_err());

    Ok(())
}

#[tokio::test]
async fn get_all_users() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let test = R::get_all_users(state.clone()).await?;
    assert!(test.0.is_empty());

    let _ = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    let _ = state
        .db
        .create_user(stub::user("roridev", "155774074885242880"))
        .await?;

    let test = R::get_all_users(state.clone()).await?;
    assert_eq!(test.0.len(), 2);

    Ok(())
}

#[tokio::test]
async fn get_by_offline_id() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    let test = R::get_by_offline_id(state.clone(), Path(u.uuid)).await?;

    assert_eq!(u.uuid, test.uuid);

    Ok(())
}

#[tokio::test]
async fn get_by_username() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    let test = R::get_by_username(state.clone(), Path(u.username)).await?;

    assert_eq!(u.uuid, test.uuid);

    Ok(())
}

#[tokio::test]
async fn get_linked_users() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let test = R::get_all_users(state.clone()).await?;
    assert!(test.0.is_empty());

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;
    let _ = state
        .db
        .create_user(stub::user("roridev", "155774074885242880"))
        .await?;

    let test = R::get_linked_users(state.clone(), Path(u.discord_id)).await?;
    assert_eq!(test.0.len(), 2);
    Ok(())
}
