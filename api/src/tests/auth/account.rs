#![allow(unused_imports)]

use db::data::stub::{AccountStub, UserStub};

use crate::{
    routes::auth::account as R,
    tests::prelude::{
        query_params::{ChangePassword, LoginAttempt, OfflineUuid},
        *,
    },
};

#[tokio::test()]
async fn create() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let _ = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;

    let data = stub::login_attempt("alikindsys", "test_password");
    let uuid = data.uuid.clone();

    assert!(state.db.get_account(&uuid).await.is_err()); // Doesn't exist since the account wasn't created yet

    let _ = R::create(state.clone(), Json(data)).await?;

    assert!(state.db.get_account(&uuid).await.is_ok()); // Was created sucessfully

    Ok(())
}

#[tokio::test]
async fn exists() -> Result<(), anyhow::Error> {
    let state = get_state();
    state.db.run_migrations().await;

    let u = state
        .db
        .create_user(stub::user("alikindsys", "155774074885242880"))
        .await?;

    let pre = R::exists(state.clone(), Query(OfflineUuid { uuid: u.uuid })).await?;
    assert_eq!(pre.0, false); // Doesn't exist since the account wasn't created yet

    state
        .db
        .create_account(stub::account(u.uuid, "test_password"))
        .await?;

    let post = R::exists(state.clone(), Query(OfflineUuid { uuid: u.uuid })).await?;
    assert_eq!(post.0, true); // Account exists.
    Ok(())
}

#[tokio::test]
async fn change_password() -> Result<(), anyhow::Error> {
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

    let _ = R::change_password(
        state.clone(),
        Json(ChangePassword {
            uuid: u.uuid,
            old: "test_password".into(),
            new: "new_password".to_string(),
        }),
    )
    .await?;

    let acc = state.db.get_account(&u.uuid).await?;

    assert!(bcrypt::verify("new_password", &acc.password)?);

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
    state
        .db
        .create_account(stub::account_hashed(u.uuid, "test_password"))
        .await?;

    let res = R::delete(state.clone(), Path(u.uuid)).await?;

    assert!(res.0);
    assert!(state.db.get_account(&u.uuid).await.is_err());

    Ok(())
}
