use bcrypt;
use db::data::stub::AccountStub;

use crate::routes::prelude::{
    query_params::{ChangePassword, LoginAttempt, OfflineUuid},
    *,
};

const HASH_COST: u32 = 12;
const MAX_ATTEMPTS_PER_ACC: i32 = 10;

/// [GET] /auth/exists?uuid=<uuid>
pub async fn exists(
    State(state): State<Arc<AppState>>, Query(account): Query<OfflineUuid>,
) -> Res<bool> {
    let data = state.db.get_account(&account.uuid).await;

    Ok(Json(data.is_ok()))
}

/// [POST] /auth
pub async fn create(
    State(state): State<Arc<AppState>>, Json(attempt): Json<LoginAttempt>,
) -> Res<bool> {
    let hash = bcrypt::hash(&attempt.password, HASH_COST)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

    match state
        .db
        .create_account(AccountStub { uuid: attempt.uuid, password: hash })
        .await
    {
        Ok(_) => {}
        Result::Err(_) => return Err(ErrKind::Internal(Err::new("Account already exists"))),
    };

    let _ = state.db.create_allowlist(&attempt.uuid, attempt.ip).await;

    Ok(Json(true))
}

/// [PATCH] /auth/changepw
pub async fn change_password(
    State(state): State<Arc<AppState>>, Json(attempt): Json<ChangePassword>,
) -> Res<bool> {
    let mut eph = state.ephemeral.lock().await;

    let acc = state
        .db
        .get_account(&attempt.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Account not found.")))?;

    let matches = bcrypt::verify(attempt.old, &acc.password)
        .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

    if matches {
        let new_pass = bcrypt::hash(attempt.new, 12)
            .map_err(|e| ErrKind::Internal(Err::new("BCrypt Error.").with_inner(e)))?;

        let _ = state.db.update_password(&attempt.uuid, new_pass).await;

        Ok(Json(true))
    } else {
        let mut count = 1;

        if eph.password.contains_key(&attempt.uuid) {
            count = *(eph.password.get(&attempt.uuid).unwrap());
            count += 1;
        }

        eph.password.insert(attempt.uuid, count);

        if count >= MAX_ATTEMPTS_PER_ACC {
            Err(ErrKind::BadRequest(Err::new("Exhausted MAX_ATTEMPTS for this account.")))
        } else {
            Ok(Json(false))
        }
    }
}

/// [DELETE] /auth/:user
pub async fn delete(
    State(state): State<Arc<AppState>>, Path(offline_uuid): Path<Uuid>,
) -> Res<bool> {
    state
        .db
        .delete_account(&offline_uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("User not found.")))?;

    Ok(Json(true))
}
