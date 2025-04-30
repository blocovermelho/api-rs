use db::data::{stub::UserStub, User};

use crate::routes::prelude::{query_params::OfflineUuid, *};

// TODO: Add Pagination
/// [GET] /api/users
pub async fn get_all_users(State(state): State<Arc<AppState>>) -> Res<Vec<Uuid>> {
    let data = state.db.get_all_users().await.map_err(|e| {
        ErrKind::Internal(Err::new("Couldn't get all users").with_inner(format!("{:?}", e)))
    })?;
    Ok(Json(data))
}

/// [GET] /`api/user/:user_id`
pub async fn get_by_offline_id(
    State(state): State<Arc<AppState>>, Path(user_id): Path<Uuid>,
) -> Res<User> {
    let data = state
        .db
        .get_user_by_uuid(&user_id)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("User not found.")))?;

    Ok(Json(data))
}

/// [GET] /api/user/by-name/:username
pub async fn get_by_username(
    State(state): State<Arc<AppState>>, Path(username): Path<String>,
) -> Res<User> {
    let data = state
        .db
        .get_user_by_name(username)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("User not found.")))?;

    Ok(Json(data))
}

/// [GET] /api/user/by-discord/:discordId
pub async fn get_linked_users(
    State(state): State<Arc<AppState>>, Path(discord_id): Path<String>,
) -> Res<Vec<User>> {
    let data = state
        .db
        .get_users_by_discord_id(discord_id)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("No users linked.")))?;

    Ok(Json(data))
}

/// [GET] /api/user/exists?uuid=<uuid>
pub async fn exists(
    State(state): State<Arc<AppState>>, Query(uuid): Query<OfflineUuid>,
) -> Res<bool> {
    let data = state.db.get_user_by_uuid(&uuid.uuid).await;

    Ok(Json(data.is_ok()))
}

/// [POST] /api/user
pub async fn create(State(state): State<Arc<AppState>>, Json(stub): Json<UserStub>) -> Res<User> {
    let user = state
        .db
        .create_user(stub)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("This user already exists.")))?;

    Ok(Json(user))
}
