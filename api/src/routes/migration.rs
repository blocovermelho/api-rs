use db::data::{result::NodeDeletion, stub::UserStub, Migration};
use uuid_mc::PlayerUuid;

use crate::routes::prelude::{
    query_params::{MigrateAccount, OfflineUuid},
    *,
};

/// [POST] /auth/migrate?old=<old_username>&new=<new_username>
pub async fn create(
    State(state): State<Arc<AppState>>, Query(migrate): Query<MigrateAccount>,
) -> Res<Migration> {
    let old_user = state
        .db
        .get_user_by_name(migrate.old.clone())
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Old user not found.")))?;

    let mut new_user = state.db.get_user_by_name(migrate.new.clone()).await;

    if new_user.is_err() {
        let user_uuid = PlayerUuid::new_with_offline_username(&migrate.new);
        new_user = state
            .db
            .create_user(UserStub {
                uuid: *user_uuid.as_uuid(),
                username: migrate.new.clone(),
                discord_id: old_user.discord_id,
            })
            .await;
    }

    let new_user =
        new_user.map_err(|_| ErrKind::Internal(Err::new("Couldn't get or create New User")))?;

    // If the new account already has a pending migration, return that pending migration and dont create a new one.
    if let Some(id) = new_user.current_migration {
        let migration =
            state.db.get_migration(&id).await.map_err(|_| {
                ErrKind::NotFound(Err::new("Invalid Current Migration for New User."))
            })?;

        // Migration hasn't finished yet.
        if migration.finished_at.is_none() {
            return Ok(Json(migration));
        }
    }

    // We now should create a new migration
    let migration = state
        .db
        .create_migration(
            migrate.old,
            migrate.new,
            old_user.current_migration.or(new_user.current_migration),
        )
        .await
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't create migration").with_inner(e)))?;

    // And set it as the current migration for the new user.
    let _ = state
        .db
        .set_current_migration(&new_user.uuid, Some(migration.id))
        .await
        .map_err(|e| {
            ErrKind::Internal(Err::new("Couldn't set Current Migration for New User").with_inner(e))
        })?;

    Ok(Json(migration))
}

/// [GET] /auth/migration?id=<uuid>
pub async fn get(
    State(state): State<Arc<AppState>>, Query(migration_id): Query<OfflineUuid>,
) -> Res<Migration> {
    let migration = state
        .db
        .get_migration(&migration_id.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Migration not found.")))?;

    Ok(Json(migration))
}

/// [PATCH] /auth/migration/:uuid/show
pub async fn set_visible(
    State(state): State<Arc<AppState>>, Path(migration_id): Path<Uuid>,
) -> Res<bool> {
    let migration = state
        .db
        .get_migration(&migration_id)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Migration not found.")))?;

    let result = state
        .db
        .update_visibility(&migration.id, true)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("Couldn't update migration.")))?;

    Ok(Json(result))
}

/// [PATCH] /auth/migration/:uuid/hide
pub async fn set_hidden(
    State(state): State<Arc<AppState>>, Path(migration_id): Path<Uuid>,
) -> Res<bool> {
    let migration = state
        .db
        .get_migration(&migration_id)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Migration not found.")))?;

    let result = state
        .db
        .update_visibility(&migration.id, false)
        .await
        .map_err(|_| ErrKind::Internal(Err::new("Couldn't update migration.")))?;

    Ok(Json(result))
}

/// [DELETE] /auth/migration?id=<uuid>
pub async fn delete(
    State(state): State<Arc<AppState>>, Query(migration_id): Query<OfflineUuid>,
) -> Res<bool> {
    let migration = state
        .db
        .get_migration(&migration_id.uuid)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("Migration not found.")))?;

    let new_user = state
        .db
        .get_user_by_name(migration.new)
        .await
        .map_err(|_| ErrKind::NotFound(Err::new("New User not found.")))?;

    let node = state
        .db
        .delete_migration(&migration_id.uuid)
        .await
        .map_err(|e| ErrKind::Internal(Err::new("Couldn't delete Migration").with_inner(e)))?;

    match node {
        NodeDeletion::Middle | NodeDeletion::First { is_orphan: false } => {}
        NodeDeletion::First { is_orphan: true } => {
            state
                .db
                .set_current_migration(&new_user.uuid, None)
                .await
                .map_err(|e| {
                    ErrKind::Internal(
                        Err::new("Couldn't update user state. Orphaned Node.").with_inner(e),
                    )
                })?;
        }
        NodeDeletion::Last { replacement } => {
            state
                .db
                .set_current_migration(&new_user.uuid, Some(replacement))
                .await
                .map_err(|e| {
                    ErrKind::Internal(
                        Err::new("Couldn't update user state. Last Node.").with_inner(e),
                    )
                })?;
        }
    }

    Ok(Json(true))
}
