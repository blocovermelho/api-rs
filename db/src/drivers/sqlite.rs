use core::time;
use std::{fmt::Display, net::Ipv4Addr, time::Duration};

use chrono::Utc;
use sqlx::{types::Json, SqliteConnection};
use tracing::error;
use uuid::Uuid;

use crate::{
    data::{
        self,
        result::{ServerJoin, ServerLeave},
        Account, Allowlist, BanActor, Blacklist, Loc, SaveData, Server, User, Viewport,
    },
    interface::DataSource,
};

use super::err::{base, DriverError, Response};

#[derive(Debug)]
pub struct Sqlite {
    conn: SqliteConnection,
}

impl Sqlite {
    pub fn new(conn: SqliteConnection) -> Self {
        Self { conn }
    }
}

fn map_or_log<T, E, F>(either: Result<T, E>, err: F) -> Result<T, F>
where
    E: Display,
{
    match either {
        Ok(value) => Ok(value),
        Err(e) => {
            error!("{e}");
            Err(err)
        }
    }
}

impl DataSource for Sqlite {
    /// Gets an [User] by its Uuid.
    ///
    /// Returns an [`base::NotFoundError::User`] wrapped inside a [`DriverError::DatabaseError`] if a user with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_user_by_uuid(&mut self, uuid: &uuid::Uuid) -> Response<User> {
        let query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE uuid = ?")
            .bind(uuid)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::User(uuid.clone())),
        )
    }

    /// Gets *all* [`User`]s registered to an Discord account.
    ///
    /// ### Note: Multiple users can share the same Discord account.
    /// Returns an [`base::NotFoundError::DiscordAccount`] wrapped inside a [`DriverError::DatabaseError`] if no users can be found for the given discord id.
    #[tracing::instrument]
    async fn get_users_by_discord_id(&mut self, discord_id: String) -> Response<Vec<User>> {
        let query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE discord_id = ?")
            .bind(discord_id)
            .fetch_all(&mut self.conn)
            .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::DiscordAccount),
        )
    }

    /// Creates a new [`User`]
    ///
    /// Returns [`DriverError::DuplicateKeyInsertion`] if an user with the provided uuid already exists.
    #[tracing::instrument]
    async fn create_user(&mut self, stub: data::stub::UserStub) -> Response<User> {
        let query = sqlx::query_as::<_, User>("INSERT INTO users (uuid, username, discord_id, created_at, pronouns) VALUES ($1, $2, $3, $4, $5) RETURNING * ")
        .bind(stub.uuid)
        .bind(stub.username)
        .bind(stub.discord_id)
        .bind(Utc::now())
        .bind("[]")
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Deletes an [`User`] given its uuid, returning the deleted User.
    ///
    /// Returns an [`base::NotFoundError::User`] wrapped inside a [`DriverError::DatabaseError`] if a user with the given uuid can't be found.
    #[tracing::instrument]
    async fn delete_user(&mut self, uuid: &uuid::Uuid) -> Response<User> {
        let query = sqlx::query_as::<_, User>("DELETE FROM users WHERE uuid == ? RETURNING *")
            .bind(uuid)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::User(uuid.clone())),
        )
    }

    #[tracing::instrument]
    /// Migrates an [`User`]'s metadata to a new User, returing the "merged" User.
    ///
    /// Returns an [`base::NotFoundError::User`] wrapped inside a [`DriverError::DatabaseError`] if either user with the provided uuid can't be found.  
    /// Returns an [`DriverError::Unreachable`] if something *bad* happens.
    /// ### Note: Using [`DriverError::Unreachable`] is justified since all inputs were validated prior to running the query.
    async fn migrate_user(&mut self, from: &uuid::Uuid, into: &uuid::Uuid) -> Response<User> {
        let from_user = self.get_user_by_uuid(from).await?;
        let into_user = self.get_user_by_uuid(into).await?;

        let query = sqlx::query_as::<_, User>(
            "UPDATE users SET created_at = $1, pronouns = $2 WHERE uuid = $3 RETURNING *",
        )
        .bind(from_user.created_at)
        .bind(from_user.pronouns)
        .bind(into_user.uuid)
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(query, DriverError::Unreachable)
    }

    /// Creates an [`Account`] returning the unit value if it succeeds.
    ///
    /// ### Warning: This function expects a salted/hashed password since it *does not* do any hashing/salting itself.
    /// Returns [`DriverError::DuplicateKeyInsertion`] if an account with said uuid already exists.
    #[tracing::instrument(skip(stub))]
    async fn create_account(&mut self, stub: data::stub::AccountStub) -> Response<()> {
        let query = sqlx::query_as::<_, Account>(
            "INSERT INTO accounts (uuid, password, current_join) VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(stub.uuid)
        .bind(stub.password)
        .bind(Utc::now())
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(query.map(|_| ()), DriverError::DuplicateKeyInsertion)
    }

    /// Gets an [`Account`] retuning the Account if it succeds.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_account(&mut self, uuid: &Uuid) -> Response<Account> {
        let query = sqlx::query_as::<_, Account>("SELECT * FROM accounts WHERE uuid = ?")
            .bind(uuid)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Account(uuid.clone())),
        )
    }

    /// Updates an [`Account`]'s password..
    ///
    /// ### Warning: This function expects a salted/hashed password since it *does not* do any hashing/salting itself.
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument(skip(password))]
    async fn update_password(
        &mut self,
        player_uuid: &uuid::Uuid,
        password: String,
    ) -> Response<()> {
        let query = sqlx::query("UPDATE accounts SET password = $1 WHERE uuid = $2")
            .bind(password)
            .bind(player_uuid)
            .execute(&mut self.conn)
            .await;

        map_or_log(
            query.map(|_| ()),
            DriverError::DatabaseError(base::NotFoundError::Account(player_uuid.clone())),
        )
    }

    /// Migrates an [`Account`]'s password to a new Account, returing the unit value on success.
    ///
    /// Returns an [`base::NotFoundError::User`] wrapped inside a [`DriverError::DatabaseError`] if either user with the provided uuid can't be found.  
    /// Returns an [`DriverError::Unreachable`] if something *bad* happens.
    /// ### Note: Using [`DriverError::Unreachable`] is justified since all inputs were validated prior to running the query.

    #[tracing::instrument]
    async fn migrate_account(&mut self, from: &uuid::Uuid, to: &uuid::Uuid) -> Response<()> {
        let from = self.get_user_by_uuid(from).await?;
        let to = self.get_user_by_uuid(to).await?;

        let query = sqlx::query("UPDATE accounts SET uuid = $2 WHERE uuid = $1")
        .bind(from.uuid)
        .bind(to.uuid)
        .execute(&mut self.conn)
        .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Deletes an [`Account`] given its uuid, returning the unit value on success.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument]
    async fn delete_account(&mut self, player_uuid: &uuid::Uuid) -> Response<()> {
        let query = sqlx::query("DELETE FROM accounts WHERE uuid == ?")
            .bind(player_uuid)
            .execute(&mut self.conn)
            .await;

        map_or_log(
            query.map(|_| ()),
            DriverError::DatabaseError(base::NotFoundError::Account(player_uuid.clone())),
        )
    }

    /// Creates an [`AllowlistEntry`] given its uuid and ip address, returning the AllowlistEntry.
    ///
    /// Returns an [`DriverError::DuplicateKeyInsertion`] if an account with the given uuid or ip address can be found.
    #[tracing::instrument(skip(ip))]
    async fn create_allowlist(&mut self, player_uuid: &Uuid, ip: Ipv4Addr) -> Response<Allowlist> {
        let user = self.get_user_by_uuid(player_uuid).await?;

        let query = sqlx::query_as::<_, Allowlist>(
            "INSERT INTO allowlist (uuid, discord_id, base_ip, mask, last_join, hits) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *"
        )
        .bind(player_uuid)
        .bind(user.discord_id)
        .bind(ip.to_bits())
        .bind(32)
        .bind(Utc::now())
        .bind(1)
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Gets *ALL* [`AllowlistEntry`]s assigned to a user, sorted by how recently they were used.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_allowlists(&mut self, player_uuid: &Uuid) -> Response<Vec<Allowlist>> {
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist WHERE uuid = $1 ORDER BY last_join DESC",
        )
        .bind(player_uuid)
        .fetch_all(&mut self.conn)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Account(player_uuid.clone())),
        )
    }

    /// Gets *ANY* [`AllowlistEntry`]s assigned to a user that match the provided ip address, sorted by how recently they were used.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_allowlists_with_ip(
        &mut self,
        player_uuid: &Uuid,
        ip: Ipv4Addr,
    ) -> Response<Vec<Allowlist>> {
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist WHERE uuid = $1 AND ($2 & (-1 << (32 - mask))) = (base_ip & (-1 << (32 - mask))) ORDER BY last_join DESC"
        )
        .bind(player_uuid)
        .bind(ip.to_bits())
        .fetch_all(&mut self.conn)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Account(player_uuid.clone())),
        )
    }

    /// Gets *ANY* [`AllowlistEntry`]s assigned to a user that match the provided ip range, sorted by how recently they were used.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_allowlists_with_range(
        &mut self,
        player_uuid: &Uuid,
        ip: Ipv4Addr,
        mask: u8,
    ) -> Response<Vec<Allowlist>> {
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist WHERE uuid = $1 AND ($2 & (-1 << (32 - $3))) = (base_ip & (-1 << (32 - $3))) ORDER BY last_join DESC"
        )
        .bind(player_uuid)
        .bind(ip.to_bits())
        .bind(mask)
        .fetch_all(&mut self.conn)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Account(player_uuid.clone())),
        )
    }

    /// Bumps the `hits` field of an [`AllowlistEntry`].
    ///
    /// Also updates the `last_joined` field to `Utc::now`.  
    /// Returns an [DriverError::Unreachable] if something *bad* happens.  
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn bump_allowlist(&mut self, entry: Allowlist) -> Response<()> {
        let query = sqlx::query(
            "UPDATE allowlist SET hits = $1, last_joined = $2 WHERE uuid = $3 AND base_ip = $4",
        )
        .bind(entry.hits + 1)
        .bind(Utc::now())
        .bind(entry.uuid)
        .bind(entry.base_ip)
        .execute(&mut self.conn)
        .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Broadens the network mask of an [`AllowlistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.  
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn broaden_allowlist_mask(&mut self, entry: Allowlist, new_mask: u8) -> Response<()> {
        let query = sqlx::query("UPDATE allowlist SET mask = $1 WHERE uuid = $2 AND base_ip = $3")
            .bind(new_mask)
            .bind(entry.uuid)
            .bind(entry.base_ip)
            .execute(&mut self.conn)
            .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Deletes an *existing* [`AllowlistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.  
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn delete_allowlist(&mut self, entry: Allowlist) -> Response<()> {
        let query =
            sqlx::query("DELETE FROM allowlist WHERE uuid = $1 AND base_ip = $2 AND mask = $3")
                .bind(entry.uuid)
                .bind(entry.base_ip)
                .bind(entry.mask)
                .execute(&mut self.conn)
                .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Returns all [`BLacklistEntry`] that match the given IP address.
    ///
    /// Returns an [`base::NotFoundError::BlacklistEntry`] wrapped inside a [`DriverError::DatabaseError`] if an entry with the given IP Address can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_blacklists(&mut self, ip: Ipv4Addr) -> Response<Vec<Blacklist>> {
        let query = sqlx::query_as::<_,Blacklist>(
            "SELECT * FROM blacklist WHERE ($1 & (-1 << (32 - mask))) = (base_ip & (-1 << (32 - mask))) ORDER BY hits DESC"
        )
        .bind(ip.to_bits())
        .fetch_all(&mut self.conn)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::BlacklistEntry),
        )
    }

    /// Returns all [`BLacklistEntry`] that match the given IP range.
    ///
    /// Returns an [`base::NotFoundError::BlacklistEntry`] wrapped inside a [`DriverError::DatabaseError`] if an entry with the given IP Address can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_blacklists_with_range(
        &mut self,
        ip: Ipv4Addr,
        mask: u8,
    ) -> Response<Vec<Blacklist>> {
        let query = sqlx::query_as::<_,Blacklist>(
            "SELECT * FROM blacklist WHERE ($1 & (-1 << (32 - $2))) = (base_ip & (-1 << (32 - $2))) ORDER BY hits DESC"
        )
        .bind(ip.to_bits())
        .bind(mask)
        .fetch_all(&mut self.conn)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::BlacklistEntry),
        )
    }

    /// Creates an [`BlacklistEntry`] given its IP address and [`BanActor`], returning the BlacklistEntry.
    ///
    /// ### Note: This function doesn't check for matches when inserting the new entry. Please check if a match already exists with [`DataSource::get_blacklists`] or [`DataSource::get_blacklists_with_range`] before creating a new entry.
    /// Returns an [`DriverError::DuplicateKeyInsertion`] if an entry with that IP address already exists.
    #[tracing::instrument(skip(ip))]
    async fn create_blacklist(&mut self, ip: Ipv4Addr, actor: BanActor) -> Response<Blacklist> {
        let query = sqlx::query_as::<_, Blacklist>(
            "INSERT INTO blacklist (base_ip, mask, created_at, actor, hits) VALUES ($1, $2, $3, $4, $5) RETURNING *"
        )
        .bind(ip.to_bits())
        .bind(32)
        .bind(Utc::now())
        .bind(Json(actor))
        .bind(1)
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Bumps the `hits` field of an [`BlacklistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.  
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn bump_blacklist(&mut self, entry: Blacklist) -> Response<()> {
        let query = sqlx::query("UPDATE blacklist SET hits = $1 WHERE base_ip = $2 AND mask = $3")
            .bind(entry.hits + 1)
            .bind(entry.base_ip)
            .bind(entry.mask)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Broadens the network mask of an [`BlacklistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.  
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    async fn broaden_blacklist_mask(&mut self, entry: Blacklist, new_mask: u8) -> Response<()> {
        let query = sqlx::query("UPDATE blacklist SET mask = $1 WHERE base_ip = $2 AND mask = $3")
            .bind(new_mask)
            .bind(entry.base_ip)
            .bind(entry.mask)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Deletes an *existing* [`BlacklistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.  
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    async fn delete_blacklist(&mut self, entry: Blacklist) -> Response<()> {
        let query = sqlx::query("DELETE FROM blacklist WHERE base_ip = $1 AND mask = $2")
            .bind(entry.base_ip)
            .bind(entry.mask)
            .execute(&mut self.conn)
            .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Creates an [`Server`] returning the created server if it succeeds.
    ///
    /// Returns [`DriverError::DuplicateKeyInsertion`] if an server with said name already exists.
    #[tracing::instrument]
    async fn create_server(&mut self, stub: data::stub::ServerStub) -> Response<Server> {
        let query = sqlx::query_as::<_, Server>("INSERT INTO servers (uuid, name, supported_versions, current_modpack, online, players) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *")
            .bind(Uuid::new_v4())
            .bind(stub.name)
            .bind(Json(stub.supported_versions))
            .bind(Json(stub.current_modpack))
            .bind(Json(true))
            .bind("[]")
	    .fetch_one(&mut self.conn).await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Deletes an [`Server`] given its uuid, returning the deleted value on success.
    ///
    /// Returns an [`base::NotFoundError::Server`] wrapped inside a [`DriverError::DatabaseError`] if an server with the given uuid can't be found.
    #[tracing::instrument]
    async fn delete_server(&mut self, server_uuid: &uuid::Uuid) -> Response<Server> {
        let query = sqlx::query_as::<_, Server>("DELETE FROM servers WHERE uuid = ? RETURNING *")
            .bind(server_uuid)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Server),
        )
    }

    /// Gets an [`Server`] given its uuid.
    ///
    /// Returns an [`base::NotFoundError::Server`] wrapped inside a [`DriverError::DatabaseError`] if an server with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_server(&mut self, server_uuid: &uuid::Uuid) -> Response<Server> {
        let query = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE uuid = ?")
            .bind(server_uuid)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Server),
        )
    }

    /// Gets an [`Server`] given its name.
    ///
    /// Returns an [`base::NotFoundError::Server`] wrapped inside a [`DriverError::DatabaseError`] if an server with the given name can't be found.
    #[tracing::instrument]
    async fn get_server_by_name(&mut self, name: String) -> Response<Server> {
        let query = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE name = ?")
            .bind(name)
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Server),
        )
    }

    /// Adds an [`User`] to an [`Server`] if it wasn't already there, returning an [`data::result::ServerJoin`] if the user was added successfully.
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if either [`User`] or [`Server`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    async fn join_server(
        &mut self,
        server_uuid: &uuid::Uuid,
        player_uuid: &uuid::Uuid,
    ) -> Response<ServerJoin> {
        let _ = self.get_user_by_uuid(player_uuid).await?;
        let mut server = self.get_server(server_uuid).await?;

        if !server.players.contains(player_uuid) {
            server.players.push(player_uuid.clone());
            let query = sqlx::query("UPDATE servers SET players = $1 WHERE uuid = $2")
                .bind(Json(server.players))
                .bind(server_uuid)
                .execute(&mut self.conn)
                .await;

            map_or_log(query, DriverError::Unreachable)?;
        }

        if let Some(viewport) = self.get_viewport(player_uuid, server_uuid).await.ok() {
            Ok(ServerJoin::Resume(viewport))
        } else {
            Ok(ServerJoin::FirstJoin)
        }
    }

    /// Removes an [`User`] to an [`Server`] if it wasn't already there, returning an [`data::result::ServerLeave`] if the user was removed successfully.
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if either [`User`] or [`Server`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    async fn leave_server(
        &mut self,
        server_uuid: &uuid::Uuid,
        player_uuid: &uuid::Uuid,
    ) -> Response<ServerLeave> {
        let _ = self.get_user_by_uuid(player_uuid).await?;
        let mut server = self.get_server(server_uuid).await?;

        if !server.players.contains(player_uuid) {
            Ok(ServerLeave::NotJoined)
        } else {
            server.players.retain(|x| x != player_uuid);
            let query = sqlx::query("UPDATE servers SET players = $1 WHERE uuid = $2")
                .bind(Json(server.players))
                .bind(server_uuid)
                .execute(&mut self.conn)
                .await;

            map_or_log(
                query.map(|_| ServerLeave::Accepted),
                DriverError::Unreachable,
            )
        }
    }

    /// Updates an [`User`]'s [`Viewport`] for a given [`Server`], returning the updated [`Viewport`].
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if either [`User`] or [`Server`] don't exist.
    /// - [`base::NotFoundError::UserData`] if the [`UserData`] for the following User/Server pair didn't exist.
    #[tracing::instrument]
    async fn update_viewport(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
        viewport: data::Viewport,
    ) -> Response<Viewport> {
        let _ = self.get_user_by_uuid(player_uuid).await?;
        let _ = self.get_server(server_uuid).await?;

        let query = sqlx::query_as::<_,SaveData>(
            "UPDATE savedata SET viewport = $1 WHERE player_uuid = $2 AND server_uuid = $3 RETURNING *"
        )
        .bind(Json(viewport))
        .bind(player_uuid)
        .bind(server_uuid)
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(
            query.map(|x| x.viewport.0),
            DriverError::DatabaseError(base::NotFoundError::UserData {
                server_uuid: server_uuid.clone(),
                player_uuid: player_uuid.clone(),
            }),
        )
    }

    /// Gets an [`User`]'s [`Viewport`] for a given [`Server`].
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if either [`User`] or [`Server`] don't exist.
    /// - [`base::NotFoundError::UserData`] if the [`UserData`] for the following User/Server pair didn't exist.
    async fn get_viewport(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
    ) -> Response<Viewport> {
        let _ = self.get_user_by_uuid(player_uuid).await?;
        let _ = self.get_server(server_uuid).await?;

        let query = sqlx::query_as::<_, SaveData>(
            "SELECT * FROM savedata WHERE player_uuid = $1 AND server_uuid = $2",
        )
        .bind(player_uuid)
        .bind(server_uuid)
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(
            query.map(|x| x.viewport.0),
            DriverError::DatabaseError(base::NotFoundError::UserData {
                server_uuid: server_uuid.clone(),
                player_uuid: player_uuid.clone(),
            }),
        )
    }

    /// Updates an [`User`]'s playtime for a given [`Server`].
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if either [`User`] or [`Server`] don't exist.
    /// - [`base::NotFoundError::UserData`] if the [`UserData`] for the following User/Server pair didn't exist.
    #[tracing::instrument]
    async fn update_playtime(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
        new_duration: Duration,
    ) -> Response<()> {
        let _ = self.get_user_by_uuid(player_uuid).await?;
        let _ = self.get_server(server_uuid).await?;

        let query = sqlx::query_as::<_, SaveData>(
            "UPDATE savedata SET playtime = $1 WHERE player_uuid = $2 AND server_uuid = $3 RETURNING *"
        )
        .bind(Json(new_duration))
        .bind(player_uuid)
        .bind(server_uuid)
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(
            query.map(|_| ()),
            DriverError::DatabaseError(base::NotFoundError::UserData {
                server_uuid: server_uuid.clone(),
                player_uuid: player_uuid.clone(),
            }),
        )
    }

    /// Gets an [`User`]'s playtime for a given [`Server`]. Returns a [`std::time::Duration`] representing the current playtime.
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if either [`User`] or [`Server`] don't exist.
    /// - [`base::NotFoundError::UserData`] if the [`UserData`] for the following User/Server pair didn't exist.
    #[tracing::instrument]
    async fn get_playtime(
        &mut self,
        player_uuid: &uuid::Uuid,
        server_uuid: &uuid::Uuid,
    ) -> Response<time::Duration> {
        let _ = self.get_user_by_uuid(player_uuid).await?;
        let _ = self.get_server(server_uuid).await?;

        let query = sqlx::query_as::<_, SaveData>(
            "SELECT * FROM savedata WHERE player_uuid = $1 AND server_uuid = $2",
        )
        .bind(player_uuid)
        .bind(server_uuid)
        .fetch_one(&mut self.conn)
        .await;

        map_or_log(
            query.map(|x| x.playtime.0),
            DriverError::DatabaseError(base::NotFoundError::UserData {
                server_uuid: server_uuid.clone(),
                player_uuid: player_uuid.clone(),
            }),
        )
    }

    /// Adds an [`Pronoun`] for an [`User`].
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    async fn add_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        pronoun: data::Pronoun,
    ) -> Response<Vec<data::Pronoun>> {
        let mut pronouns = self.get_user_by_uuid(player_uuid).await?.pronouns;
        pronouns.push(pronoun);

        let query =
            sqlx::query_as::<_, User>("UPDATE users SET pronouns = $1 WHERE uuid = $2 RETURNING *")
                .bind(Json(pronouns))
                .bind(player_uuid)
                .fetch_one(&mut self.conn)
                .await;

        map_or_log(query.map(|x| x.pronouns.0), DriverError::Unreachable)
    }

    /// Removes an [`Pronoun`] for an [`User`].
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    async fn remove_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        pronoun: data::Pronoun,
    ) -> Response<Vec<data::Pronoun>> {
        let mut pronouns = self.get_user_by_uuid(player_uuid).await?.pronouns;
        pronouns.retain(|x| x.pronoun != pronoun.pronoun);

        let query =
            sqlx::query_as::<_, User>("UPDATE users SET pronouns = $1 WHERE uuid = $2 RETURNING *")
                .bind(Json(pronouns))
                .bind(player_uuid)
                .fetch_one(&mut self.conn)
                .await;

        map_or_log(query.map(|x| x.pronouns.0), DriverError::Unreachable)
    }

    /// Updates an existing [`Pronoun`] for an [`User`].
    /// 
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    async fn update_pronoun(
        &mut self,
        player_uuid: &uuid::Uuid,
        old: &data::Pronoun,
        new: data::Pronoun,
    ) -> Response<Vec<data::Pronoun>> {
        let mut pronouns = self.get_user_by_uuid(player_uuid).await?.pronouns;
        pronouns.retain(|x| x.pronoun != old.pronoun);
        pronouns.push(new);

        let query =
            sqlx::query_as::<_, User>("UPDATE users SET pronouns = $1 WHERE uuid = $2 RETURNING *")
                .bind(Json(pronouns))
                .bind(player_uuid)
                .fetch_one(&mut self.conn)
                .await;

        map_or_log(query.map(|x| x.pronouns.0), DriverError::Unreachable)
    }

    /// Creates a [`SaveData`] for an [`User`] / [`Server`] pair.
    ///
    /// Returns:
    /// - [`DriverError::DuplicateKeyInsertion`] if that user/server pair already existed.
    #[tracing::instrument]
    async fn create_savedata(
        &mut self,
        player_uuid: &Uuid,
        server_uuid: &Uuid,
    ) -> Response<SaveData> {
        let user = self.get_user_by_uuid(player_uuid).await?;
        let _ = self.get_server(server_uuid).await?;

        let query = sqlx::query_as::<_, SaveData>("INSERT INTO savedata (server_uuid, player_uuid, playtime, viewport) VALUES ($1, $2, $3, $4) RETURNING *")
            .bind(server_uuid)
            .bind(player_uuid)
            .bind(Json(time::Duration::ZERO))
            .bind(Json(Viewport::default()))
            .fetch_one(&mut self.conn)
            .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }
}
