use core::time;
use std::{collections::HashMap, fmt::Display, net::Ipv4Addr, path::PathBuf};

use chrono::{Timelike, Utc};
use sqlx::{query_as, sqlite::SqliteConnectOptions, types::Json, Pool, SqlitePool};
use tracing::error;
use uuid::{NoContext, Timestamp, Uuid};

use super::err::{base, DriverError, Response};
use crate::{
    core::{
        types::{
            enums::ConnectionData,
            structs::stub::{GameServerStub, ProfileStub},
        },
        utils::generation::server_token,
    },
    db::{
        data::{
            self, result::PlaytimeEntry, Account, Allowlist, BanIssuer, Blacklist, Connection,
            Profile, SaveData, Server, ServerV2, Token, User,
        },
        interface::DataSource,
    },
};

#[derive(Debug)]
pub struct Sqlite(pub Pool<sqlx::Sqlite>);

impl From<Pool<sqlx::Sqlite>> for Sqlite {
    fn from(value: Pool<sqlx::Sqlite>) -> Self {
        Self(value)
    }
}

impl Sqlite {
    pub async fn run_migrations(&self) {
        sqlx::migrate!("src/db/migrations")
            .run(&self.0)
            .await
            .unwrap();
    }

    pub async fn new(path: &PathBuf) -> Self {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);

        SqlitePool::connect_with(options).await.unwrap().into()
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

#[async_trait::async_trait]
impl DataSource for Sqlite {
    /// Gets an [User] by its Uuid.
    ///
    /// Returns an [`base::NotFoundError::User`] wrapped inside a [`DriverError::DatabaseError`] if a user with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_user_by_uuid(&self, uuid: &uuid::Uuid) -> Response<User> {
        let query = sqlx::query_as::<_, User>("SELECT * FROM users WHERE uuid = ?")
            .bind(uuid)
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::User(*uuid)))
    }

    /// Gets the [Uuid]s for all currently registered users.
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function only returns Uuids, and we currently don't have enough players for that to be a concern.
    async fn get_all_users(&self) -> Response<Vec<Uuid>> {
        let query = sqlx::query_scalar::<_, Uuid>("SELECT uuid FROM users")
            .fetch_all(&self.0)
            .await;
        map_or_log(query, DriverError::Unreachable)
    }

    /// Gets an [`Account`] retuning the Account if it succeds.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_account(&self, uuid: &Uuid) -> Response<Account> {
        let query = sqlx::query_as::<_, Account>("SELECT * FROM accounts WHERE uuid = ?")
            .bind(uuid)
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Account(*uuid)))
    }

    /// Gets the [Uuid]s for all currently registered accounts.
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function only returns Uuids, and we currently don't have enough players for that to be a concern.
    async fn get_all_accounts(&self) -> Response<Vec<Uuid>> {
        let query = sqlx::query_scalar::<_, Uuid>("SELECT uuid FROM accounts")
            .fetch_all(&self.0)
            .await;
        map_or_log(query, DriverError::Unreachable)
    }

    async fn upcast_profile(&self, user: User, account: Account) -> Response<Profile> {
        let stub = ProfileStub {
            username: user.username,
            discord_id: user.discord_id,
            password: account.password,
        };

        // Create a new profile.
        let profile = self.create_profile(stub, Some(user.created_at)).await?;

        // Upcast the allowlists
        let mut tx = self.0.begin().await.unwrap();
        let old_allowlist_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM allowlist WHERE uuid = ?")
                .bind(user.uuid)
                .fetch_one(&mut *tx)
                .await?;

        let new_allowlists = sqlx::query::<_>("INSERT INTO allowlist_v2 (uuid, base_ip, mask, last_join, hits) SELECT $1, base_ip, mask, last_join, hits FROM allowlist WHERE uuid = $2")
            .bind(profile.uuid)
            .bind(user.uuid)
            .execute(&mut *tx).await?;

        if old_allowlist_count == new_allowlists.rows_affected() as i64 {
            sqlx::query::<_>("DELETE FROM allowlist WHERE uuid = ?")
                .bind(user.uuid)
                .execute(&mut *tx)
                .await?;
        } else {
            tx.rollback().await?;
            return Err(DriverError::Generic("Allowlist Migration Mismatch".into()));
        }

        tx.commit().await?;

        Ok(profile)
    }

    /// Creates a new [`Profile`]
    ///
    /// Returns [`DriverError::DuplicateKeyInsertion`] if an profile with the provided username already exists.
    async fn create_profile(
        &self, stub: ProfileStub, when: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Response<Profile> {
        let time = when.unwrap_or_else(Utc::now);
        let id = Uuid::new_v7(Timestamp::from_unix(
            NoContext,
            time.timestamp().try_into().unwrap_or_default(),
            time.nanosecond(),
        ));

        let query = sqlx::query_as::<_, Profile>("INSERT INTO profiles (uuid, username, discord_id, password) VALUES ($1, $2, $3, $4) RETURNING *")
            .bind(id)
            .bind(stub.username)
            .bind(stub.discord_id)
            .bind(stub.password)
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Gets an [`Profile`] based on its name
    ///
    /// **Note:** This is the *prefered* way to get an profile.
    /// Getting a profile based on its uuid is still available for convenience.
    ///
    /// The workflow now involves asking the server for a profile based on its username and
    /// keeping the returned Profile's uuid for doing changes to it.
    ///
    /// **WARNING:** UUIDS are no longer derived on the username as they once were before.
    ///
    /// Returns an [`base::NotFoundError::Profile`] if an profile with the given username can't be found.
    async fn get_profile(&self, username: String) -> Response<Profile> {
        let query = sqlx::query_as::<_, Profile>("SELECT * FROM profiles WHERE username = ?")
            .bind(username.clone())
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Profile(username)))
    }

    /// Gets an [`Profile`] based on its id
    ///
    /// **WARNING:** UUIDS are no longer derived on the username as they once were before.
    ///
    /// Returns an [`base::NotFoundError::User`] if an profile with the given uuid can't be found.
    async fn get_profile_by_id(&self, profile_uuid: &Uuid) -> Response<Profile> {
        let query = sqlx::query_as::<_, Profile>("SELECT * FROM profiles WHERE uuid = ?")
            .bind(profile_uuid)
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::User(*profile_uuid)))
    }

    async fn get_profiles_by_discord_id(&self, discord_id: String) -> Response<Vec<Profile>> {
        let query = sqlx::query_as::<_, Profile>("SELECT * FROM profiles WHERE discord_id = ?")
            .bind(discord_id)
            .fetch_all(&self.0)
            .await
            .unwrap_or_default();
        Ok(query)
    }

    async fn get_all_profiles(&self) -> Response<Vec<String>> {
        let query = sqlx::query_scalar("SELECT username FROM profiles")
            .fetch_all(&self.0)
            .await
            .unwrap_or_default();
        Ok(query)
    }

    /// Deletes an [`Profile`] based on its id
    ///
    /// **WARNING:** UUIDS are no longer derived on the username as they once were before.
    ///
    /// Returns an [`base::NotFoundError::User`] if an profile with the given uuid can't be found.
    async fn delete_profile(&self, profile_uuid: &Uuid) -> Response<Profile> {
        let query = sqlx::query_as::<_, Profile>("DELETE FROM profiles WHERE uuid = ? RETURNING *")
            .bind(profile_uuid)
            .fetch_one(&self.0)
            .await;
        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::User(*profile_uuid)))
    }

    /// Updates an [`Account`]'s password..
    ///
    /// ### Warning: This function expects a salted/hashed password since it *does not* do any hashing/salting itself.
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument(skip(password))]
    async fn update_password(&self, player_uuid: &uuid::Uuid, password: String) -> Response<()> {
        let query = sqlx::query("UPDATE profiles SET password = $1 WHERE uuid = $2")
            .bind(password)
            .bind(player_uuid)
            .execute(&self.0)
            .await;

        map_or_log(
            query.map(|_| ()),
            DriverError::DatabaseError(base::NotFoundError::Account(*player_uuid)),
        )
    }

    async fn update_username(&self, profile_uuid: &Uuid, new_username: String) -> Response<()> {
        let query = sqlx::query("UPDATE profiles SET username = $1 WHERE uuid = $2")
            .bind(new_username)
            .bind(profile_uuid)
            .execute(&self.0)
            .await;

        map_or_log(
            query.map(|_| ()),
            DriverError::DatabaseError(base::NotFoundError::Account(*profile_uuid)),
        )
    }

    /// Deletes an [`Account`] given its uuid, returning the unit value on success.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument]
    async fn delete_account(&self, player_uuid: &uuid::Uuid) -> Response<()> {
        let query = sqlx::query("DELETE FROM accounts WHERE uuid == ?")
            .bind(player_uuid)
            .execute(&self.0)
            .await;

        map_or_log(
            query.map(|_| ()),
            DriverError::DatabaseError(base::NotFoundError::Account(*player_uuid)),
        )
    }

    /// Creates an [`AllowlistEntry`] given its uuid and ip address, returning the AllowlistEntry.
    ///
    /// Returns an [`DriverError::DuplicateKeyInsertion`] if an account with the given uuid or ip address can be found.
    #[tracing::instrument(skip(ip))]
    async fn create_allowlist(&self, player_uuid: &Uuid, ip: Ipv4Addr) -> Response<Allowlist> {
        let _ = self.get_profile_by_id(player_uuid).await?;

        let query = sqlx::query_as::<_, Allowlist>(
            "INSERT INTO allowlist_v2 (uuid, base_ip, mask, last_join, hits) VALUES ($1, $2, $3, $4, $5) RETURNING *"
        )
        .bind(player_uuid)
        .bind(ip.to_bits())
        .bind(32)
        .bind(Utc::now())
        .bind(1)
        .fetch_one(&self.0)
        .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Gets *ALL* [`AllowlistEntry`]s assigned to a user, sorted by how recently they were used.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_allowlists(&self, player_uuid: &Uuid) -> Response<Vec<Allowlist>> {
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist_v2 WHERE uuid = $1 ORDER BY last_join DESC",
        )
        .bind(player_uuid)
        .fetch_all(&self.0)
        .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Account(*player_uuid)))
    }

    /// Gets *ANY* [`AllowlistEntry`]s assigned to a user that match the provided ip address, sorted by how recently they were used.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_allowlists_with_ip(
        &self, player_uuid: &Uuid, ip: Ipv4Addr,
    ) -> Response<Vec<Allowlist>> {
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist_v2 WHERE uuid = $1 AND ($2 & (-1 << (32 - mask))) = (base_ip & (-1 << (32 - mask))) ORDER BY last_join DESC"
        )
        .bind(player_uuid)
        .bind(ip.to_bits())
        .fetch_all(&self.0)
        .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Account(*player_uuid)))
    }

    /// Gets *ANY* [`AllowlistEntry`]s assigned to a user that match the provided ip range, sorted by how recently they were used.
    ///
    /// Returns an [`base::NotFoundError::Account`] wrapped inside a [`DriverError::DatabaseError`] if an account with the given uuid can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_allowlists_with_range(
        &self, player_uuid: &Uuid, ip: Ipv4Addr, mask: u8,
    ) -> Response<Vec<Allowlist>> {
        let query = sqlx::query_as::<_, Allowlist>(
            "SELECT * FROM allowlist_v2 WHERE uuid = $1 AND ($2 & (-1 << (32 - $3))) = (base_ip & (-1 << (32 - $3))) ORDER BY last_join DESC"
        )
        .bind(player_uuid)
        .bind(ip.to_bits())
        .bind(mask)
        .fetch_all(&self.0)
        .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Account(*player_uuid)))
    }

    /// Bumps the `hits` field of an [`AllowlistEntry`].
    ///
    /// Also updates the `last_join` field to `Utc::now`.
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn bump_allowlist(&self, entry: Allowlist) -> Response<()> {
        let query = sqlx::query(
            "UPDATE allowlist_v2 SET hits = $1, last_join = $2 WHERE uuid = $3 AND base_ip = $4",
        )
        .bind(entry.hits + 1)
        .bind(Utc::now())
        .bind(entry.uuid)
        .bind(entry.base_ip)
        .execute(&self.0)
        .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Broadens the network mask of an [`AllowlistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn broaden_allowlist_mask(&self, entry: Allowlist, new_mask: u8) -> Response<()> {
        let query =
            sqlx::query("UPDATE allowlist_v2 SET mask = $1 WHERE uuid = $2 AND base_ip = $3")
                .bind(new_mask)
                .bind(entry.uuid)
                .bind(entry.base_ip)
                .execute(&self.0)
                .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Deletes an *existing* [`AllowlistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn delete_allowlist(&self, entry: Allowlist) -> Response<()> {
        let query =
            sqlx::query("DELETE FROM allowlist_v2 WHERE uuid = $1 AND base_ip = $2 AND mask = $3")
                .bind(entry.uuid)
                .bind(entry.base_ip)
                .bind(entry.mask)
                .execute(&self.0)
                .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Returns all [`BLacklistEntry`] that match the given IP address.
    ///
    /// Returns an [`base::NotFoundError::BlacklistEntry`] wrapped inside a [`DriverError::DatabaseError`] if an entry with the given IP Address can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_blacklists(&self, ip: Ipv4Addr) -> Response<Vec<Blacklist>> {
        let query = sqlx::query_as::<_,Blacklist>(
            "SELECT * FROM blacklist WHERE ($1 & (-1 << (32 - mask))) = (base_ip & (-1 << (32 - mask))) ORDER BY hits DESC"
        )
        .bind(ip.to_bits())
        .fetch_all(&self.0)
        .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::BlacklistEntry))
    }

    /// Returns all [`BLacklistEntry`] that match the given IP range.
    ///
    /// Returns an [`base::NotFoundError::BlacklistEntry`] wrapped inside a [`DriverError::DatabaseError`] if an entry with the given IP Address can't be found.
    #[tracing::instrument(skip(ip))]
    async fn get_blacklists_with_range(&self, ip: Ipv4Addr, mask: u8) -> Response<Vec<Blacklist>> {
        let query = sqlx::query_as::<_,Blacklist>(
            "SELECT * FROM blacklist WHERE ($1 & (-1 << (32 - $2))) = (base_ip & (-1 << (32 - $2))) ORDER BY hits DESC"
        )
        .bind(ip.to_bits())
        .bind(mask)
        .fetch_all(&self.0)
        .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::BlacklistEntry))
    }

    /// Creates an [`BlacklistEntry`] given its IP address and [`BanActor`], returning the BlacklistEntry.
    ///
    /// ### Note: This function doesn't check for matches when inserting the new entry. Please check if a match already exists with [`DataSource::get_blacklists`] or [`DataSource::get_blacklists_with_range`] before creating a new entry.
    /// Returns an [`DriverError::DuplicateKeyInsertion`] if an entry with that IP address already exists.
    #[tracing::instrument(skip(ip))]
    async fn create_blacklist(&self, ip: Ipv4Addr, actor: BanIssuer) -> Response<Blacklist> {
        let query = sqlx::query_as::<_, Blacklist>(
            "INSERT INTO blacklist (base_ip, mask, created_at, actor, hits) VALUES ($1, $2, $3, $4, $5) RETURNING *"
        )
        .bind(ip.to_bits())
        .bind(32)
        .bind(Utc::now())
        .bind(Json(actor))
        .bind(1)
        .fetch_one(&self.0)
        .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Bumps the `hits` field of an [`BlacklistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    #[tracing::instrument]
    async fn bump_blacklist(&self, entry: Blacklist) -> Response<()> {
        let query = sqlx::query("UPDATE blacklist SET hits = $1 WHERE base_ip = $2 AND mask = $3")
            .bind(entry.hits + 1)
            .bind(entry.base_ip)
            .bind(entry.mask)
            .execute(&self.0)
            .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Broadens the network mask of an [`BlacklistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    async fn broaden_blacklist_mask(&self, entry: Blacklist, new_mask: u8) -> Response<()> {
        let query = sqlx::query("UPDATE blacklist SET mask = $1 WHERE base_ip = $2 AND mask = $3")
            .bind(new_mask)
            .bind(entry.base_ip)
            .bind(entry.mask)
            .execute(&self.0)
            .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Deletes an *existing* [`BlacklistEntry`].
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function should be used for modifying already existing input.
    async fn delete_blacklist(&self, entry: Blacklist) -> Response<()> {
        let query = sqlx::query("DELETE FROM blacklist WHERE base_ip = $1 AND mask = $2")
            .bind(entry.base_ip)
            .bind(entry.mask)
            .execute(&self.0)
            .await;

        map_or_log(query.map(|_| ()), DriverError::Unreachable)
    }

    /// Creates an [`Server`] returning the created server if it succeeds.
    ///
    /// Returns [`DriverError::DuplicateKeyInsertion`] if an server with said name already exists.
    #[tracing::instrument]
    async fn create_server(&self, stub: GameServerStub) -> Response<ServerV2> {
        let query = sqlx::query_as::<_, ServerV2>("INSERT INTO server_v2 (uuid, name, versions, staff, game, max_players) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *")
            .bind(Uuid::now_v7())
            .bind(stub.name)
            .bind(Json(stub.versions))
            .bind(Json(stub.staff))
            .bind(stub.game)
            .bind(stub.max_players)
	    .fetch_one(&self.0).await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Deletes an [`ServerV2`] given its uuid, returning the deleted value on success.
    ///
    /// Returns an [`base::NotFoundError::Server`] wrapped inside a [`DriverError::DatabaseError`] if an server with the given uuid can't be found.
    #[tracing::instrument]
    async fn delete_server(&self, server_uuid: &uuid::Uuid) -> Response<ServerV2> {
        let query =
            sqlx::query_as::<_, ServerV2>("DELETE FROM server_v2 WHERE uuid = ? RETURNING *")
                .bind(server_uuid)
                .fetch_one(&self.0)
                .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Server))
    }

    /// Gets an [`Server`] given its uuid.
    ///
    /// Returns an [`base::NotFoundError::Server`] wrapped inside a [`DriverError::DatabaseError`] if an server with the given uuid can't be found.
    #[tracing::instrument]
    async fn get_server_v1(&self, server_uuid: &uuid::Uuid) -> Response<Server> {
        let query = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE uuid = ?")
            .bind(server_uuid)
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Server))
    }

    async fn get_server(&self, server_uuid: &uuid::Uuid) -> Response<ServerV2> {
        let query = sqlx::query_as::<_, ServerV2>("SELECT * FROM server_v2 WHERE uuid = ?")
            .bind(server_uuid)
            .fetch_one(&self.0)
            .await;
        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Server))
    }

    async fn upcast_server_v1(&self, v1: Server) -> Response<ServerV2> {
        let mut tx = self.0.begin().await.unwrap();
        let new_server = sqlx::query::<_>("INSERT INTO server_v2 (uuid, name, versions, game, max_players, staff) SELECT uuid, name, supported_versions, $1, $2, $3 FROM servers WHERE uuid = $4")
            .bind("Minecraft")
            .bind(20)
            .bind("[]")
            .bind(v1.uuid)
            .execute(&mut *tx).await?;

        if new_server.rows_affected() == 1 {
            // sqlx::query::<_>("DELETE FROM servers WHERE uuid = ?")
            //     .bind(v1.uuid)
            //     .execute(&mut *tx)
            //     .await?;
        } else {
            tx.rollback().await?;
            return Err(DriverError::Generic("Server Migration Mismatch".into()));
        }

        tx.commit().await?;

        let server = self.get_server(&v1.uuid).await?;

        Ok(server)
    }

    /// Gets the [Uuid]s for all currently registered servers.
    ///
    /// Returns an [DriverError::Unreachable] if something *bad* happens.
    /// ### Note: The use of unreachable is justified since this function only returns Uuids, and we currently don't have enough players for that to be a concern.
    async fn get_all_servers_v1(&self) -> Response<Vec<Uuid>> {
        let query = sqlx::query_scalar::<_, Uuid>("SELECT uuid FROM servers")
            .fetch_all(&self.0)
            .await;
        map_or_log(query, DriverError::Unreachable)
    }

    async fn get_all_servers_v2(&self) -> Response<Vec<Uuid>> {
        let query = sqlx::query_scalar::<_, Uuid>("SELECT uuid FROM server_v2")
            .fetch_all(&self.0)
            .await;
        map_or_log(query, DriverError::Unreachable)
    }

    async fn update_server_versions(
        &self, server_uuid: &Uuid, versions: Vec<String>,
    ) -> Response<ServerV2> {
        let query = sqlx::query_as::<_, ServerV2>(
            "UPDATE server_v2 SET versions = $1 WHERE uuid = $2 RETURNING *",
        )
        .bind(Json(versions))
        .bind(server_uuid)
        .fetch_one(&self.0)
        .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Server))
    }

    /// Gets an [`Server`] given its name.
    ///
    /// Returns an [`base::NotFoundError::Server`] wrapped inside a [`DriverError::DatabaseError`] if an server with the given name can't be found.
    #[tracing::instrument]
    async fn get_server_by_name(&self, name: String) -> Response<ServerV2> {
        let query = sqlx::query_as::<_, ServerV2>("SELECT * FROM server_v2 WHERE name = ?")
            .bind(name)
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Server))
    }

    /// Creates an new token with the given scopes replacing the existing one if it exists.
    async fn create_token(&self, server_uuid: &Uuid, scopes: Vec<String>) -> Response<String> {
        let _ = self.get_server(server_uuid).await?;

        let when = Utc::now();
        let token = server_token(server_uuid, &when);

        // Check if the server already has an token
        let query = if let Ok(Some(_)) =
            sqlx::query_scalar::<_, String>("SELECT token FROM tokens WHERE owner = $1")
                .bind(server_uuid)
                .fetch_optional(&self.0)
                .await
        {
            // Replace
            sqlx::query(
                "UPDATE tokens SET token = $1, scopes = $2, created_at = $3 WHERE owner = $4",
            )
            .bind(token.clone())
            .bind(Json(scopes))
            .bind(when)
            .bind(server_uuid)
            .execute(&self.0)
            .await
        } else {
            // Create new
            sqlx::query(
                "INSERT INTO tokens (token, owner, scopes, created_at) VALUES ($1, $2, $3, $4)",
            )
            .bind(token.clone())
            .bind(server_uuid)
            .bind(Json(scopes))
            .bind(when)
            .execute(&self.0)
            .await
        };

        query.map(|_| token).map_err(DriverError::SqlxError)
    }

    /// Regenerates a new token, keeping the same scopes that were granted on the old token.
    async fn reset_token(&self, server_uuid: &Uuid) -> Response<String> {
        let _ = self.get_server(server_uuid).await?;

        let when = Utc::now();
        let token = server_token(server_uuid, &when);
        if let Ok(Some(_)) =
            sqlx::query_scalar::<_, String>("SELECT token FROM tokens WHERE owner = $1")
                .bind(server_uuid)
                .fetch_optional(&self.0)
                .await
        {
            // Replace
            let query =
                sqlx::query("UPDATE tokens SET token = $1, created_at = $2 WHERE owner = $3")
                    .bind(token.clone())
                    .bind(when)
                    .bind(server_uuid)
                    .execute(&self.0)
                    .await;

            query.map(|_| token).map_err(DriverError::SqlxError)
        } else {
            Err(DriverError::DatabaseError(base::NotFoundError::TokenServer(*server_uuid)))
        }
    }

    /// Gets an [`Token`] based on the issued token.
    /// This is the only public api for obtaining existing tokens. There will *not* be a reverse-lookup for getting a token based on the server's uuid.
    async fn get_token(&self, token: String) -> Response<Token> {
        let query = sqlx::query_as::<_, Token>("SELECT * FROM tokens WHERE token = $1")
            .bind(token)
            .fetch_one(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Token))
    }

    /// Revokes an token from a server, deleting it and disallowing that server from acessing scope-protected routes.
    async fn revoke_token(&self, server_uuid: &Uuid) -> Response<()> {
        let _ = self.get_server(server_uuid).await?;
        if let Ok(Some(_)) =
            sqlx::query_scalar::<_, String>("SELECT token FROM tokens WHERE owner = $1")
                .bind(server_uuid)
                .fetch_optional(&self.0)
                .await
        {
            let query = sqlx::query("DELETE FROM tokens WHERE owner = $1")
                .bind(server_uuid)
                .execute(&self.0)
                .await;

            query.map(|_| ()).map_err(DriverError::SqlxError)
        } else {
            Err(DriverError::DatabaseError(base::NotFoundError::TokenServer(*server_uuid)))
        }
    }

    /// Gets an [`User`]'s playtime for a given [`Server`]. Returns a [`std::time::Duration`] representing the current playtime.
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if either [`User`] or [`Server`] don't exist.
    /// - [`base::NotFoundError::UserData`] if the [`UserData`] for the following User/Server pair didn't exist.
    #[tracing::instrument]
    #[allow(deprecated)]
    async fn get_playtime_v1(
        &self, player_uuid: &uuid::Uuid, server_uuid: &uuid::Uuid,
    ) -> Response<time::Duration> {
        let _ = self.get_user_by_uuid(player_uuid).await?;
        let _ = self.get_server(server_uuid).await?;

        let query = sqlx::query_as::<_, SaveData>(
            "SELECT * FROM savedata WHERE player_uuid = $1 AND server_uuid = $2",
        )
        .bind(player_uuid)
        .bind(server_uuid)
        .fetch_one(&self.0)
        .await;

        map_or_log(
            query.map(|x| x.playtime.0),
            DriverError::DatabaseError(base::NotFoundError::UserData {
                server_uuid: *server_uuid,
                player_uuid: *player_uuid,
            }),
        )
    }

    /// Gets all [`PlaytimeEntry`]s for a given [`Server`]
    ///
    /// Returns:
    /// - [base::NotFoundError] if the [`Server`] doesn't exist.
    /// - May return an empty list if no players have joined yet.
    async fn get_playtimes_v1(&self, server_uuid: &Uuid) -> Response<Vec<PlaytimeEntry>> {
        // TODO: Limit this query.
        let query = sqlx::query_as::<_, PlaytimeEntry>("SELECT username,player_uuid,playtime from savedata INNER JOIN users ON users.uuid = savedata.player_uuid WHERE server_uuid = $1")
	    .bind(server_uuid)
	    .fetch_all(&self.0)
	    .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::Server))
    }

    #[allow(deprecated)]
    async fn upcast_savedata(&self, data: SaveData) -> Response<Connection> {
        println!("[upcast_savedata] Got data.player : {}", &data.player_uuid);
        let u = self.get_user_by_uuid(&data.player_uuid).await?;
        println!("[upcast_savedata] Got user.uuid : {}", &u.uuid);
        let p = self.get_profile(u.username).await?;
        println!("[upcast_savedata] Got profile.uuid : {}", &p.uuid);

        if let Ok(existing) = self.get_connection(&p.uuid, "bv:playtime").await {
            println!("[upcast_savedata] Updating existing connection.");
            match ConnectionData::try_from((existing.kind.clone(), existing.data)).unwrap() {
                ConnectionData::Playtime(mut map) => {
                    map.insert(data.server_uuid, data.playtime.0);

                    self.update_connection(Connection {
                        data: serde_json::ser::to_string(&map).unwrap(),
                        ..existing
                    })
                    .await
                }
                _ => {
                    unreachable!();
                }
            }
        } else {
            println!("[upcast_savedata] Creating new connection.");
            let mut map = HashMap::new();
            map.insert(data.server_uuid, data.playtime.0);
            self.create_connection(Connection {
                profile: p.uuid,
                issuer: None,
                kind: "bv:playtime".into(),
                data: serde_json::ser::to_string(&map).unwrap(),
            })
            .await
        }
    }

    /// Adds an [`Pronoun`] for an [`User`].
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    #[allow(deprecated)]
    async fn add_pronoun(
        &self, player_uuid: &uuid::Uuid, pronoun: data::Pronoun,
    ) -> Response<Vec<data::Pronoun>> {
        let mut pronouns = self.get_user_by_uuid(player_uuid).await?.pronouns;
        pronouns.push(pronoun);

        let query =
            sqlx::query_as::<_, User>("UPDATE users SET pronouns = $1 WHERE uuid = $2 RETURNING *")
                .bind(Json(pronouns))
                .bind(player_uuid)
                .fetch_one(&self.0)
                .await;

        map_or_log(query.map(|x| x.pronouns.0), DriverError::Unreachable)
    }

    /// Removes an [`Pronoun`] for an [`User`].
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    #[allow(deprecated)]
    async fn remove_pronoun(
        &self, player_uuid: &uuid::Uuid, pronoun: data::Pronoun,
    ) -> Response<Vec<data::Pronoun>> {
        let mut pronouns = self.get_user_by_uuid(player_uuid).await?.pronouns;
        pronouns.retain(|x| x.pronoun != pronoun.pronoun);

        let query =
            sqlx::query_as::<_, User>("UPDATE users SET pronouns = $1 WHERE uuid = $2 RETURNING *")
                .bind(Json(pronouns))
                .bind(player_uuid)
                .fetch_one(&self.0)
                .await;

        map_or_log(query.map(|x| x.pronouns.0), DriverError::Unreachable)
    }

    /// Updates an existing [`Pronoun`] for an [`User`].
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`DriverError::Unreachable`] if something *bad* happened.
    #[tracing::instrument]
    #[allow(deprecated)]
    async fn update_pronoun(
        &self, player_uuid: &uuid::Uuid, old: &data::Pronoun, new: data::Pronoun,
    ) -> Response<Vec<data::Pronoun>> {
        let mut pronouns = self.get_user_by_uuid(player_uuid).await?.pronouns;
        pronouns.retain(|x| x.pronoun != old.pronoun);
        pronouns.push(new);

        let query =
            sqlx::query_as::<_, User>("UPDATE users SET pronouns = $1 WHERE uuid = $2 RETURNING *")
                .bind(Json(pronouns))
                .bind(player_uuid)
                .fetch_one(&self.0)
                .await;

        map_or_log(query.map(|x| x.pronouns.0), DriverError::Unreachable)
    }

    /// Creates a [`SaveData`] for an [`User`] / [`Server`] pair.
    ///
    /// Returns:
    /// - [`DriverError::DuplicateKeyInsertion`] if that user/server pair already existed.
    ///
    /// Gets all [`SaveData`]s for an [`User`].
    /// Useful for gathering all servers an user has joined.
    #[allow(deprecated)]
    async fn get_savedatas(&self, player_uuid: &Uuid) -> Response<Vec<SaveData>> {
        let _ = self.get_user_by_uuid(player_uuid).await?;

        let query = sqlx::query_as::<_, SaveData>("SELECT * FROM savedata WHERE player_uuid = $1")
            .bind(player_uuid)
            .fetch_all(&self.0)
            .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::User(*player_uuid)))
    }

    #[allow(deprecated)]
    async fn delete_savedatas(&self, player_uuid: &Uuid) -> Response<Vec<SaveData>> {
        let _ = self.get_user_by_uuid(player_uuid).await?;

        let query = sqlx::query_as::<_, SaveData>(
            "DELETE FROM savedata WHERE player_uuid = $1 RETURNING *",
        )
        .bind(player_uuid)
        .fetch_all(&self.0)
        .await;

        map_or_log(query, DriverError::DatabaseError(base::NotFoundError::User(*player_uuid)))
    }

    /// Creates a new [`Connection`].
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`DriverError::DuplicateKeyInsertion`] if that profile already has a connection with the same kind.
    async fn create_connection(&self, connection: Connection) -> Response<Connection> {
        let _ = self.get_profile_by_id(&connection.profile).await?;

        let query = sqlx::query_as::<_, Connection>(
            "INSERT INTO connections (profile, issuer, kind, data) VALUES ($1, $2, $3, $4) RETURNING *"
        )
        .bind(connection.profile)
        .bind(connection.issuer)
        .bind(connection.kind)
        .bind(connection.data)
        .fetch_one(&self.0)
        .await;

        map_or_log(query, DriverError::DuplicateKeyInsertion)
    }

    /// Gets an [`Connection`] from its kind and the profile who owns it
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`base::NotFoundError`] if the [`User`] don't have an [`Connection`] with that kind associated with it.
    async fn get_connection(&self, profile: &Uuid, kind: &str) -> Response<Connection> {
        let _ = self.get_profile_by_id(profile).await?;

        let query = sqlx::query_as::<_, Connection>(
            "SELECT * FROM connections WHERE profile = $1 AND kind = $2",
        )
        .bind(profile)
        .bind(kind)
        .fetch_one(&self.0)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Connection(*profile, kind.into())),
        )
    }

    /// Gets a list of all [`Connection`]s associated with a profile, or an empty list if none exist.
    ///
    /// Returns
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    async fn get_connections_by_profile(&self, profile: &Uuid) -> Response<Vec<Connection>> {
        let _ = self.get_profile_by_id(profile).await?;
        let query = sqlx::query_as::<_, Connection>("SELECT * FROM connections WHERE profile = $1")
            .bind(profile)
            .fetch_all(&self.0)
            .await
            .unwrap_or_default();

        Ok(query)
    }

    async fn get_connections_by_kind(&self, kind: &str) -> Response<Vec<Connection>> {
        let query = sqlx::query_as::<_, Connection>("SELECT * FROM connections WHERE kind = $1")
            .bind(kind)
            .fetch_all(&self.0)
            .await
            .unwrap_or_default();
        Ok(query)
    }

    /// Deletes an [`Connection`]
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`base::NotFoundError`] if the [`User`] don't have an [`Connection`] with that kind associated with it.
    #[allow(deprecated)]
    async fn delete_connection(
        &self, profile: &Uuid, connection_type: &str,
    ) -> Response<Connection> {
        let _ = self.get_user_by_uuid(profile).await?;

        let query = query_as::<_, Connection>(
            "DELETE FROM connections WHERE profile = $1 AND kind = $2 RETURNING *",
        )
        .bind(profile)
        .bind(connection_type)
        .fetch_one(&self.0)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Connection(
                *profile,
                connection_type.into(),
            )),
        )
    }

    // Updates an [`Connection`]
    ///
    /// Returns:
    /// - [`base::NotFoundError`] if the [`User`] don't exist.
    /// - [`base::NotFoundError`] if the [`User`] don't have an [`Connection`] with that kind associated with it.
    async fn update_connection(&self, connection: Connection) -> Response<Connection> {
        let _ = self.get_profile_by_id(&connection.profile).await?;

        let query = sqlx::query_as::<_, Connection>(
            "UPDATE connections SET data = $1 WHERE profile = $2 AND kind = $3 RETURNING *",
        )
        .bind(connection.data)
        .bind(connection.profile)
        .bind(connection.kind.clone())
        .fetch_one(&self.0)
        .await;

        map_or_log(
            query,
            DriverError::DatabaseError(base::NotFoundError::Connection(
                connection.profile,
                connection.kind,
            )),
        )
    }
}
