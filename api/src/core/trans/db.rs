use std::{collections::HashMap, sync::Arc};

// Transformations and ingress for databse datatypes
use chrono::TimeDelta;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    core::types::{enums::ConnectionData, structs::*},
    db::{
        data::{self as dbd},
        interface::{DataSource, NetworkProvider},
    },
};

const SESSION_LEASE: TimeDelta = TimeDelta::minutes(10);

impl From<dbd::Allowlist> for Session {
    fn from(val: dbd::Allowlist) -> Self {
        Self {
            profile: val.uuid,
            last_seen: val.last_join,
            expires_at: val.last_join + SESSION_LEASE,
            network: val.get_network(),
        }
    }
}
#[derive(Debug, Error)]
pub enum ProfileConversionError {
    #[error("No account found.")]
    NoAccountError,
    #[error("User hasn't yet linked a discord account.")]
    UnlinkedUserError,
    #[error("Couldn't find user from the given uuid.")]
    UnknownUUIDError,
}

#[async_trait::async_trait]
pub trait TryIngest<T, D: DataSource>: Sized {
    type Error;
    async fn try_ingest(value: T, source: Arc<D>) -> Result<Self, Self::Error>
    where
        D: 'async_trait;
}

#[async_trait::async_trait]
impl<D: DataSource> TryIngest<dbd::User, D> for Profile {
    type Error = ProfileConversionError;

    async fn try_ingest(value: dbd::User, source: Arc<D>) -> Result<Self, Self::Error>
    where
        D: 'async_trait,
    {
        let account = source
            .get_account(&value.uuid)
            .await
            .map_err(|_| ProfileConversionError::NoAccountError)?;

        Ok(Self {
            id: value.uuid,
            username: value.username,
            discord_id: value.discord_id,
            hash_password: account.password,
            connections: vec![],
            created_at: get_timestamp_from_uuid(&value.uuid, value.created_at),
            last_seen: account.current_join,
        })
    }
}

#[allow(clippy::as_conversions)]
fn get_timestamp_from_uuid(
    uuid: &Uuid, fallback: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    if let Some(timestamp) = uuid.get_timestamp() {
        let (secs, nsecs) = timestamp.to_unix();
        chrono::DateTime::from_timestamp(secs as i64, nsecs).unwrap()
    } else {
        fallback
    }
}

#[async_trait::async_trait]
impl<D: DataSource> TryIngest<dbd::Account, D> for Profile {
    type Error = ProfileConversionError;

    async fn try_ingest(value: dbd::Account, source: Arc<D>) -> Result<Self, Self::Error>
    where
        D: 'async_trait,
    {
        let user = source
            .get_user_by_uuid(&value.uuid)
            .await
            .map_err(|_| ProfileConversionError::UnlinkedUserError)?;

        Ok(Self {
            id: value.uuid,
            username: user.username,
            discord_id: user.discord_id,
            hash_password: value.password,
            connections: vec![],
            created_at: get_timestamp_from_uuid(&value.uuid, user.created_at),
            last_seen: value.current_join,
        })
    }
}
#[derive(Debug, Error)]
pub enum ConnectionConversionError {
    #[error("The type of the connection is not known.")]
    UnknownTypeError,
    #[error("The profile for this connection does not exist.")]
    UnknownProfile,
    #[error("The issuer for this connection does not exit.")]
    UnknownIssuer,
    #[error("The Mojang UUID for this account is invalid.")]
    InvalidMojangUUIDError,
}

#[async_trait::async_trait]
impl<D: DataSource> TryIngest<dbd::Connection, D> for Connection {
    type Error = ConnectionConversionError;

    async fn try_ingest(value: dbd::Connection, source: Arc<D>) -> Result<Self, Self::Error>
    where
        D: 'async_trait,
    {
        let extra = ConnectionData::try_from((value.kind, value.data))?;
        let user = source
            .get_user_by_uuid(&value.profile)
            .await
            .map_err(|_| ConnectionConversionError::UnknownProfile)?;

        let profile = Profile::try_ingest(user, source)
            .await
            .map_err(|_| ConnectionConversionError::UnknownProfile)?;

        Ok(Self { issuer: value.issuer, profile, extra })
    }
}

impl TryFrom<(String, String)> for ConnectionData {
    type Error = ConnectionConversionError;

    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        match value.0.as_str() {
            "bv:bedrock_link" => Ok(Self::BedrockUsername(value.1.trim().to_owned())),
            "bv:mojang_uuid" => {
                if let Ok(uuid) = value.1.parse() {
                    Ok(Self::MojangUuid(uuid))
                } else {
                    Err(ConnectionConversionError::InvalidMojangUUIDError)
                }
            }
            "bv:playtime" => {
                if let Ok(parse) = serde_json::de::from_str(&value.1) {
                    Ok(Self::Playtime(parse))
                } else {
                    Ok(Self::Playtime(HashMap::new()))
                }
            }
            _ => Err(ConnectionConversionError::UnknownTypeError),
        }
    }
}

impl From<Connection> for dbd::Connection {
    fn from(value: Connection) -> Self {
        let (kind, data) = match value.extra {
            ConnectionData::BedrockUsername(username) => ("bv:bedrock_link", username),
            ConnectionData::MojangUuid(uuid) => ("bv:mojang_uuid", uuid.into()),
            ConnectionData::Playtime(map) => (
                "bv:playtime",
                serde_json::ser::to_string(&map).unwrap_or_else(|_| String::from("{}")),
            ),
        };

        Self {
            profile: value.profile.id,
            issuer: value.issuer,
            kind: kind.to_string(),
            data,
        }
    }
}
