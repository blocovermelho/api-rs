use sea_orm::FromJsonQueryResult;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, FromJsonQueryResult, Serialize, Deserialize)]
pub struct LookVector {
    yaw: String,
    pitch: String,
}
