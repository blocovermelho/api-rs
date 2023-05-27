use sea_orm::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(EnumIter, DeriveActiveEnum, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(None)")]
pub enum TrustLevel {
    #[sea_orm(string_value = "Unlinked")]
    Unlinked,
    #[sea_orm(string_value = "Linked")]
    Linked,
    #[sea_orm(string_value = "Invited")]
    Invited,
    #[sea_orm(string_value = "Trusted")]
    Trusted,
}

#[derive(EnumIter, DeriveActiveEnum, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "String(None)")]
pub enum DiscordResponse {
    #[sea_orm(string_value = "ExternalAPIError")]
    ExternalAPIError,
    #[sea_orm(string_value = "NotInGuild")]
    NotInGuild,
    #[sea_orm(string_value = "Success")]
    Success,
}

pub mod modpacks {
    use sea_orm::{DeriveActiveEnum, EnumIter};
    use serde::{Deserialize, Serialize};

    #[derive(EnumIter, DeriveActiveEnum, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[sea_orm(rs_type = "String", db_type = "String(None)")]
    pub enum RequirementLevel {
        #[sea_orm(string_value = "Optional")]
        Optional,
        #[sea_orm(string_value = "Recommended")]
        Recommended,
        #[sea_orm(string_value = "Required")]
        Required,
    }
    #[derive(EnumIter, DeriveActiveEnum, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[sea_orm(rs_type = "String", db_type = "String(None)")]
    pub enum Modloader {
        #[sea_orm(string_value = "Quilt")]
        Quilt,
        #[sea_orm(string_value = "Fabric")]
        Fabric,
        #[sea_orm(string_value = "Forge")]
        Forge,
    }
}
