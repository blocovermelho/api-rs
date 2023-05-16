use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Server::Table)
                    .col(ColumnDef::new(Server::Id).uuid().primary_key())
                    .col(ColumnDef::new(Server::Name).string().not_null())
                    .col(
                        ColumnDef::new(Server::SupportedVersions)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Server::Ip).string().not_null())
                    .col(ColumnDef::new(Server::Modded).boolean().not_null())
                    .col(ColumnDef::new(Server::Modpacks).string().not_null())
                    .col(ColumnDef::new(Server::Multimap).boolean().not_null())
                    .col(ColumnDef::new(Server::Maps).string().not_null())
                    .col(ColumnDef::new(Server::PlayerCount).integer().not_null())
                    .col(ColumnDef::new(Server::MaxPlayers).integer().not_null())
                    .to_owned(),
            )
            .await
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Server::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Server {
    Table,
    Id,
    Name,
    SupportedVersions,
    Ip,
    Modded,
    Modpacks,
    Multimap,
    Maps,
    PlayerCount,
    MaxPlayers,
}
