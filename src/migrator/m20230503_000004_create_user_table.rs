use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .col(ColumnDef::new(User::Uuid).uuid().not_null().primary_key())
                    .col(ColumnDef::new(User::JoinedAt).timestamp().not_null())
                    .col(ColumnDef::new(User::LinkedAt).timestamp())
                    .col(ColumnDef::new(User::LastSeen).timestamp())
                    .col(ColumnDef::new(User::Trust).string())
                    .col(ColumnDef::new(User::Referer).uuid())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum User {
    Table,
    Uuid,
    JoinedAt,
    LinkedAt,
    LastSeen,
    Trust,
    Referer,
}
