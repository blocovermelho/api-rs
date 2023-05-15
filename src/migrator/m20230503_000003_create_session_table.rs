use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Session::Table)
                    .col(
                        ColumnDef::new(Session::Player)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Session::Pos).string().not_null())
                    .col(ColumnDef::new(Session::LookingAt).string().not_null())
                    .col(ColumnDef::new(Session::IpAddr).string().not_null())
                    .col(ColumnDef::new(Session::Server).string().not_null())
                    .col(ColumnDef::new(Session::ExpiresAt).timestamp().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Session::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
pub enum Session {
    Table,
    Player,
    Pos,
    LookingAt,
    IpAddr,
    Server,
    ExpiresAt,
}
