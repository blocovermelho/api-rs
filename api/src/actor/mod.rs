use tokio::sync::oneshot;

pub mod cidr;
pub mod database;
pub mod discord;
pub mod ip_notification;
pub mod livemessage;
pub mod mailbox;
pub mod new_connection;
pub mod playtime;
pub mod server_liveliness;
pub mod session;
pub mod single_use_token;
pub mod websocket;

pub type RespCell<T> = oneshot::Sender<T>;

#[macro_export]
macro_rules! ask_actor {
    ($queue:expr, $enum:ident::$variant:ident { $($field:ident : $value:expr),* $(,)?}) => {{
        let (tx, rx) = tokio::sync::oneshot::channel();
        $queue
            .send($enum::$variant{$($field: $value,)* tx})
            .expect("Dropped actors have no handles.");
        return rx.await.expect("Actors are well behaved.");
    }};

    ($queue:expr, $enum:ident::$variant:ident { $($field:ident),* $(,)?}) => {{
        let (tx, rx) = tokio::sync::oneshot::channel();
        $queue
            .send($enum::$variant{$($field,)* tx})
            .expect("Dropped actors have no handles.");
        return rx.await.expect("Actors are well behaved.");
    }};

    ($queue:expr, $enum:ident::$variant:ident($($value:expr),* $(,)?)) => {
        let (tx, rx) = tokio::sync::oneshot::channel();
        $queue
            .send($enum::$variant($($value,)* tx))
            .expect("Dropped actors have no handles.");
        return rx.await.expect("Actors are well behaved.");
    };
}

#[macro_export]
macro_rules! notify_actor {
    ($queue:expr, $enum:ident::$variant:ident { $($field:ident),* $(,)?}) => {{
        $queue
            .send($enum::$variant{$($field,)*})
            .expect("Dropped actors have no handles.");
    }};

    ($queue:expr, $enum:ident::$variant:ident { $($field:ident : $value:expr),* $(,)?}) => {{
        $queue
            .send($enum::$variant{$($field: $value,)*})
            .expect("Dropped actors have no handles.");
    }};

    ($queue:expr, $enum:ident::$variant:ident($($value:expr),* $(,)?)) => {
        $queue
            .send($enum::$variant($($value,)*))
            .expect("Dropped actors have no handles.");
    };


    ($queue:expr, $enum:ident::$variant:ident) => {
        $queue
            .send($enum::$variant)
            .expect("Dropped actors have no handles.");
    };
}

mod prelude {
    pub use tokio::sync::{
        mpsc::{self, WeakUnboundedSender},
        oneshot,
    };
    pub use tracing::{debug, info, trace, warn};

    pub use super::{database::DatabaseActorHandle, mailbox::MailboxCommand, RespCell};

    pub type WeakMailboxSender = mpsc::WeakUnboundedSender<MailboxCommand>;

    pub use crate::{ask_actor, notify_actor};
}
