use std::time::Duration;

use serenity::all::{ChannelId, EditMessage, MessageId};
use tokio::time::Instant;

use super::{discord::DiscordActorHandle, prelude::*};

/*
 * Live updating message
 */

pub struct LiveMessageA {
    last: Instant,
    fail_count: u64,
    interval: Duration,
    change: Option<EditMessage>,
    message_id: MessageId,
    channel_id: ChannelId,
    delete_on_drop: bool,
    discord_hnd: DiscordActorHandle,
}

impl LiveMessageA {
    fn deadline(&self) -> Instant {
        self.last + self.interval
    }

    fn has_to_wait_for_deadline(&self) -> bool {
        self.deadline() > Instant::now()
    }

    fn get_backoff(&self) -> Instant {
        // Simple exponential backoff where it starts at one second and doubles per each failure.
        let pow = if self.fail_count == 0 {
            1
        } else {
            self.fail_count - 1
        };

        self.last + Duration::from_secs(std::cmp::min(1 << pow, 60))
    }

    async fn update_message(&mut self) {
        if let Some(change) = self.change.take() {
            if self
                .discord_hnd
                .edit_message(self.channel_id, self.message_id, change)
                .await
                .is_err()
            {
                self.fail_count += 1;
            } else {
                self.fail_count = 0;
            }

            self.last = Instant::now();
            debug!("[a:LiveMessageActor({})] Updated Message.", self.message_id);
        }
    }

    pub async fn submit_change(&mut self, change: EditMessage) {
        debug!("[a:LiveMessageActor({})] Event:SubmitChange RECV ", self.message_id);
        self.change = Some(change);
        if !self.has_to_wait_for_deadline() {
            self.update_message().await;
        }
    }

    pub async fn edit_instantly(&mut self, change: EditMessage) {
        debug!("[a:LiveMessageActor({})] Event:EditInstantly RECV ", self.message_id);
        self.change = Some(change);
        self.update_message().await;
    }
}

pub enum LiveMessageCommand {
    SubmitChange(EditMessage),
    EditInstantly(EditMessage),
}

pub struct LiveMessageActor {
    state: LiveMessageA,
    queue: mpsc::UnboundedReceiver<LiveMessageCommand>,
}

impl LiveMessageActor {
    pub fn spawn(
        interval: Duration, message_id: MessageId, channel_id: ChannelId, delete_on_drop: bool,
        discord_hnd: DiscordActorHandle,
    ) -> LiveMessageActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor = Self {
            state: LiveMessageA {
                last: Instant::now(),
                interval,
                change: None,
                message_id,
                channel_id,
                discord_hnd,
                delete_on_drop,
                fail_count: 0,
            },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        LiveMessageActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.queue.recv() => {
                    if let Some(cmd) = cmd {
                        match cmd {
                            LiveMessageCommand::SubmitChange(change) => self.state.submit_change(change).await,
                            LiveMessageCommand::EditInstantly(change) => self.state.edit_instantly(change).await,
                        }
                    } else {
                        return;
                    }
                }
                _ = tokio::time::sleep_until(self.state.deadline()) => {
                    self.state.update_message().await;
                }
                _ = tokio::time::sleep_until(self.state.get_backoff()), if self.state.fail_count > 0 => {
                    warn!("[a:LiveMessageActor({})] Running Exponential Backoff. Failures: {}.", self.state.message_id, self.state.fail_count);
                    self.state.update_message().await;
                }
            }
        }
    }
}

impl Drop for LiveMessageActor {
    fn drop(&mut self) {
        if self.state.delete_on_drop {
            self.state
                .discord_hnd
                .delete_message(self.state.channel_id, self.state.message_id);
        }
    }
}

#[derive(Clone)]
pub struct LiveMessageActorHandle {
    queue: mpsc::UnboundedSender<LiveMessageCommand>,
}

impl LiveMessageActorHandle {
    pub fn submit_change(&self, change: EditMessage) {
        notify_actor!(self.queue, LiveMessageCommand::SubmitChange(change));
    }

    pub fn edit_instantly(&self, change: EditMessage) {
        notify_actor!(self.queue, LiveMessageCommand::EditInstantly(change));
    }

    pub fn mock() -> (Self, mpsc::UnboundedReceiver<LiveMessageCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { queue: tx }, rx)
    }
}
