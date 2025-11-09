/*
 * Playtime Tracking Actor
 */

use std::collections::HashMap;

use chrono::{DateTime, Duration, TimeDelta, Utc};
use uuid::Uuid;

use super::prelude::*;

pub struct PlaytimeA {
    profile_id: Option<Uuid>,
    times: HashMap<Uuid, Tracker>,
    database_hnd: DatabaseActorHandle,
}

#[derive(Debug)]
struct Tracker {
    last: Option<DateTime<Utc>>,
    running_total: Duration,
}

impl Tracker {
    fn new() -> Self {
        Self {
            last: Some(Utc::now()),
            running_total: TimeDelta::zero(),
        }
    }

    fn lap(&mut self) -> Duration {
        let now = Utc::now();
        let prev = self.last.take().unwrap_or(now);

        let current_lap = now - prev;
        self.running_total += current_lap;
        self.last = Some(now);
        current_lap
    }

    fn end(&mut self) {
        let now = Utc::now();
        let prev = self.last.take().unwrap_or(now);

        let current_lap = now - prev;
        self.running_total += current_lap;
    }
}

impl PlaytimeA {
    fn start(&mut self, server_id: Uuid) {
        let entry = self.times.insert(server_id, Tracker::new());
        debug!(
            "[a:Playtime({:?})] Event:Start({}) RECV | state={:?}",
            self.profile_id, server_id, entry
        );
    }

    fn lap(&mut self, server_id: Uuid) {
        let entry = self.times.entry(server_id).or_insert_with(Tracker::new);
        debug!(
            "[a:Playtime({:?})] Event:Lap({}) RECV | state={:?}",
            self.profile_id, server_id, entry
        );

        let lap = entry.lap();

        debug!(
            "[a:Playtime({:?})] Event:Lap({}) HANDLE | lap={}, state={:?}",
            self.profile_id, server_id, lap, entry
        );
    }

    fn end(&mut self, server_id: Uuid) {
        let entry = self.times.entry(server_id).or_insert_with(Tracker::new);
        debug!(
            "[a:Playtime({:?})] Event:End({}) RECV | state={:?}",
            self.profile_id, server_id, entry
        );

        entry.end();

        debug!(
            "[a:Playtime({:?})] Event:End({}) HANDLE | state={:?}",
            self.profile_id, server_id, entry
        );
    }

    fn get(&mut self, server_id: Uuid) -> Duration {
        let entry = self.times.entry(server_id).or_insert_with(Tracker::new);
        debug!(
            "[a:Playtime({:?})] Event:Get({}) RECV | state={:?}",
            self.profile_id, server_id, entry
        );
        entry.running_total
    }

    fn promote(&mut self, profile_id: Uuid) {
        debug!(
            "[a:Playtime({:?})] Event:Promote RECV | profile_id={}",
            self.profile_id, profile_id
        );
        self.profile_id = Some(profile_id);
        debug!("[a:Playtime({:?})] Event:Promote HANDLE ", self.profile_id);
    }
}

pub enum PlaytimeCommand {
    Start(Uuid),
    Lap(Uuid),
    End(Uuid),
    Get(Uuid, RespCell<Duration>),
    Promote(Uuid),
}

pub struct PlaytimeActor {
    state: PlaytimeA,
    queue: mpsc::UnboundedReceiver<PlaytimeCommand>,
}

impl PlaytimeActor {
    pub fn spawn(
        profile_id: Option<Uuid>, database_hnd: DatabaseActorHandle,
    ) -> PlaytimeActorHandle {
        let (tx, rx) = mpsc::unbounded_channel();
        let actor = Self {
            state: PlaytimeA { profile_id, times: HashMap::new(), database_hnd },
            queue: rx,
        };

        tokio::spawn(async move { actor.run().await });

        PlaytimeActorHandle { queue: tx }
    }

    pub async fn run(mut self) {
        while let Some(cmd) = self.queue.recv().await {
            match cmd {
                PlaytimeCommand::Start(id) => self.state.start(id),
                PlaytimeCommand::Lap(id) => self.state.lap(id),
                PlaytimeCommand::End(id) => self.state.end(id),
                PlaytimeCommand::Get(id, res) => {
                    let k = self.state.get(id);
                    let _ = res.send(k);
                }
                PlaytimeCommand::Promote(id) => self.state.promote(id),
            }
        }
    }
}

impl Drop for PlaytimeActor {
    fn drop(&mut self) {
        if let Some(profile_id) = self.state.profile_id {
            for (server, value) in &self.state.times {
                self.state
                    .database_hnd
                    .increase_playtime(*server, profile_id, value.running_total);
            }
        }
    }
}

pub struct PlaytimeActorHandle {
    queue: mpsc::UnboundedSender<PlaytimeCommand>,
}

impl PlaytimeActorHandle {
    pub fn start(&self, server_id: Uuid) {
        notify_actor!(self.queue, PlaytimeCommand::Start(server_id));
    }

    pub fn lap(&self, server_id: Uuid) {
        notify_actor!(self.queue, PlaytimeCommand::Lap(server_id));
    }

    pub fn end(&self, server_id: Uuid) {
        notify_actor!(self.queue, PlaytimeCommand::End(server_id));
    }

    pub async fn get(&self, server_id: Uuid) -> Duration {
        ask_actor!(self.queue, PlaytimeCommand::Get(server_id));
    }

    pub fn promote(&self, profile_id: Uuid) {
        notify_actor!(self.queue, PlaytimeCommand::Promote(profile_id));
    }
}
