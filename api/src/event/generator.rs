use axum::async_trait;

use crate::event::EventKind;

use super::{Event, Module, ModuleCtx};

pub struct GeneratorModule {
    ctx: ModuleCtx,
}

#[async_trait]
impl Module for GeneratorModule {
    fn new(ctx: ModuleCtx) -> Self {
        GeneratorModule { ctx }
    }
    async fn run(&mut self) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let event = Event {
                        module: self.ctx.name.clone(),
                        inner: EventKind::PlayerRequestLink("3984dfa8-5b4f-3cf4-bbd1-1d497b1220ab".parse().unwrap(), "alikindsys".to_string()),
                    };
                    self.ctx.sender
                        .send(event)
                        .unwrap();
                },
            }
        }
    }
    async fn handle_event(&mut self, event: Event) -> anyhow::Result<()> {
        Ok(())
    }
}
