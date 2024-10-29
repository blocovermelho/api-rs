use axum::async_trait;

use super::{Event, Module, ModuleCtx};

pub struct LoggerModule {
    ctx: ModuleCtx,
}

#[async_trait]
impl Module for LoggerModule {
    fn new(ctx: ModuleCtx) -> Self {
        LoggerModule { ctx }
    }
    async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                e =  self.ctx.receiver.recv() => {
                   match e {
                       Ok(event) => { let _ = self.handle_event(event).await; },
                       Err(e) => println!("Error: {}", e),
                   }
                }
            }
        }
    }
    async fn handle_event(&mut self, event: Event) -> anyhow::Result<()> {
        println!("LOG [{}]: Received {:?}", event.module, event.inner);
        Ok(())
    }
}
