use std::net::Ipv4Addr;

use poise::{
    serenity_prelude::{ComponentInteractionDataKind, Context, FullEvent, Interaction},
    FrameworkContext,
};

use crate::{
    actor::new_connection::InteractionHolder,
    discord::{Data, Error},
};

pub mod new_ip;

pub async fn event_handler(
    ctx: &Context, fw: FrameworkContext<'_, Data, Error>, event: &FullEvent,
) -> Result<(), Error> {
    match event {
        FullEvent::InteractionCreate { interaction: Interaction::Component(component) } => {
            if matches!(component.data.kind, ComponentInteractionDataKind::Button) {
                let custom_id = &component.data.custom_id;
                if custom_id.starts_with("ip_allow") {
                    let thing: Vec<_> = custom_id.split(":").collect();
                    let ip: Ipv4Addr = thing[1].parse().unwrap();

                    let _ = component.defer(ctx).await;

                    fw.user_data.mailbox.btn_ip_clicked_allow(
                        ip,
                        component.channel_id,
                        component.message.id,
                        component.user.id,
                        InteractionHolder(component.id, component.token.clone()),
                    );
                }

                if custom_id.starts_with("ip_deny") {
                    let thing: Vec<_> = custom_id.split(":").collect();
                    let ip: Ipv4Addr = thing[1].parse().unwrap();

                    let _ = component.defer(ctx).await;

                    fw.user_data.mailbox.btn_ip_clicked_deny(
                        ip,
                        component.channel_id,
                        component.message.id,
                        component.user.id,
                        InteractionHolder(component.id, component.token.clone()),
                    );
                }
            }
        }
        FullEvent::Ready { data_about_bot } => {
            println!("[Ready] Bot is ready. {}#0000", data_about_bot.user.name);
        }
        _ => {
            println!("[Event Handler] Got Event of type: {:?}.", event.snake_case_name());
        }
    }
    Ok(())
}
