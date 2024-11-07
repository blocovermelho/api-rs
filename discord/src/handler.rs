use std::net::Ipv4Addr;

use poise::{
    serenity_prelude::{ComponentInteractionDataKind, Context, FullEvent, Interaction},
    FrameworkContext,
};

use crate::{id::Id, Data, Error};

pub mod new_ip;

pub async fn event_handler(
    ctx: &Context, fw: FrameworkContext<'_, Data, Error>, event: &FullEvent,
) -> Result<(), Error> {
    match event {
        FullEvent::InteractionCreate { interaction: Interaction::Component(component) } => {
            if matches!(component.data.kind, ComponentInteractionDataKind::Button) {
                if let Some(id) = Id::decode(&component.data.custom_id) {
                    match id.action {
                        crate::id::Action::AcceptIp => {
                            // Parse Nonce
                            let ip = Ipv4Addr::from_bits(id.nonce.parse()?);
                            new_ip::ip_accept(ctx, &fw, component, ip, id.target).await?;
                        }
                        crate::id::Action::DenyIp => {
                            // Parse Nonce
                            let ip = Ipv4Addr::from_bits(id.nonce.parse()?);
                            new_ip::ip_deny(ctx, &fw, component, ip, id.target).await?;
                        }
                        crate::id::Action::PromptBanIp => {
                            // Parse Nonce
                            let ip = Ipv4Addr::from_bits(id.nonce.parse()?);
                            new_ip::ip_prompt(ctx, &fw, component, ip, id.target).await?;
                        }
                        crate::id::Action::ReturnIp => {
                            let ip = Ipv4Addr::from_bits(id.nonce.parse()?);
                            new_ip::ip_back(ctx, &fw, component, ip, id.target).await?;
                        }
                        crate::id::Action::PasswordInput => {}
                    }
                } else {
                    panic!("Unparsed button id: {}", &component.data.custom_id)
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
