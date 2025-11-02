// use db::data::User;
// use ids::{CHANGE_PASSWORD, INPUT_PASSWORD};
// use poise::serenity_prelude::{
//     CreateActionRow, CreateInputText, CreateModal, CreateSelectMenu, CreateSelectMenuOption,
//     InputTextStyle,
// };

// pub mod ids {
//     pub const CHANGE_PASSWORD: &str = "change_pass";
//     pub const INPUT_PASSWORD: &str = "input_pass";
//     pub fn make_unique(key: &'static str, nonce: String) -> String {
//         format!("{}_{}", key, nonce)
//     }
// }

// pub fn new_password(username: &String, uuid: &String) -> CreateModal {
//     CreateModal::new(
//         ids::make_unique(&CHANGE_PASSWORD, uuid.clone()),
//         "Bloco Vemelho - Modificando Senha",
//     )
//     .components(vec![CreateActionRow::InputText(
//         CreateInputText::new(
//             InputTextStyle::Short,
//             format!("Senha de {}", username),
//             ids::make_unique(&INPUT_PASSWORD, uuid.clone()),
//         )
//         .max_length(32)
//         .min_length(8),
//     )])
// }

#[derive(Debug, poise::Modal)]
#[name = "Bloco Vermelho - Modificando Senha"]
pub struct NewPassword {
    #[name = "Nova senha"]
    #[placeholder = "Digite sua senha aqui"]
    #[min_length = 8]
    #[max_length = 64]
    pub password: String,
}
