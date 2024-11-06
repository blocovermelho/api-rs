use oauth2::{
    basic::{BasicClient, BasicTokenResponse},
    url::ParseError,
    AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::Client;

use crate::models::{Config, Member, User};

pub const BASE_URI: &str = "https://discord.com/api";

pub fn get_client(config: &Config) -> Result<BasicClient, ParseError> {
    Ok(BasicClient::new(
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
        AuthUrl::new(format!("{}{}", BASE_URI, "/oauth2/authorize"))?,
        Some(TokenUrl::new(format!("{}{}", BASE_URI, "/oauth2/token"))?),
    )
    .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone())?))
}

pub fn authorize(client: &BasicClient) -> oauth2::AuthorizationRequest<'_> {
    client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .add_scope(Scope::new("guilds.members.read".to_string()))
}

pub async fn get_guild(
    client: &Client,
    token: &BasicTokenResponse,
    config: &Config,
) -> Result<Member, reqwest::Error> {
    let req = client
        .get(BASE_URI.to_owned() + "/users/@me/guilds/" + &config.guild_id + "/member")
        .bearer_auth(token.access_token().secret())
        .build()?;

    let member = client.execute(req).await?.json::<Member>().await?;

    Ok(member)
}

pub async fn get_self(client: &Client, token: &BasicTokenResponse) -> Result<User, reqwest::Error> {
    let req = client
        .get(BASE_URI.to_owned() + "/users/@me")
        .bearer_auth(token.access_token().secret())
        .build()?;

    let user = client.execute(req).await?.json::<User>().await?;

    Ok(user)
}
