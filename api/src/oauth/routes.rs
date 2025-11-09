use oauth2::{
    basic::{BasicClient, BasicTokenResponse},
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use reqwest::Client;
use serenity::all::{Member, User};

use crate::oauth::models::Config;

pub const BASE_URI: &str = "https://discord.com/api";

pub type OAuthClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
>;

pub fn get_client(config: &Config) -> std::result::Result<OAuthClient, oauth2::url::ParseError> {
    let k = BasicClient::new(ClientId::new(config.client_id.clone()))
        .set_client_secret(ClientSecret::new(config.client_secret.clone()))
        .set_auth_uri(AuthUrl::new("https://discord.com/oauth2/authorize".to_string())?)
        .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone())?)
        .set_token_uri(TokenUrl::new("https://discord.com/api/oauth2/token".to_string())?)
        .set_auth_type(oauth2::AuthType::RequestBody);

    Ok(k)
}

pub fn authorize(client: &OAuthClient) -> oauth2::AuthorizationRequest<'_> {
    client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .add_scope(Scope::new("guilds.members.read".to_string()))
}

pub async fn get_guild(
    client: &Client, token: &BasicTokenResponse, config: &Config,
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
