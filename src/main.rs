mod model;
mod util;

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use ed25519_dalek::VerifyingKey;
use reqwest::{redirect::Policy, Client as HttpClient};
use tokio::net::TcpListener;
use twilight_http::{client::InteractionClient, Client as DiscordClient};
use twilight_model::{
    application::interaction::{
        application_command::CommandOptionValue, Interaction, InteractionData, InteractionType,
    },
    channel::message::MessageFlags,
    http::interaction::{InteractionResponse, InteractionResponseType},
    id::{
        marker::{ApplicationMarker, GuildMarker, RoleMarker},
        Id,
    },
    user::User,
};
use twilight_util::builder::{embed::EmbedBuilder, InteractionResponseDataBuilder};

use crate::{
    model::{Bests, RunStatus},
    util::validate_discord_sig,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let pub_key_string = std::env::var("DISCORD_PUBKEY").expect("Expected DISCORD_PUBKEY");
    let token = std::env::var("DISCORD_TOKEN").expect("Expected DISCORD_TOKEN");
    let game_id = std::env::var("GAME_ID").expect("Expected GAME_ID");
    let guild_id: Id<GuildMarker> = std::env::var("GUILD_ID")
        .expect("Expected GUILD_ID")
        .parse()
        .expect("ROLE_ID was not a snowflake!");
    let role_id: Id<RoleMarker> = std::env::var("ROLE_ID")
        .expect("Expected ROLE_ID")
        .parse()
        .expect("ROLE_ID was not a snowflake!");

    let pub_key_bytes: [u8; 32] = hex::decode(pub_key_string)
        .expect("Discord pubkey was invalid hex")
        .try_into()
        .expect("Discord pubkey was wrong length (32 bytes, 64 chars expected)");
    let pubkey = VerifyingKey::from_bytes(&pub_key_bytes).expect("Invalid Ed25519 verifying key");

    let discord = twilight_http::Client::new(token);
    let my_id = discord
        .current_user_application()
        .await
        .unwrap()
        .model()
        .await
        .unwrap()
        .id;
    let http = reqwest::Client::builder()
        .user_agent("smbwdiscord/rolelinker (valk@randomairborne.dev)")
        .redirect(Policy::limited(5))
        .build()
        .unwrap();

    let state = AppState {
        discord: Arc::new(discord),
        http,
        pubkey: Arc::new(pubkey),
        my_id,
        game_id: game_id.into(),
        guild_id,
        role_id,
    };
    state
        .interaction()
        .set_global_commands(model::commands().as_slice())
        .await
        .unwrap();
    let app = Router::new()
        .route("/interaction-callback", axum::routing::any(handle))
        .with_state(state);
    let tcp = TcpListener::bind((IpAddr::from([0, 0, 0, 0]), 8080))
        .await
        .expect("Failed to start TCP listener on");
    axum::serve(tcp, app).await.unwrap()
}

pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<InteractionResponse>, Error> {
    validate_discord_sig(&state, &headers, body.as_ref())?;
    let interaction: Interaction = serde_json::from_slice(&body)?;
    let resp = match interaction.kind {
        InteractionType::ApplicationCommand => state.submit(interaction).await,
        _ => InteractionResponse {
            kind: InteractionResponseType::Pong,
            data: None,
        },
    };
    Ok(Json(resp))
}

#[derive(Clone)]
pub struct AppState {
    discord: Arc<DiscordClient>,
    http: HttpClient,
    pubkey: Arc<VerifyingKey>,
    my_id: Id<ApplicationMarker>,
    game_id: Arc<str>,
    role_id: Id<RoleMarker>,
    guild_id: Id<GuildMarker>,
}

impl AppState {
    pub async fn submit(&self, interaction: Interaction) -> InteractionResponse {
        let this = self.clone();
        tokio::spawn(async move { this.process_wrap(interaction).await });
        InteractionResponse {
            kind: InteractionResponseType::DeferredChannelMessageWithSource,
            data: Some(
                InteractionResponseDataBuilder::new()
                    .flags(MessageFlags::EPHEMERAL)
                    .build(),
            ),
        }
    }

    async fn process_wrap(&self, interaction: Interaction) {
        let interaction_token = interaction.token.clone();
        if let Err(source) = self.process(interaction).await {
            if let Err(effect) = self.report_err(&interaction_token, &source).await {
                eprintln!(
                    "Encountered error processing command: {source:?} \
                     with error trying to report: {effect:?}"
                );
            } else {
                eprintln!("Encountered error processing command: {source:?}");
            }
        }
    }

    async fn report_err(&self, token: &str, error: &Error) -> Result<(), Error> {
        let client = self.interaction();
        let err_embed = EmbedBuilder::new().description(error.to_string()).build();
        client
            .update_response(token)
            .embeds(Some(&[err_embed]))?
            .await?;
        Ok(())
    }

    fn interaction(&self) -> InteractionClient<'_> {
        self.discord.interaction(self.my_id)
    }

    async fn process(&self, interaction: Interaction) -> Result<(), Error> {
        let Some(InteractionData::ApplicationCommand(data)) = &interaction.data else {
            return Err(Error::WrongInteractionData);
        };
        let user = Self::interaction_get_user(&interaction).ok_or(Error::MissingUser)?;
        let resp_text = match data.name.as_str() {
            "link" => {
                let args: HashMap<String, CommandOptionValue> = data
                    .options
                    .iter()
                    .cloned()
                    .map(|v| (v.name, v.value))
                    .collect();
                let Some(CommandOptionValue::String(src_name)) = args.get("src_name") else {
                    return Err(Error::WrongSrcName);
                };
                self.link(user, src_name).await?
            }
            "unlink" => self.unlink(user).await?,
            name => return Err(Error::UnknownCommand(name.to_owned())),
        };
        let embed = EmbedBuilder::new().description(resp_text).build();
        self.interaction()
            .update_response(&interaction.token)
            .embeds(Some(&[embed]))?
            .await?;
        Ok(())
    }

    async fn link(&self, user: &User, src_name: &str) -> Result<String, Error> {
        let msg = match self.eligible(&user.name, src_name).await? {
            Eligibility::Eligible => {
                self.discord
                    .add_guild_member_role(self.guild_id, user.id, self.role_id)
                    .await?;
                format!("granted role <@&{}>", self.role_id)
            }
            Eligibility::NotLinked => format!("speedrun.com user [{src_name}](https://www.speedrun.com/users/{src_name}) is not connected to discord user <@{0}>", user.id),
            Eligibility::LinkedWithNoVerifiedRuns => format!("You have linked your speedrun.com account [{src_name}](https://www.speedrun.com/users/{src_name}), but it does not have any verified runs for SMBW!")
        };
        Ok(msg)
    }

    async fn unlink(&self, user: &User) -> Result<String, Error> {
        self.discord
            .remove_guild_member_role(self.guild_id, user.id, self.role_id)
            .await?;
        Ok(format!("removed role <@&{}>", self.role_id))
    }

    fn interaction_get_user(interaction: &Interaction) -> Option<&User> {
        if let Some(member) = &interaction.member {
            if let Some(user) = &member.user {
                return Some(user);
            }
        }
        if let Some(user) = &interaction.user {
            return Some(user);
        }
        None
    }

    async fn eligible(&self, discord_name: &str, src_name: &str) -> Result<Eligibility, Error> {
        let src_url = format!("https://www.speedrun.com/user/{src_name}");
        let page = self.http.get(src_url).send().await?.text().await?;
        if !page.contains(&format!("@{discord_name}")) {
            return Ok(Eligibility::NotLinked);
        }
        let pbs_url = format!("https://www.speedrun.com/api/v1/users/{src_name}/personal-bests");
        let bests: Bests = self
            .http
            .get(pbs_url)
            .header("Accept", "application/json")
            .send()
            .await?
            .json()
            .await?;
        for run_data in bests.data {
            let run = run_data.run;
            if run.status.status == RunStatus::Verified && run.game == self.game_id.as_ref() {
                return Ok(Eligibility::Eligible);
            }
        }
        Ok(Eligibility::LinkedWithNoVerifiedRuns)
    }
}

pub enum Eligibility {
    NotLinked,
    LinkedWithNoVerifiedRuns,
    Eligible,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ed25519-dalek signature error")]
    Dalek(#[from] ed25519_dalek::SignatureError),
    #[error("hex decode error")]
    Hex(#[from] hex::FromHexError),
    #[error("serde-json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("twilight-http error: {0}")]
    TwilightHttp(#[from] twilight_http::Error),
    #[error("twilight-validate embed error: {0}")]
    TwilightValidateEmbed(#[from] twilight_validate::embed::EmbedValidationError),
    #[error("twilight-validate message error: {0}")]
    TwilightValidateMessage(#[from] twilight_validate::message::MessageValidationError),
    #[error("Unknown command: {0}")]
    UnknownCommand(String),
    #[error("Missing X-Signature-Ed25519 header")]
    MissingSignatureHeader,
    #[error("Missing X-Signature-Timestamp header")]
    MissingTimestampHeader,
    #[error("Missing user from discord")]
    MissingUser,
    #[error("Wrong interaction data from discord")]
    WrongInteractionData,
    #[error("Discord sent `src_name` that was not a string, or didn't send it at all!")]
    WrongSrcName,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = match self {
            Error::Dalek(_) => StatusCode::UNAUTHORIZED,
            Error::Hex(_) => StatusCode::UNAUTHORIZED,
            Error::SerdeJson(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Reqwest(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::TwilightHttp(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::TwilightValidateEmbed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::TwilightValidateMessage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::UnknownCommand(_) => StatusCode::BAD_REQUEST,
            Error::MissingSignatureHeader => StatusCode::UNAUTHORIZED,
            Error::MissingTimestampHeader => StatusCode::UNAUTHORIZED,
            Error::MissingUser => StatusCode::BAD_REQUEST,
            Error::WrongInteractionData => StatusCode::BAD_REQUEST,
            Error::WrongSrcName => StatusCode::BAD_REQUEST,
        };
        (status, self.to_string()).into_response()
    }
}
