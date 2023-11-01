use twilight_model::application::command::{Command, CommandType};
use twilight_util::builder::command::{CommandBuilder, StringBuilder};

#[derive(serde::Deserialize)]
pub struct Bests {
    pub data: Vec<RunData>,
}

#[derive(serde::Deserialize)]
pub struct RunData {
    pub place: usize,
    pub run: Run,
}

#[derive(serde::Deserialize)]
pub struct Run {
    pub game: String,
    pub status: RunStatusContainer,
}

#[derive(serde::Deserialize)]
pub struct RunStatusContainer {
    pub status: RunStatus,
}

#[derive(serde::Deserialize, Copy, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RunStatus {
    New,
    Verified,
    Rejected,
}

pub fn commands() -> Vec<Command> {
    let link = CommandBuilder::new(
        "link",
        "Link your speedrun.com account",
        CommandType::ChatInput,
    )
    .dm_permission(false)
    .option(StringBuilder::new("src_name", "The name you use on speedrun.com").required(true))
    .build();
    let unlink = CommandBuilder::new(
        "unlink",
        "Unlink your speedrun.com account",
        CommandType::ChatInput,
    )
    .dm_permission(false)
    .build();
    vec![link, unlink]
}
