use axum::http::HeaderMap;
use ed25519_dalek::{Signature, Verifier};
#[cfg(axumzerosevennotready)]
use tokio::signal::unix::{signal, SignalKind};

use crate::{AppState, Error};

#[cfg(axumzerosevennotready)]
pub async fn wait_for_shutdown() {
    let mut int = signal(SignalKind::interrupt()).unwrap();
    let mut quit = signal(SignalKind::quit()).unwrap();
    let mut term = signal(SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = int.recv() => {},
        _ = quit.recv() => {},
        _ = term.recv() => {}
    }
}

pub fn validate_discord_sig(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), Error> {
    let sig_arr = hex::decode(
        headers
            .get("X-Signature-Ed25519")
            .ok_or(Error::MissingSignatureHeader)?,
    )?;
    let sig = Signature::from_slice(&sig_arr)?;
    let timestamp = headers
        .get("X-Signature-Timestamp")
        .ok_or(Error::MissingTimestampHeader)?;
    let to_be_verified: Vec<u8> = timestamp
        .as_bytes()
        .iter()
        .chain(body.iter())
        .copied()
        .collect();
    state.pubkey.verify(to_be_verified.as_slice(), &sig)?;
    Ok(())
}
