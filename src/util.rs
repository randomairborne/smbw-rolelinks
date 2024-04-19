use axum::http::HeaderMap;
use ed25519_dalek::{Signature, Verifier};

use crate::{AppState, Error};

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
