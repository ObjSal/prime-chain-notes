//! Sync-bundle JSON (companion → device), note extraction (the scanner
//! side), and the high-level compose path (device → signed tx hex).

use serde::{Deserialize, Serialize};

use crate::address::taproot_address;
use crate::crypt;
use crate::envelope::{self, Chunk, FLAG_PRIVATE};
use crate::keys::{derive_encryption_key, derive_identity_key, xonly_pubkey};
use crate::taproot::{taproot_tweak_pubkey, taproot_tweak_seckey};
use crate::tx::{build_note_tx, NoteTx, Utxo};
use crate::{Error, Network};

/// Everything derived from the app seed that the app needs at runtime.
pub struct Identity {
    pub internal_x: [u8; 32],
    pub output_x: [u8; 32],
    pub tweaked_seckey: [u8; 32],
    pub enc_key: [u8; 32],
}

impl Identity {
    pub fn from_app_seed(app_seed: &[u8; 32]) -> Result<Self, Error> {
        let identity_key = derive_identity_key(app_seed);
        let (internal_x, _) = xonly_pubkey(&identity_key)?;
        let (output_x, _) = taproot_tweak_pubkey(&internal_x, None)?;
        let tweaked_seckey = taproot_tweak_seckey(&identity_key, None)?;
        Ok(Identity {
            internal_x,
            output_x,
            tweaked_seckey,
            enc_key: derive_encryption_key(app_seed),
        })
    }

    pub fn address(&self, network: Network) -> String {
        taproot_address(network, &self.output_x)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FeeRates {
    #[serde(rename = "fastestFee")]
    pub fastest: f64,
    #[serde(rename = "halfHourFee")]
    pub half_hour: f64,
    #[serde(rename = "hourFee")]
    pub hour: f64,
    #[serde(rename = "economyFee")]
    pub economy: f64,
    #[serde(rename = "minimumFee")]
    pub minimum: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    #[serde(default)]
    pub height: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnchainTx {
    pub txid: String,
    #[serde(default)]
    pub height: Option<u64>,
    #[serde(default)]
    pub blocktime: Option<u64>,
    /// True when the tx spends an input belonging to the notes address —
    /// the sender-authentication rule; payloads in txs merely PAYING the
    /// address are ignored.
    pub spends_from_self: bool,
    /// OP_RETURN payloads (hex), in output order.
    pub payloads: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncBundle {
    pub network: String,
    pub full: bool,
    pub since_height: Option<u64>,
    pub tip_height: u64,
    pub bundle_time: u64,
    /// Legacy field, tolerated on parse but no longer emitted or consumed:
    /// chunk size is a device-side setting (app Settings screen).
    pub max_op_return_bytes: usize,
    pub fee_rates: FeeRates,
    pub btc_usd: Option<f64>,
    pub utxos: Vec<BundleUtxo>,
    pub notes_onchain: Vec<OnchainTx>,
}

impl Default for SyncBundle {
    fn default() -> Self {
        SyncBundle {
            network: String::new(),
            full: false,
            since_height: None,
            tip_height: 0,
            bundle_time: 0,
            max_op_return_bytes: 80,
            fee_rates: FeeRates::default(),
            btc_usd: None,
            utxos: Vec::new(),
            notes_onchain: Vec::new(),
        }
    }
}

impl SyncBundle {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn utxos(&self) -> Vec<Utxo> {
        self.utxos
            .iter()
            .filter_map(|u| {
                let mut txid = [0u8; 32];
                hex::decode_to_slice(&u.txid, &mut txid).ok()?;
                txid.reverse(); // display order → internal order
                Some(Utxo { txid, vout: u.vout, value: u.value })
            })
            .collect()
    }
}

/// A note recovered from chain data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredNote {
    pub note_id: [u8; 4],
    pub txids: Vec<String>,
    pub height: Option<u64>,
    pub blocktime: Option<u64>,
    pub private: bool,
    /// None = private note that did not decrypt under our key (foreign).
    pub text: Option<String>,
}

/// Scan a bundle's on-chain txs into notes: filter to self-spends, decode
/// PNTE envelopes, group chunks by note_id across txs, reassemble, decrypt
/// private bodies. Import is idempotent by construction — output depends
/// only on chain content, keyed by note_id.
pub fn extract_notes(bundle: &SyncBundle, enc_key: &[u8; 32]) -> Vec<RecoveredNote> {
    struct Pending {
        chunks: Vec<Chunk>,
        txids: Vec<String>,
        height: Option<u64>,
        blocktime: Option<u64>,
    }
    let mut by_id: Vec<([u8; 4], Pending)> = Vec::new();

    for tx in &bundle.notes_onchain {
        if !tx.spends_from_self {
            continue;
        }
        for payload_hex in &tx.payloads {
            let Ok(payload) = hex::decode(payload_hex) else { continue };
            let Some(chunk) = envelope::decode(&payload) else { continue };
            let entry = match by_id.iter_mut().find(|(id, _)| *id == chunk.note_id) {
                Some((_, p)) => p,
                None => {
                    by_id.push((
                        chunk.note_id,
                        Pending {
                            chunks: Vec::new(),
                            txids: Vec::new(),
                            height: None,
                            blocktime: None,
                        },
                    ));
                    &mut by_id.last_mut().expect("just pushed").1
                }
            };
            // Drop exact duplicates (overlapping incremental bundles).
            if entry.chunks.iter().any(|c| c.seq == chunk.seq && c.data == chunk.data) {
                continue;
            }
            entry.chunks.push(chunk);
            if !entry.txids.contains(&tx.txid) {
                entry.txids.push(tx.txid.clone());
            }
            // A note's height is its FIRST confirmation.
            if entry.height.is_none() || tx.height < entry.height {
                if tx.height.is_some() {
                    entry.height = tx.height;
                    entry.blocktime = tx.blocktime;
                }
            }
        }
    }

    let mut notes = Vec::new();
    for (note_id, pending) in by_id {
        let Ok(body) = envelope::reassemble(&pending.chunks) else { continue };
        let private = pending.chunks[0].flags & FLAG_PRIVATE != 0;
        let text = if private {
            crypt::open(enc_key, &note_id, &body)
                .ok()
                .and_then(|pt| String::from_utf8(pt).ok())
        } else {
            String::from_utf8(body).ok()
        };
        notes.push(RecoveredNote {
            note_id,
            txids: pending.txids,
            height: pending.height,
            blocktime: pending.blocktime,
            private,
            text,
        });
    }
    // Confirmed first, oldest first; unconfirmed last.
    notes.sort_by_key(|n| n.height.unwrap_or(u64::MAX));
    notes
}

/// Compose path: text → (sealed) body → enveloped payloads → signed tx.
#[allow(clippy::too_many_arguments)]
pub fn compose_note(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    max_op_return_bytes: usize,
    fee_rate: f64,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let body = if private {
        crypt::seal(&identity.enc_key, &note_id, text.as_bytes())?
    } else {
        text.as_bytes().to_vec()
    };
    let flags = if private { FLAG_PRIVATE } else { 0 };
    let payloads = envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes)?;
    build_note_tx(
        utxos,
        &identity.output_x,
        &payloads,
        fee_rate,
        &identity.tweaked_seckey,
        aux,
    )
}

/// Cost preview for the compose screen: (payload_lens, est_vsize) for the
/// current text. Pure arithmetic — no crypto runs (see crypt::SEAL_OVERHEAD).
pub fn estimate_note_cost(
    text_len: usize,
    private: bool,
    max_op_return_bytes: usize,
    n_inputs: usize,
) -> Result<(usize, usize), Error> {
    let body_len = if private { text_len + crypt::SEAL_OVERHEAD } else { text_len };
    if body_len == 0 {
        return Err(Error::Envelope("empty body"));
    }
    if max_op_return_bytes <= envelope::HEADER_LEN {
        return Err(Error::Envelope("max_payload smaller than header"));
    }
    let chunk_size = max_op_return_bytes - envelope::HEADER_LEN;
    let total = body_len.div_ceil(chunk_size);
    if total > u8::MAX as usize {
        return Err(Error::PayloadTooLarge);
    }
    let mut payload_lens = vec![max_op_return_bytes; total - 1];
    let tail = body_len - (total - 1) * chunk_size;
    payload_lens.push(envelope::HEADER_LEN + tail);
    let vsize = crate::tx::estimate_vsize(n_inputs.max(1), &payload_lens, true);
    Ok((total, vsize))
}
