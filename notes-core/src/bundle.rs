//! Sync-bundle JSON (companion → device), note extraction (the scanner
//! side), and the high-level compose path (device → signed tx hex).

use serde::{Deserialize, Serialize};

use crate::address::{p2tr_x_of_address, taproot_address, Recipient};
use crate::crypt;
use crate::dm;
use crate::envelope::{self, Chunk, FLAG_DIRECTED, FLAG_PRIVATE};
use crate::keys::{derive_encryption_key, derive_identity_key, xonly_pubkey};
use crate::taproot::{taproot_tweak_pubkey, taproot_tweak_seckey};
use crate::tx::{build_note_tx_with_change, NoteTx, Utxo};
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
    /// the sender-authentication rule for OWN notes; PNTE payloads in txs
    /// merely PAYING the address surface as RECEIVED notes instead.
    pub spends_from_self: bool,
    /// OP_RETURN payloads (hex), in output order.
    pub payloads: Vec<String>,
    /// True when any output pays the notes address (directed-note delivery).
    #[serde(default)]
    pub pays_self: bool,
    /// First taproot input prevout address — the (unforgeable) author of a
    /// received note.
    #[serde(default)]
    pub sender: Option<String>,
    /// First non-self, non-OP_RETURN output address — the recipient of an
    /// own directed note (lets the sender re-derive the DM key after a wipe).
    #[serde(default)]
    pub recipient: Option<String>,
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

/// Magic prefix of a scanned-bundle payload: `CNB1 || deflate-raw(json)`.
/// The same bytes travel as one binary QR (small bundles) or as the
/// reassembled payload of an animated `ur:bytes` sequence (the system
/// scanner hands back the whole message either way).
pub const SCAN_MAGIC: &[u8; 4] = b"CNB1";

/// Decode a payload returned by the system QR scanner into bundle JSON.
/// Tolerates a plain uncompressed JSON QR too (starts with `{`).
pub fn decode_scanned(data: &[u8]) -> Result<String, Error> {
    if data.len() > 4 && data[..4] == *SCAN_MAGIC {
        let inflated = miniz_oxide::inflate::decompress_to_vec(&data[4..])
            .map_err(|_| Error::Envelope("bad deflate stream"))?;
        String::from_utf8(inflated).map_err(|_| Error::Envelope("bundle not utf-8"))
    } else if data.first() == Some(&b'{') {
        String::from_utf8(data.to_vec()).map_err(|_| Error::Envelope("bundle not utf-8"))
    } else {
        Err(Error::Envelope("not a Chain Notes bundle QR"))
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
    /// Directed note (dust output to a recipient; FLAG_DIRECTED set).
    pub directed: bool,
    /// True = someone else sent this note TO our address; false = our own.
    pub received: bool,
    /// Author address of a received note (first taproot input prevout).
    pub sender: Option<String>,
    /// Recipient address of our own directed note.
    pub recipient: Option<String>,
    /// None = private note that did not decrypt under our key (foreign).
    pub text: Option<String>,
}

/// Scan a bundle's on-chain txs into notes.
///
/// Acceptance: a tx that SPENDS FROM the notes address carries OWN notes
/// (the frozen spoof-resistance rule); a tx that only PAYS the address and
/// carries PNTE is a RECEIVED note, attributed to its (unforgeable) input
/// address; anything else is ignored. Chunks bucket by (note_id, origin) so
/// a pays-me tx reusing one of our note_ids can never contaminate our own
/// note. Import stays idempotent — output depends only on chain content.
pub fn extract_notes(
    bundle: &SyncBundle,
    identity: &Identity,
    network: Network,
) -> Vec<RecoveredNote> {
    #[derive(PartialEq, Eq, Clone)]
    enum Origin {
        Own,
        Received(Option<String>), // sender address
    }
    struct Pending {
        origin: Origin,
        chunks: Vec<Chunk>,
        txids: Vec<String>,
        height: Option<u64>,
        blocktime: Option<u64>,
        recipient: Option<String>,
    }
    let mut by_id: Vec<([u8; 4], Pending)> = Vec::new();

    for tx in &bundle.notes_onchain {
        let origin = if tx.spends_from_self {
            Origin::Own
        } else if tx.pays_self {
            Origin::Received(tx.sender.clone())
        } else {
            continue; // neither from nor to us — pure spoof, ignored
        };
        for payload_hex in &tx.payloads {
            let Ok(payload) = hex::decode(payload_hex) else { continue };
            let Some(chunk) = envelope::decode(&payload) else { continue };
            let entry = match by_id
                .iter_mut()
                .find(|(id, p)| *id == chunk.note_id && p.origin == origin)
            {
                Some((_, p)) => p,
                None => {
                    by_id.push((
                        chunk.note_id,
                        Pending {
                            origin: origin.clone(),
                            chunks: Vec::new(),
                            txids: Vec::new(),
                            height: None,
                            blocktime: None,
                            recipient: None,
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
            if entry.recipient.is_none() {
                entry.recipient = tx.recipient.clone();
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
        let flags = pending.chunks[0].flags;
        let private = flags & FLAG_PRIVATE != 0;
        let directed = flags & FLAG_DIRECTED != 0;
        let received = matches!(pending.origin, Origin::Received(_));
        let sender = match &pending.origin {
            Origin::Received(s) => s.clone(),
            Origin::Own => None,
        };
        let recipient = if received { None } else { pending.recipient.clone() };

        let plaintext = if !private {
            Some(body)
        } else if !directed {
            // Own self-note: the frozen enc_key path, byte-for-byte as v1.
            crypt::open(&identity.enc_key, &note_id, &body).ok()
        } else if received {
            // Received directed-private: reciprocal ECDH with the sender key.
            sender
                .as_deref()
                .and_then(|s| p2tr_x_of_address(network, s))
                .and_then(|sender_x| {
                    dm::open_received(
                        &identity.tweaked_seckey,
                        &identity.output_x,
                        &sender_x,
                        &note_id,
                        &body,
                    )
                    .ok()
                })
        } else {
            // Own sent directed-private: re-derive via the dust-output key.
            recipient
                .as_deref()
                .and_then(|r| p2tr_x_of_address(network, r))
                .and_then(|recipient_x| {
                    dm::open_sent(
                        &identity.tweaked_seckey,
                        &identity.output_x,
                        &recipient_x,
                        &note_id,
                        &body,
                    )
                    .ok()
                })
        };
        let text = plaintext.and_then(|pt| String::from_utf8(pt).ok());

        notes.push(RecoveredNote {
            note_id,
            txids: pending.txids,
            height: pending.height,
            blocktime: pending.blocktime,
            private,
            directed,
            received,
            sender,
            recipient,
            text,
        });
    }
    // Confirmed first, oldest first; unconfirmed last.
    notes.sort_by_key(|n| n.height.unwrap_or(u64::MAX));
    notes
}

/// Shared tail of both compose paths: body → enveloped payloads → signed tx.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn compose_inner(
    identity: &Identity,
    utxos: &[Utxo],
    note_id: [u8; 4],
    flags: u8,
    body: &[u8],
    recipient_spk: Option<&[u8]>,
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let payloads = envelope::encode_chunks(note_id, flags, body, max_op_return_bytes)?;
    build_note_tx_with_change(
        utxos,
        &identity.output_x,
        &payloads,
        recipient_spk,
        change_spk,
        fee_rate,
        &identity.tweaked_seckey,
        aux,
    )
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
    compose_note_with_change(
        identity, utxos, text, private, note_id, None, max_op_return_bytes, fee_rate, aux,
    )
}

/// Like `compose_note`, but change goes to `change_spk` when Some.
#[allow(clippy::too_many_arguments)]
pub fn compose_note_with_change(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    change_spk: Option<&[u8]>,
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
    compose_inner(
        identity, utxos, note_id, flags, &body, None, change_spk, max_op_return_bytes, fee_rate,
        aux,
    )
}

/// Directed compose: like `compose_note` but the note is addressed TO
/// `recipient` — a DUST_LIMIT output delivers/indexes it at their address.
/// Private bodies are sealed under the static-static ECDH key (dm.rs), so
/// only the recipient (and the sender, reciprocally) can read them; private
/// therefore requires a taproot recipient. Public directed notes go to any
/// segwit address.
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipient: &Recipient,
    max_op_return_bytes: usize,
    fee_rate: f64,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    compose_directed_note_with_change(
        identity, utxos, text, private, note_id, recipient, None, max_op_return_bytes, fee_rate,
        aux,
    )
}

/// Like `compose_directed_note`, but change goes to `change_spk` when Some.
#[allow(clippy::too_many_arguments)]
pub fn compose_directed_note_with_change(
    identity: &Identity,
    utxos: &[Utxo],
    text: &str,
    private: bool,
    note_id: [u8; 4],
    recipient: &Recipient,
    change_spk: Option<&[u8]>,
    max_op_return_bytes: usize,
    fee_rate: f64,
    aux: impl FnMut() -> Result<[u8; 32], Error>,
) -> Result<NoteTx, Error> {
    let body = if private {
        let recipient_x = recipient.p2tr_x.ok_or(Error::RecipientNotTaproot)?;
        dm::seal_directed(
            &identity.tweaked_seckey,
            &identity.output_x,
            &recipient_x,
            &note_id,
            text.as_bytes(),
        )?
    } else {
        text.as_bytes().to_vec()
    };
    let flags = FLAG_DIRECTED | if private { FLAG_PRIVATE } else { 0 };
    compose_inner(
        identity,
        utxos,
        note_id,
        flags,
        &body,
        Some(&recipient.spk),
        change_spk,
        max_op_return_bytes,
        fee_rate,
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
    recipient_spk_len: Option<usize>,
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
    let vsize = crate::tx::estimate_vsize(n_inputs.max(1), &payload_lens, recipient_spk_len, true);
    Ok((total, vsize))
}
