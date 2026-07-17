mod notebooks;
mod spending;
mod theme;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use notes_core::address::Recipient;
use notes_core::bundle::{
    compose_directed_note_exact_amount, compose_directed_note_with_change_amount,
    compose_note_exact, decode_scanned, estimate_note_cost, extract_notes_multi,
    sealed_note_payloads, Identity, SyncBundle,
};
use notes_core::address::p2tr_script_pubkey;
use notes_core::keys::{generate_aux_rand, generate_note_id, pick_unique_note_id};
use notes_core::tx::{
    build_note_tx_mixed_exact, build_sweep_tx_multi, estimate_sweep_vsize, estimate_vsize_mixed,
    InputKind, MixedInput, NoteTx, SweepSource, Utxo,
};
use notes_core::Network;
use serde::{Deserialize, Serialize};
use spending::SpendingIndex;
use slint_keyos_platform::app_ui;
use slint_keyos_platform::fs::{self, Location, OpenFlags};
use slint_keyos_platform::gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult};
use slint_keyos_platform::navigation::open_qr_scanner;
use slint_keyos_platform::qrcode;
use slint_keyos_platform::slint::{Color, ComponentHandle, Image, Timer, VecModel};

security::use_api!();

app_ui!("prime-chain-notes");

type Fs = fs::FileSystem<fs_permissions::FileSystemPermissions>;

/// Below this the 12-byte envelope header dominates and a 255-chunk note
/// holds almost nothing.
const MIN_CHUNK: usize = 20;
/// Default chunk ceiling: Bitcoin Core v30's relay default (verified live
/// on mempool.space). Chunk size is a pure DEVICE setting — bundles carry
/// no relay policy; if an endpoint rejects, pick "80 compat" in Settings
/// and recompose.
const DEFAULT_CHUNK: usize = 100_000;
/// Bitcoin standardness ceiling on a single transaction: `MAX_STANDARD_TX_WEIGHT`
/// (400_000 WU) / 4 = 100_000 vB. Nodes won't relay a bigger tx, so this — NOT
/// the per-output chunk size — is the hard wall on one note (a note is one tx of
/// ≤255 OP_RETURN chunks). At a small chunk size the 255-chunk cap binds first,
/// so raising the size to DEFAULT_CHUNK can rescue a note that overflows.
const MAX_STANDARD_TX_VSIZE: usize = 100_000;

/// Whether the composed note fits in one standard tx, and if not, whether
/// raising the chunk size to Standard (DEFAULT_CHUNK) would rescue it.
enum FitCheck {
    Ok,
    /// Over now, but fits at Standard — the user is on a smaller setting whose
    /// 255-chunk cap binds first. Offer to switch.
    FitsAtStandard,
    /// Over even at Standard: the ~100 kB per-tx network wall. No setting helps.
    HardWall,
}

fn note_fits(text_len: usize, private: bool, chunk: usize, recipient_spk_len: Option<usize>) -> bool {
    estimate_note_cost(text_len, private, chunk, 1, recipient_spk_len)
        .map(|(_, vsize)| vsize <= MAX_STANDARD_TX_VSIZE)
        .unwrap_or(false) // Err = >255 chunks → over-limit
}

fn fit_check(
    effective_chunk: usize,
    text_len: usize,
    private: bool,
    recipient_spk_len: Option<usize>,
) -> FitCheck {
    if note_fits(text_len, private, effective_chunk, recipient_spk_len) {
        FitCheck::Ok
    } else if effective_chunk < DEFAULT_CHUNK
        && note_fits(text_len, private, DEFAULT_CHUNK, recipient_spk_len)
    {
        FitCheck::FitsAtStandard
    } else {
        FitCheck::HardWall
    }
}

const STATE_DIR: &str = "/.chain-notes";
const NOTEBOOKS_PATH: &str = "/.chain-notes/notebooks.json";
const CONFIG_PATH: &str = "/.chain-notes/config.json"; // device-level {network, chunk}
const INBOX_DIR: &str = "/chain-notes/inbox";
const OUTBOX_DIR: &str = "/chain-notes/outbox";

// ---------------------------------------------------------------- state

#[derive(Serialize, Deserialize, Clone)]
struct NoteRec {
    id: String, // note_id hex
    text: String,
    private: bool,
    txid: String,
    raw_hex: String, // "" for notes recovered from chain (already broadcast)
    fee: u64,
    vsize: u64,
    chunks: u64,
    height: Option<u64>,
    blocktime: Option<u64>,
    status: String, // "pending" | "confirmed"
    // Directed notes (all default so pre-existing state.json loads as-is).
    #[serde(default)]
    directed: bool,
    /// Recipient address of a note we sent to someone else.
    #[serde(default)]
    to: Option<String>,
    /// Sender address of a note someone sent to us.
    #[serde(default)]
    from: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct UtxoRec {
    txid: String, // display hex
    vout: u32,
    value: u64,
}

/// A send-to contact. Order in `State.contacts` IS the recency (front =
/// most recently used — there is no clock on-device). Device-side
/// convenience only: state.json, NOT recoverable from chain after a wipe.
#[derive(Serialize, Deserialize, Clone)]
struct ContactRec {
    name: String, // "" = unnamed
    address: String,
}

const MAX_CONTACTS: usize = 20;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct State {
    /// Which notebook (indexed identity) this state belongs to. NOT
    /// persisted — the file path (`state-<account>.json`) implies it; set
    /// on load. Lets `save_state` route without threading the account
    /// through every call site.
    #[serde(skip)]
    account: u32,
    network: String,
    notes: Vec<NoteRec>,
    utxos: Vec<UtxoRec>,
    contacts: Vec<ContactRec>,
    tip_height: Option<u64>,
    bundle_time: Option<u64>,
    /// User-picked chunk size; None = DEFAULT_CHUNK. Purely device-side.
    chunk_override: Option<usize>,
    /// Sender filter: sender keys (addresses, or "self") hidden from this
    /// notebook's notes list. The EXCLUSION set persists — anything not
    /// listed shows, so a new sender is visible by default.
    #[serde(default)]
    excluded_senders: Vec<String>,
    fee_economy: f64,
    fee_normal: f64,
    fee_fast: f64,
    btc_usd: Option<f64>,
}

impl Default for State {
    fn default() -> Self {
        State {
            account: 0,
            network: "mainnet".into(),
            notes: Vec::new(),
            utxos: Vec::new(),
            contacts: Vec::new(),
            tip_height: None,
            bundle_time: None,
            chunk_override: None,
            excluded_senders: Vec::new(),
            fee_economy: 1.0,
            fee_normal: 2.0,
            fee_fast: 5.0,
            btc_usd: None,
        }
    }
}

impl State {
    fn network(&self) -> Network {
        Network::from_str_opt(&self.network).unwrap_or(Network::Mainnet)
    }

    fn balance(&self) -> u64 {
        self.utxos.iter().map(|u| u.value).sum()
    }

    fn core_utxos(&self) -> Vec<Utxo> {
        self.utxos
            .iter()
            .filter_map(|u| {
                let mut txid = [0u8; 32];
                hex::decode_to_slice(&u.txid, &mut txid).ok()?;
                txid.reverse();
                Some(Utxo { txid, vout: u.vout, value: u.value })
            })
            .collect()
    }

    /// Chunk size actually used for composing: the override clamped into
    /// [MIN_CHUNK, DEFAULT_CHUNK], or DEFAULT_CHUNK.
    fn effective_chunk(&self) -> usize {
        self.chunk_override
            .map(|c| c.clamp(MIN_CHUNK, DEFAULT_CHUNK))
            .unwrap_or(DEFAULT_CHUNK)
    }

    /// The sender-filter key of a note: the counterparty for received
    /// notes, else "self" (own notes — self and directed-from-us).
    fn sender_key(n: &NoteRec) -> String {
        match &n.from {
            Some(f) => f.clone(),
            None => "self".to_string(),
        }
    }

    /// Distinct sender keys with counts, newest activity first.
    fn senders(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for n in self.notes.iter().rev() {
            let k = Self::sender_key(n);
            match out.iter_mut().find(|(x, _)| *x == k) {
                Some((_, c)) => *c += 1,
                None => out.push((k, 1)),
            }
        }
        out
    }

    fn is_excluded(&self, key: &str) -> bool {
        self.excluded_senders.iter().any(|s| s == key)
    }

    fn set_excluded(&mut self, key: &str, excluded: bool) {
        if excluded {
            if !self.is_excluded(key) {
                self.excluded_senders.push(key.to_string());
            }
        } else {
            self.excluded_senders.retain(|s| s != key);
        }
    }

    fn fee_rate(&self, tier: i32) -> f64 {
        let rate = match tier {
            0 => self.fee_economy,
            2 => self.fee_fast,
            _ => self.fee_normal,
        };
        if rate <= 0.0 {
            1.0
        } else {
            rate
        }
    }
}

/// A built-and-signed note waiting for user confirmation.
struct Plan {
    note: NoteTx,
    text: String,
    private: bool,
    note_id: [u8; 4],
    chunks: u64,
    recipient: Option<String>,
    /// Funding-unification: which spending-wallet coins this note spent
    /// (dropped from the ledger on sign) and, when change went to a fresh
    /// spending address, the address to mark used — both applied ONLY
    /// after a successful sign (see `resolve_change`'s doc comment).
    spending_spent: Vec<(String, u32)>,
    spending_change_addr: Option<spending::SpendingAddress>,
    /// True when change (if any) belongs in the NOTEBOOK ledger — false
    /// when it went to a fresh spending address (`spending_change_addr`
    /// is Some) or an external custom address (neither Some, untracked).
    change_is_notebook: bool,
    /// True when this tx carries the mandatory notebook-dust output
    /// (decision 4 — present whenever the spending wallet funded any part
    /// of it), which lands as a NEW notebook coin right after the
    /// OP_RETURN(s)/optional recipient, before change.
    notebook_dust: bool,
}

/// A built-and-signed sweep/consolidate waiting for user confirmation.
struct SweepPlan {
    tx: NoteTx,
    kind: &'static str,      // "sweep" | "consolidate"
    dest: Option<String>,    // None = self (consolidate)
    // Wallet-level: which outpoints (display txid, vout) each source
    // notebook contributed, so signing can update every source's ledger;
    // and the destination notebook a consolidate's new coin lands in.
    spent_by_account: Vec<(u32, Vec<(String, u32)>)>,
    dest_account: u32,
}

// ------------------------------------------------------------- helpers

/// Derive a notebook's identity from the app seed (None if locked).
/// Every notebook is a per-network BIP-86 leaf under its rotation seed
/// (PLAN-chain-notes-seed-rotation.md).
fn derive_identity(
    app_seed: &Option<[u8; 32]>,
    meta: &notebooks::NotebookMeta,
    net: &str,
) -> Option<Identity> {
    let seed = app_seed.as_ref()?;
    let network = Network::from_str_opt(net).unwrap_or(Network::Mainnet);
    Identity::from_bip86(seed, meta.seed, network, meta.bip_account, meta.index).ok()
}

/// The active notebook's leaf key rendered as (raw hex, WIF) for the
/// Export-keys reveal — a single-address private-key export.
fn export_leaf_formats(
    seed: &[u8; 32],
    seed_index: u32,
    network: Network,
    account: u32,
    index: u32,
) -> Result<(String, String), notes_core::Error> {
    Ok((
        notes_core::export::leaf_hex(seed, seed_index, network, account, index)?.as_str().to_string(),
        notes_core::export::leaf_wif(seed, seed_index, network, account, index)?.as_str().to_string(),
    ))
}

/// The reveal-screen title: master fingerprint · seed index · account.
/// The fingerprint (BIP-32 xfp, not a secret) identifies which seed/wallet
/// the exported keys belong to.
fn export_title(seed: &[u8; 32], seed_index: u32, account: u32) -> String {
    match notes_core::seeds::seed_fingerprint_hex(seed, seed_index) {
        Ok(fp) => format!("{fp} · Seed {seed_index} · account {account}"),
        Err(_) => format!("Seed {seed_index} · account {account}"),
    }
}

/// Every ACTIVE notebook with spendable coins, as
/// (account, output_x, tweaked_seckey, coins) — the inputs to a
/// wallet-level sweep/consolidate (`build_sweep_tx_multi`). Reads each
/// notebook's state from disk, so flush the active notebook first.
fn wallet_sources(
    fs: &Fs,
    ix: &notebooks::NotebookIndex,
    app_seed: &Option<[u8; 32]>,
    net: &str,
    ctx: (u32, u32),
) -> Vec<(u32, [u8; 32], [u8; 32], Vec<Utxo>)> {
    ix.visible(ctx.0, ctx.1)
        .filter_map(|m| {
            let st = load_state(fs, net, m.account);
            let coins = st.core_utxos();
            if coins.is_empty() {
                return None;
            }
            let id = derive_identity(app_seed, m, net)?;
            Some((m.account, id.output_x, id.tweaked_seckey, coins))
        })
        .collect()
}

/// Coin count + total across the wallet's visible notebooks ON `net`.
fn wallet_balance(
    fs: &Fs,
    ix: &notebooks::NotebookIndex,
    net: &str,
    ctx: (u32, u32),
) -> (usize, u64) {
    let mut n = 0;
    let mut total = 0;
    for m in ix.visible(ctx.0, ctx.1) {
        let st = load_state(fs, net, m.account);
        n += st.utxos.len();
        total += st.balance();
    }
    (n, total)
}

/// Device-level settings shared by every notebook (Sal 2026-07-11:
/// network is wallet-wide). Persisted at CONFIG_PATH.
#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct DeviceConfig {
    network: String,
    chunk_override: Option<usize>,
    /// Active rotation seed index (recovery-seeds; new bip86 notebooks
    /// derive under it).
    seed_index: u32,
    /// Active BIP-86 account — the wallet context (rev-3 parity).
    account: u32,
}
impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            network: "mainnet".into(),
            chunk_override: None,
            seed_index: 0,
            account: 0,
        }
    }
}
fn load_config(fs: &Fs) -> Option<DeviceConfig> {
    read_text(fs, CONFIG_PATH, Location::User)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
}

fn save_config(fs: &Fs, cfg: &DeviceConfig) {
    if let Ok(json) = serde_json::to_string(cfg) {
        let _ = ensure_dir(fs, STATE_DIR, Location::User)
            .and_then(|_| write_file(fs, CONFIG_PATH, Location::User, json.as_bytes()));
    }
}

/// Pre-2b per-notebook state path (had its own network field).
fn state_path_v1(account: u32) -> String {
    format!("/.chain-notes/state-{account}.json")
}

/// Per-(network, notebook) state file: each notebook has a separate ledger
/// on each network (network is device-level now).
fn state_path(net: &str, account: u32) -> String {
    format!("/.chain-notes/state-{net}-{account}.json")
}

/// Load a notebook's state for `net`, stamping network + account so
/// `save_state` routes back to the same file.
fn load_state(fs: &Fs, net: &str, account: u32) -> State {
    let mut st: State = read_text(fs, &state_path(net, account), Location::User)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();
    st.account = account;
    st.network = net.to_string();
    st
}

fn save_state(fs: &Fs, state: &State) {
    let json = serde_json::to_string(state).expect("state serializes");
    let path = state_path(&state.network, state.account);
    if let Err(e) = ensure_dir(fs, STATE_DIR, Location::User)
        .and_then(|_| write_file(fs, &path, Location::User, json.as_bytes()))
    {
        log::warn!("state save failed: {e}");
    }
}

fn load_notebooks(fs: &Fs) -> notebooks::NotebookIndex {
    read_text(fs, NOTEBOOKS_PATH, Location::User)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn save_notebooks(fs: &Fs, ix: &notebooks::NotebookIndex) {
    let json = serde_json::to_string(ix).expect("index serializes");
    if let Err(e) = ensure_dir(fs, STATE_DIR, Location::User)
        .and_then(|_| write_file(fs, NOTEBOOKS_PATH, Location::User, json.as_bytes()))
    {
        log::warn!("notebook index save failed: {e}");
    }
}

/// Load the notebook index, or an empty one on a fresh install — the
/// device has no onboarding, so first boot shows an empty notebook list
/// and the user creates their first (always bip86) notebook deliberately.
fn boot_notebooks(fs: &Fs) -> notebooks::NotebookIndex {
    if read_text(fs, NOTEBOOKS_PATH, Location::User).is_ok() {
        return load_notebooks(fs);
    }
    let ix = notebooks::NotebookIndex::default();
    save_notebooks(fs, &ix);
    ix
}

/// Device config, migrating pre-2b per-notebook state files
/// (`state-<account>.json`, each with its own network) into the
/// per-network layout (`state-<net>-<account>.json`) on first boot. The
/// device network becomes notebook 0's (else the lowest notebook's, else
/// mainnet); each notebook's ledger is preserved under its own network, so
/// switching the device network later reveals each notebook's chain data.
fn boot_config(fs: &Fs, ix: &notebooks::NotebookIndex) -> DeviceConfig {
    if let Some(cfg) = load_config(fs) {
        return cfg;
    }
    let mut dev: Option<(String, Option<usize>)> = None;
    for m in &ix.notebooks {
        let Ok(json) = read_text(fs, &state_path_v1(m.account), Location::User) else { continue };
        let st: State = serde_json::from_str(&json).unwrap_or_default();
        let net = st.network.clone();
        // Re-route to the per-network file.
        let _ = ensure_dir(fs, STATE_DIR, Location::User).and_then(|_| {
            write_file(fs, &state_path(&net, m.account), Location::User, json.as_bytes())
        });
        if m.account == 0 || dev.is_none() {
            dev = Some((net, st.chunk_override));
        }
    }
    let (network, chunk_override) = dev.unwrap_or_else(|| ("mainnet".into(), None));
    let cfg = DeviceConfig { network, chunk_override, ..Default::default() };
    save_config(fs, &cfg);
    log::info!("cb: config migrated network={} (per-network state files)", cfg.network);
    cfg
}

fn read_text(fs: &Fs, path: &str, loc: Location) -> Result<String, String> {
    use std::io::Read;
    let mut file = fs
        .open_file(path, loc, OpenFlags::READ_ONLY)
        .map_err(|e| format!("{e:?}"))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|_| "read failed".to_string())?;
    String::from_utf8(buf).map_err(|_| "not utf-8".to_string())
}

fn write_file(fs: &Fs, path: &str, loc: Location, bytes: &[u8]) -> Result<(), String> {
    fs.open_file(path, loc, OpenFlags::CREATE)
        .and_then(|mut f| f.overwrite(bytes))
        .map_err(|e| format!("{e:?}"))
}

/// create_dir for each path component (create_dir is single-level).
fn ensure_dir(fs: &Fs, path: &str, loc: Location) -> Result<(), String> {
    let mut so_far = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        so_far.push('/');
        so_far.push_str(part);
        if let Err(e) = fs.create_dir(so_far.as_str(), loc) {
            if !matches!(e, fs::Error::FileAlreadyExists) {
                return Err(format!("{e:?}"));
            }
        }
    }
    Ok(())
}

/// Lazy Airlock mount with format-on-failed-mount recovery (nothing mounts
/// Airlock in the hosted simulator; see paper-wallet NOTES.md).
fn ensure_airlock_mounted(fs: &Fs) -> Result<(), String> {
    let mut fs = fs.clone();
    if fs.mount_airlock().is_ok() {
        return Ok(());
    }
    log::warn!("airlock mount failed — formatting (no readable filesystem)");
    fs.format_airlock()
        .and_then(|_| fs.mount_airlock())
        .map_err(|e| format!("airlock unavailable: {e:?}"))
}

fn unmount_airlock(fs: &Fs) {
    let mut fs = fs.clone();
    let _ = fs.unmount_airlock();
}

fn first_inbox_bundle(fs: &Fs) -> Option<(String, Location, &'static str)> {
    for (loc, label) in [(Location::User, "internal"), (Location::Airlock, "airlock")] {
        if loc == Location::Airlock && ensure_airlock_mounted(fs).is_err() {
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        if let Ok(dir) = fs.open_dir(INBOX_DIR, loc) {
            while let Ok(Some(entry)) = dir.next_entry() {
                if entry.is_file && entry.name.ends_with(".json") {
                    names.push(entry.name);
                }
            }
        }
        names.sort();
        if let Some(name) = names.into_iter().next() {
            return Some((name, loc, label));
        }
    }
    None
}

/// Every `*.json` bundle in the inboxes (Internal first, then Airlock),
/// for the import picker. Airlock is mounted to enumerate, then unmounted
/// — the pick step re-mounts to read the chosen file.
fn list_inbox_bundles(fs: &Fs) -> Vec<(String, Location, &'static str)> {
    let mut out = Vec::new();
    for (loc, label) in [(Location::User, "internal"), (Location::Airlock, "airlock")] {
        if loc == Location::Airlock && ensure_airlock_mounted(fs).is_err() {
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        if let Ok(dir) = fs.open_dir(INBOX_DIR, loc) {
            while let Ok(Some(entry)) = dir.next_entry() {
                if entry.is_file && entry.name.ends_with(".json") {
                    names.push(entry.name);
                }
            }
        }
        if loc == Location::Airlock {
            unmount_airlock(fs);
        }
        names.sort();
        for name in names {
            out.push((name, loc, label));
        }
    }
    out
}

fn sats_line(sats: u64, usd: Option<f64>) -> String {
    match usd {
        Some(price) => format!("{sats} sats (~${:.2})", sats as f64 / 1e8 * price),
        None => format!("{sats} sats"),
    }
}

/// sat/vB for the current tier selection: tiers 0–2 come from the last
/// bundle; tier 3 (custom) parses the user-edited rate field.
fn resolve_rate(tier: i32, rate_text: &str, st: &State) -> Result<f64, String> {
    if tier == 3 {
        match rate_text.trim().parse::<f64>() {
            Ok(r) if r.is_finite() && r > 0.0 && r <= 100_000.0 => Ok(r),
            _ => Err("Enter a valid custom fee rate (sat/vB).".into()),
        }
    } else {
        Ok(st.fee_rate(tier))
    }
}

/// Sats the recipient (gift) output of a directed note carries. The gift
/// field parsed, floored at DUST_LIMIT — empty/garbage falls back to dust,
/// and a sub-dust value is bumped up (the tx builder rejects below-dust).
/// Self-notes have no recipient output, so this returns 0 and is unused.
fn resolve_gift(directed: bool, gift_text: &str) -> u64 {
    if !directed {
        return 0;
    }
    gift_text
        .trim()
        .parse::<u64>()
        .unwrap_or(notes_core::DUST_LIMIT)
        .max(notes_core::DUST_LIMIT)
}

fn preview_of(text: &str) -> String {
    let one_line: String = text.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let mut p: String = one_line.chars().take(40).collect();
    if one_line.chars().count() > 40 {
        p.push('…');
    }
    p
}

/// Compact address form for list rows: first 8 + last 6 chars.
fn short_addr(addr: &str) -> String {
    if addr.len() > 17 {
        format!("{}…{}", &addr[..8], &addr[addr.len() - 6..])
    } else {
        addr.to_string()
    }
}

/// Move-to-front recency (no clock on-device): reinsert the address at
/// index 0 preserving any existing name; cap the list at MAX_CONTACTS.
fn upsert_contact(st: &mut State, address: &str) {
    let name = st
        .contacts
        .iter()
        .position(|c| c.address == address)
        .map(|i| st.contacts.remove(i).name)
        .unwrap_or_default();
    st.contacts.insert(0, ContactRec { name, address: address.to_string() });
    st.contacts.truncate(MAX_CONTACTS);
}

/// The compose header line for a picked recipient.
fn to_label_for(st: &State, address: &str) -> String {
    if address.is_empty() {
        return "to: self — my notebook".into();
    }
    match st.contacts.iter().find(|c| c.address == address && !c.name.is_empty()) {
        Some(c) => format!("to: {} ({})", c.name, short_addr(address)),
        None => format!("to: {}", short_addr(address)),
    }
}

// ----------------------------------------------------- spending wallet
// (PLAN-chain-notes-funding-unification.md, "Prime device" + M2/M3.)

/// Per-chunk OP_RETURN payload lengths for `text_len` bytes — the same
/// arithmetic `notes_core::bundle::estimate_note_cost` uses internally,
/// exposed locally because the funding-unification cost preview needs the
/// actual per-chunk lengths (for `tx::estimate_vsize_mixed`), not just the
/// single-taproot-input vsize that helper returns.
fn payload_lens_for(text_len: usize, private: bool, max_op_return_bytes: usize) -> Result<Vec<usize>, String> {
    let body_len = if private { text_len + notes_core::crypt::SEAL_OVERHEAD } else { text_len };
    if body_len == 0 {
        return Err("empty body".into());
    }
    if max_op_return_bytes <= notes_core::envelope::HEADER_LEN {
        return Err("max_payload smaller than header".into());
    }
    let chunk_size = max_op_return_bytes - notes_core::envelope::HEADER_LEN;
    let total = body_len.div_ceil(chunk_size);
    if total > u8::MAX as usize {
        return Err("too large (> 255 chunks)".into());
    }
    let mut payload_lens = vec![max_op_return_bytes; total - 1];
    let tail = body_len - (total - 1) * chunk_size;
    payload_lens.push(notes_core::envelope::HEADER_LEN + tail);
    Ok(payload_lens)
}

/// The active notebook's (rotation seed, BIP-86 account) context — the same
/// key a spending wallet is scoped at (`spending::SpendingIndex`).
fn notebook_ctx(ix: &notebooks::NotebookIndex, account: Option<u32>) -> Option<(u32, u32)> {
    let m = ix.get(account?)?;
    Some((m.seed, m.bip_account))
}

/// A Slint `FundingCoinRow.key` for one coin: "notebook:<txid>:<vout>" or
/// "spending:<txid>:<vout>" — stable, round-trips through `parse_funding_key`.
fn funding_key(spending: bool, txid: &str, vout: u32) -> String {
    format!("{}:{txid}:{vout}", if spending { "spending" } else { "notebook" })
}

fn parse_funding_key(key: &str) -> Option<(bool, String, u32)> {
    let mut parts = key.splitn(3, ':');
    let source = parts.next()?;
    let txid = parts.next()?.to_string();
    let vout: u32 = parts.next()?.parse().ok()?;
    Some((source == "spending", txid, vout))
}

/// Which coins currently fund the compose in progress. `touched` becomes
/// true the first time the user taps a coin on the Pay-from screen — until
/// then, an empty `spending` selection means "use today's byte-identical
/// auto-select over every notebook coin" (`compose_note`/
/// `compose_directed_note_with_change_amount`); once touched (or whenever
/// ANY spending coin is selected, touched or not — the default-source
/// rule), Continue spends EXACTLY the selected set.
#[derive(Default, Clone)]
struct FundingPick {
    notebook: Vec<(String, u32)>,
    spending: Vec<(String, u32)>,
    touched: bool,
}

impl FundingPick {
    fn is_selected(&self, spending: bool, txid: &str, vout: u32) -> bool {
        let set = if spending { &self.spending } else { &self.notebook };
        set.iter().any(|(t, v)| t == txid && *v == vout)
    }

    fn toggle(&mut self, spending: bool, txid: String, vout: u32) {
        let set = if spending { &mut self.spending } else { &mut self.notebook };
        if let Some(i) = set.iter().position(|(t, v)| *t == txid && *v == vout) {
            set.remove(i);
        } else {
            set.push((txid, vout));
        }
        self.touched = true;
    }

    /// "notebook" | "spending" | "mixed" | "none" — display + log label.
    fn mode_label(&self) -> &'static str {
        match (!self.notebook.is_empty(), !self.spending.is_empty()) {
            (true, true) => "mixed",
            (false, true) => "spending",
            (true, false) => "notebook",
            (false, false) => "none",
        }
    }
}

/// Default selection for a freshly-opened compose: spending ONLY when the
/// wallet is enabled AND has a balance (funding-unification's default-
/// source rule) — otherwise every notebook coin, exactly like compose
/// behaved before this feature existed.
fn default_funding_pick(st: &State, spending_section: Option<&spending::SpendingSection>) -> FundingPick {
    let spending_balance = spending_section.map(|s| s.balance()).unwrap_or(0);
    let use_spending =
        spending_section.map(|s| s.enabled).unwrap_or(false) && spending_balance > 0;
    if use_spending {
        FundingPick {
            notebook: Vec::new(),
            spending: spending_section
                .map(|s| s.utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect())
                .unwrap_or_default(),
            touched: false,
        }
    } else {
        FundingPick {
            notebook: st.utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect(),
            spending: Vec::new(),
            touched: false,
        }
    }
}

/// Change destination pick for the compose in progress.
#[derive(Clone)]
struct ChangePickState {
    choice: String, // "auto" | "notebook" | "custom"
    custom_address: String,
}

impl Default for ChangePickState {
    fn default() -> Self {
        ChangePickState { choice: "auto".into(), custom_address: String::new() }
    }
}

/// Resolve the change destination: "custom" parses the typed address;
/// "notebook" is always the notebook's own P2TR spk; "auto" is the notebook
/// UNLESS the current pick spends a spending-wallet coin, in which case it's
/// a fresh spending-wallet change address (protecting funds is the whole
/// point of the feature) — returned alongside the `SpendingAddress` to mark
/// used, which the caller persists ONLY after a successful sign (an aborted
/// compose must never burn a change index).
#[allow(clippy::too_many_arguments)]
fn resolve_change(
    choice: &str,
    custom_address: &str,
    network: Network,
    output_x: &[u8; 32],
    spending_participates: bool,
    app_seed: &[u8; 32],
    seed_index: u32,
    bip_account: u32,
    next_change_index: u32,
) -> Result<(Vec<u8>, Option<spending::SpendingAddress>), String> {
    match choice {
        "custom" => {
            let r = Recipient::parse(network, custom_address).map_err(|e| e.to_string())?;
            Ok((r.spk, None))
        }
        "notebook" => Ok((p2tr_script_pubkey(output_x), None)),
        _ => {
            if spending_participates {
                let key = notes_core::seeds::derive_spending_key(
                    app_seed,
                    seed_index,
                    network,
                    bip_account,
                    1,
                    next_change_index,
                )
                .map_err(|e| e.to_string())?;
                let addr = spending::SpendingAddress {
                    chain: 1,
                    index: next_change_index,
                    address: key.address,
                    spk_hex: hex::encode(&key.script_pubkey),
                };
                Ok((key.script_pubkey, Some(addr)))
            } else {
                Ok((p2tr_script_pubkey(output_x), None))
            }
        }
    }
}

/// Just the change spk's LENGTH, for the keystroke cost preview (no
/// derivation needed — P2WPKH/P2TR spk lengths are fixed regardless of the
/// specific address; only "custom" needs an actual parse).
fn change_spk_len_preview(
    choice: &str,
    custom_address: &str,
    network: Network,
    spending_participates: bool,
) -> Result<usize, String> {
    match choice {
        "custom" => {
            Recipient::parse(network, custom_address).map(|r| r.spk.len()).map_err(|e| e.to_string())
        }
        "notebook" => Ok(34),
        _ => Ok(if spending_participates { 22 } else { 34 }),
    }
}

// ---------------------------------------------------------------- main

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let fs = cx.fs.clone();
    let ui_weak = ui.as_weak();

    let plan: Rc<RefCell<Option<Plan>>> = Rc::new(RefCell::new(None));
    let sweep_plan: Rc<RefCell<Option<SweepPlan>>> = Rc::new(RefCell::new(None));

    // The app seed (GetAppSeed, PIN-gated on hardware) — kept so each
    // notebook's identity can be derived on demand (`Identity::from_bip86`
    // over the notebook's rotation seed + BIP-86 account/index).
    let app_seed: Rc<Option<[u8; 32]>> = Rc::new(
        match Security::default().app_seed() {
            Ok(seed) => Some(seed),
            Err(_) => {
                log::warn!("identity unavailable: device locked or seed unavailable");
                ui.global::<Ui>().set_error("Device locked or seed unavailable".into());
                None
            }
        },
    );

    // Notebooks: the index (account -> name/archived) + the ACTIVE notebook.
    // A notebook = an indexed identity; boot lands on the notebook LIST and
    // the active notebook is set when the user taps a row (empty on a fresh
    // install — the device has no onboarding).
    let notebooks: Rc<RefCell<notebooks::NotebookIndex>> =
        Rc::new(RefCell::new(boot_notebooks(&fs)));
    // Device-level network (wallet-wide): one setting shared by every
    // notebook; each notebook's ledger is per-network on disk.
    let device_cfg = boot_config(&fs, &notebooks.borrow());
    let net: Rc<RefCell<String>> = Rc::new(RefCell::new(device_cfg.network.clone()));
    let device_chunk: Rc<RefCell<Option<usize>>> =
        Rc::new(RefCell::new(device_cfg.chunk_override));
    // Active wallet context (recovery-seeds): rotation seed index + BIP-86
    // account. New notebooks derive under it; the list + wallet features
    // scope to it (legacy notebooks are context-free).
    let seed_idx: Rc<RefCell<u32>> = Rc::new(RefCell::new(device_cfg.seed_index));
    let bip_account: Rc<RefCell<u32>> = Rc::new(RefCell::new(device_cfg.account));
    let active: Rc<RefCell<Option<u32>>> = Rc::new(RefCell::new(None));

    // Persist the device config from the current cells (single source of
    // truth — inline DeviceConfig constructions drift as fields grow).
    let persist_config = {
        let fs = fs.clone();
        let net = net.clone();
        let device_chunk = device_chunk.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        Rc::new(move || {
            save_config(
                &fs,
                &DeviceConfig {
                    network: net.borrow().clone(),
                    chunk_override: *device_chunk.borrow(),
                    seed_index: *seed_idx.borrow(),
                    account: *bip_account.borrow(),
                },
            );
        })
    };
    // The ACTIVE notebook's state + identity (both swap on notebook switch);
    // an empty placeholder until a notebook is opened.
    let state = Rc::new(RefCell::new(State::default()));
    let identity: Rc<RefCell<Option<Identity>>> = Rc::new(RefCell::new(None));


    let refresh_home = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let net = net.clone();
        let device_chunk = device_chunk.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let home = ui.global::<Home>();
            home.set_network(net.borrow().clone().into()); // device-level network
            if let Some(id) = identity.borrow().as_ref() {
                let addr = id.address(st.network());
                home.set_qr(qr_image(&addr.to_uppercase()));
                home.set_address(addr.into());
            }
            home.set_balance_line(sats_line(st.balance(), st.btc_usd).into());
            let sync_line = match st.tip_height {
                Some(h) => format!("synced to height {h}"),
                None => "never synced".to_string(),
            };
            home.set_sync_line(sync_line.into());
            let sync = ui.global::<Sync>();
            sync.set_status(
                format!(
                    "network: {}\nbalance: {} sats · {} utxos\nchain height: {}\nfees (sat/vB): {}/{}/{} · chunk: {} bytes",
                    st.network,
                    st.balance(),
                    st.utxos.len(),
                    st.tip_height.map(|h| h.to_string()).unwrap_or("—".into()),
                    st.fee_economy,
                    st.fee_normal,
                    st.fee_fast,
                    st.effective_chunk()
                )
                .into(),
            );
            let settings = ui.global::<Settings>();
            let dchunk = *device_chunk.borrow();
            settings.set_chunk_mode(match dchunk {
                None => 0,
                Some(80) => 1,
                Some(_) => 2,
            });
            let eff = dchunk.map(|c| c.clamp(MIN_CHUNK, DEFAULT_CHUNK)).unwrap_or(DEFAULT_CHUNK);
            settings.set_chunk_text(format!("{eff}").into());
            log::info!(
                "cb: home balance={} utxos={} tip={}",
                st.balance(),
                st.utxos.len(),
                st.tip_height.map(|h| h.to_string()).unwrap_or("none".into())
            );
        }
    };

    let refresh_notes = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            // Sender filter: build the checklist + filter the list. A note
            // is hidden iff its sender key is in the persisted exclusion set.
            let senders: Vec<SenderRow> = st
                .senders()
                .into_iter()
                .map(|(key, count)| {
                    let label = if key == "self" {
                        "Self".to_string()
                    } else {
                        st.contacts
                            .iter()
                            .find(|c| c.address == key && !c.name.is_empty())
                            .map(|c| c.name.clone())
                            .unwrap_or_else(|| short_addr(&key))
                    };
                    SenderRow {
                        excluded: st.is_excluded(&key),
                        key: key.into(),
                        label: label.into(),
                        sub: format!("{count} note(s)").into(),
                    }
                })
                .collect();
            let hidden = senders.iter().filter(|s| s.excluded).count();
            let notes_g = ui.global::<Notes>();
            notes_g.set_senders(Rc::new(VecModel::from(senders)).into());
            notes_g.set_hidden_label(
                if hidden == 0 { "".to_string() } else { format!("{hidden} sender(s) hidden") }.into(),
            );
            let mut recs: Vec<&NoteRec> =
                st.notes.iter().filter(|n| !st.is_excluded(&State::sender_key(n))).collect();
            // Pending first, then newest confirmed first.
            recs.sort_by_key(|n| match n.height {
                None => (0u8, 0i64),
                Some(h) => (1u8, -(h as i64)),
            });
            let rows: Vec<NoteRow> = recs
                .iter()
                .map(|n| NoteRow {
                    id: n.id.clone().into(),
                    preview: preview_of(&n.text).into(),
                    meta: {
                        let base = match n.height {
                            Some(h) => format!("block {h} · {} chunk(s)", n.chunks.max(1)),
                            None => format!("pending · fee {} sats", n.fee),
                        };
                        match (&n.from, &n.to) {
                            (Some(from), _) => format!("{base} · from {}", short_addr(from)),
                            (None, Some(to)) => format!("{base} · to {}", short_addr(to)),
                            _ => base,
                        }
                    }
                    .into(),
                    badge: if n.private { "PRIVATE" } else { "PUBLIC" }.into(),
                })
                .collect();
            log::info!("cb: refresh-notes n={} hidden={hidden}", rows.len());
            notes_g.set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    let refresh_contacts = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            // State order IS recency (front = latest use) — no re-sort.
            let rows: Vec<ContactRow> = st
                .contacts
                .iter()
                .map(|c| ContactRow {
                    address: c.address.clone().into(),
                    name: c.name.clone().into(),
                    label: if c.name.is_empty() { short_addr(&c.address) } else { c.name.clone() }
                        .into(),
                    meta: short_addr(&c.address).into(),
                })
                .collect();
            log::info!("cb: refresh-contacts n={}", rows.len());
            ui.global::<Contacts>().set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    // Coins screen (9): the UTXO ledger as of the last sync bundle, biggest
    // first. Viewer-first — consolidate is the screen's single action.
    let refresh_coins = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            // Wallet-wide: every ACTIVE notebook's coins, each tagged with
            // its notebook. Flush the active notebook first so its file is
            // current, then read all from disk.
            save_state(&fs, &state.borrow());
            let ix = notebooks.borrow();
            let active_net = net.borrow().clone();
            let ctx = (*seed_idx.borrow(), *bip_account.borrow());
            let btc_usd = state.borrow().btc_usd;
            // (value, notebook name, txid, vout) across the wallet.
            let mut all: Vec<(u64, String, String, u32)> = Vec::new();
            let mut nb_with_coins = 0usize;
            for m in ix.visible(ctx.0, ctx.1) {
                let st2 = load_state(&fs, &active_net, m.account);
                if st2.utxos.is_empty() {
                    continue;
                }
                nb_with_coins += 1;
                let short = derive_identity(&app_seed, m, &active_net)
                    .map(|id| short_addr(&id.address(st2.network())))
                    .unwrap_or_default();
                let name = notebook_name(&ix, m.account, &short);
                for u in &st2.utxos {
                    all.push((u.value, name.clone(), u.txid.clone(), u.vout));
                }
            }
            all.sort_by_key(|(v, ..)| std::cmp::Reverse(*v));
            let total: u64 = all.iter().map(|(v, ..)| v).sum();
            let rows: Vec<CoinRow> = all
                .iter()
                .map(|(v, name, txid, vout)| CoinRow {
                    label: format!("{v} sats · {name}").into(),
                    meta: format!("txid {} · output {}", short_addr(txid), vout).into(),
                })
                .collect();
            let coins = ui.global::<Coins>();
            coins.set_summary(
                format!(
                    "{} coin(s) · {} across {nb_with_coins} notebook(s)",
                    rows.len(),
                    sats_line(total, btc_usd)
                )
                .into(),
            );
            coins.set_can_consolidate(rows.len() >= 2);
            log::info!("cb: refresh-coins n={} total={total} notebooks={nb_with_coins}", rows.len());
            coins.set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    // Sweep screen (10) repricing — every tier tap / rate keystroke. Pure
    // arithmetic (estimate_sweep_vsize is byte-exact vs build_sweep_tx).
    let update_sweep = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let sweep = ui.global::<Sweep>();
            let st = state.borrow();
            let tier = sweep.get_tier();
            if tier != 3 {
                sweep.set_rate_text(format!("{}", st.fee_rate(tier)).into());
            }
            // Wallet-level: inputs are EVERY notebook's coins (flush the
            // active one first so its file reflects the latest ledger).
            save_state(&fs, &st);
            let (n, total) = wallet_balance(
                &fs,
                &notebooks.borrow(),
                &st.network,
                (*seed_idx.borrow(), *bip_account.borrow()),
            );
            sweep.set_inputs_line(format!("Inputs · {n} coin(s) · {total} sats (all notebooks)").into());
            if n == 0 {
                sweep.set_cost_line("Nothing to sweep — no spendable coins.".into());
                sweep.set_can_continue(false);
                return;
            }
            let rate = match resolve_rate(tier, sweep.get_rate_text().as_str(), &st) {
                Ok(r) => r,
                Err(e) => {
                    sweep.set_cost_line(e.into());
                    sweep.set_can_continue(false);
                    return;
                }
            };
            let consolidate = sweep.get_kind() == "consolidate";
            let dest_spk_len = if consolidate {
                34 // our own P2TR
            } else {
                match Recipient::parse(st.network(), sweep.get_dest().as_str()) {
                    Ok(r) => r.spk.len(),
                    Err(_) => {
                        sweep.set_cost_line(
                            format!("Destination is not a valid {} address.", st.network).into(),
                        );
                        sweep.set_can_continue(false);
                        return;
                    }
                }
            };
            let vsize = estimate_sweep_vsize(n, dest_spk_len);
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total <= fee || total - fee < notes_core::DUST_LIMIT {
                sweep.set_cost_line(
                    format!("Balance {total} sats can't cover the ~{fee} sat fee.").into(),
                );
                sweep.set_can_continue(false);
                return;
            }
            let recv = total - fee;
            sweep.set_cost_line(
                if consolidate {
                    format!(
                        "Consolidates {n} coins into one · ~{vsize} vB · fee ~{} @ {rate} sat/vB · keeps {recv} sats",
                        sats_line(fee, st.btc_usd)
                    )
                } else {
                    format!(
                        "Sweeps {total} sats · ~{vsize} vB · fee ~{} @ {rate} sat/vB · destination receives {recv} sats",
                        sats_line(fee, st.btc_usd)
                    )
                }
                .into(),
            );
            sweep.set_can_continue(true);
        }
    };

    // Funding-unification: current per-coin funding pick + change pick for
    // the compose in progress. Reset to the default rule whenever a fresh
    // compose is entered (see `pick_contact` below).
    let funding_pick: Rc<RefCell<FundingPick>> = Rc::new(RefCell::new(FundingPick::default()));
    let change_pick: Rc<RefCell<ChangePickState>> = Rc::new(RefCell::new(ChangePickState::default()));

    // Rebuild the Pay-from screen's rows/summaries, the compose nav row's
    // label, AND Settings' spending card (same underlying section) from
    // `state` + the active notebook's spending section + `funding_pick`.
    let refresh_funding = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let funding_pick = funding_pick.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let active_net = net.borrow().clone();
            let ix = notebooks.borrow();
            let ctx = notebook_ctx(&ix, *active.borrow())
                .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
            let section = ix.spending(&active_net, ctx.0, ctx.1).cloned();
            drop(ix);
            let pick = funding_pick.borrow();

            let nb_rows: Vec<FundingCoinRow> = st
                .utxos
                .iter()
                .map(|u| FundingCoinRow {
                    key: funding_key(false, &u.txid, u.vout).into(),
                    label: format!("{} sats", u.value).into(),
                    meta: format!("txid {} · output {}", short_addr(&u.txid), u.vout).into(),
                    selected: pick.is_selected(false, &u.txid, u.vout),
                })
                .collect();
            let nb_total: u64 = st.utxos.iter().map(|u| u.value).sum();
            let nb_selected_total: u64 = st
                .utxos
                .iter()
                .filter(|u| pick.is_selected(false, &u.txid, u.vout))
                .map(|u| u.value)
                .sum();

            let sp_rows: Vec<FundingCoinRow> = section
                .as_ref()
                .map(|s| {
                    s.utxos
                        .iter()
                        .map(|u| FundingCoinRow {
                            key: funding_key(true, &u.txid, u.vout).into(),
                            label: format!("{} sats", u.value).into(),
                            meta: format!(
                                "txid {} · output {} · idx {}",
                                short_addr(&u.txid),
                                u.vout,
                                u.index
                            )
                            .into(),
                            selected: pick.is_selected(true, &u.txid, u.vout),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let sp_total = section.as_ref().map(|s| s.balance()).unwrap_or(0);
            let sp_enabled = section.as_ref().map(|s| s.enabled).unwrap_or(false);
            let sp_selected_total: u64 = section
                .as_ref()
                .map(|s| {
                    s.utxos
                        .iter()
                        .filter(|u| pick.is_selected(true, &u.txid, u.vout))
                        .map(|u| u.value)
                        .sum()
                })
                .unwrap_or(0);

            let funding = ui.global::<Funding>();
            funding.set_notebook_coins(Rc::new(VecModel::from(nb_rows)).into());
            funding.set_spending_coins(Rc::new(VecModel::from(sp_rows)).into());
            funding.set_notebook_summary(
                format!("{} coin(s) · {} sats", st.utxos.len(), nb_total).into(),
            );
            funding.set_spending_summary(
                if !sp_enabled {
                    "Off".to_string()
                } else if sp_total == 0 {
                    "No coins".to_string()
                } else {
                    format!(
                        "{} coin(s) · {} sats",
                        section.as_ref().map(|s| s.utxos.len()).unwrap_or(0),
                        sp_total
                    )
                }
                .into(),
            );
            funding.set_spending_enabled(sp_enabled);
            let mode = pick.mode_label();
            let selected_total = nb_selected_total + sp_selected_total;
            let selected_n = pick.notebook.len() + pick.spending.len();
            funding.set_warning(
                if mode == "mixed" {
                    "This note spends from both the notebook and the spending wallet — their addresses become publicly linked on-chain.".to_string()
                } else {
                    String::new()
                }
                .into(),
            );

            let compose = ui.global::<Compose>();
            compose.set_pay_from_label(
                match mode {
                    "mixed" => "Mixed",
                    "spending" => "Spending wallet",
                    _ => "Notebook",
                }
                .into(),
            );
            compose
                .set_pay_from_balance(format!("{selected_total} sats · {selected_n} coin(s)").into());

            // Settings' spending card mirrors the SAME section — harmless to
            // refresh even when Settings isn't the visible screen.
            let settings = ui.global::<Settings>();
            settings.set_spending_enabled(sp_enabled);
            if let Some(s) = &section {
                settings.set_spending_balance_line(
                    format!("{} coin(s) · {} sats", s.utxos.len(), s.balance()).into(),
                );
                if let Some(seed) = app_seed.as_ref() {
                    let net_v = Network::from_str_opt(&active_net).unwrap_or(Network::Mainnet);
                    if let Ok(key) = notes_core::seeds::derive_spending_key(
                        seed, ctx.0, net_v, ctx.1, 0, s.next_receive,
                    ) {
                        settings.set_spending_address(key.address.clone().into());
                        settings.set_spending_qr(qr_image(&key.address.to_uppercase()));
                    }
                }
                let addr_lines: Vec<String> = s
                    .used
                    .iter()
                    .map(|a| {
                        format!(
                            "{}/{}  {}",
                            if a.chain == 1 { "change" } else { "receive" },
                            a.index,
                            a.address
                        )
                    })
                    .collect();
                settings.set_spending_addresses_text(addr_lines.join("\n").into());
            } else {
                settings.set_spending_balance_line("0 coin(s) · 0 sats".into());
                settings.set_spending_addresses_text("".into());
            }
        }
    };

    // Rebuild the compose nav row's Change label + the Change screen's
    // "Auto" sub-line from `change_pick` + whether the CURRENT funding pick
    // spends any spending-wallet coin.
    let refresh_change = {
        let ui_weak = ui_weak.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let participates = !funding_pick.borrow().spending.is_empty();
            let cp = change_pick.borrow();
            let auto_label = if participates {
                "Fresh spending-wallet address — protects the change from address reuse."
            } else {
                "Notebook address — the same address it goes to today."
            };
            ui.global::<ChangePick>().set_auto_label(auto_label.into());
            let label = match cp.choice.as_str() {
                "custom" if !cp.custom_address.is_empty() => short_addr(&cp.custom_address),
                "custom" => "custom address".to_string(),
                "notebook" => "notebook".to_string(),
                _ if participates => "fresh spending address".to_string(),
                _ => "back to you".to_string(),
            };
            ui.global::<Compose>().set_change_label(label.into());
        }
    };

    // A notebook's display name: its local name, else its address short
    // form (never empty — rows and the home title read this).
    fn notebook_name(ix: &notebooks::NotebookIndex, account: u32, addr_short: &str) -> String {
        match ix.get(account).map(|m| m.name.clone()) {
            Some(n) if !n.trim().is_empty() => n,
            _ => addr_short.to_string(),
        }
    }

    // Rebuild the notebook list (screen 20) from the index + each
    // notebook's state file. Device has no live balance — the row meta is
    // address-short · note count.
    let refresh_notebooks = {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        Rc::new(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let ix = notebooks.borrow();
            let active_acct = *active.borrow();
            let dev_net = net.borrow().clone();
            let ctx = (*seed_idx.borrow(), *bip_account.borrow());
            let build = |m: &notebooks::NotebookMeta| -> NotebookRow {
                let st = load_state(&fs, &dev_net, m.account);
                let addr = derive_identity(&app_seed, m, &dev_net)
                    .map(|id| id.address(Network::from_str_opt(&dev_net).unwrap_or(Network::Mainnet)))
                    .unwrap_or_default();
                let short = short_addr(&addr);
                let n = st.notes.len();
                NotebookRow {
                    account: m.account as i32,
                    name: notebook_name(&ix, m.account, &short).into(),
                    meta: format!(
                        "{short} · {n} note{}",
                        if n == 1 { "" } else { "s" }
                    )
                    .into(),
                    active: active_acct == Some(m.account),
                }
            };
            let rows: Vec<NotebookRow> = ix.visible(ctx.0, ctx.1).map(build).collect();
            let archived: Vec<NotebookRow> =
                ix.archived_in_context(ctx.0, ctx.1).map(build).collect();
            let nb = ui.global::<NotebooksUi>();
            nb.set_empty_line(
                if rows.is_empty() {
                    if !archived.is_empty() {
                        "All notebooks are archived.".into()
                    } else {
                        "No notebooks yet — create one to start writing.".into()
                    }
                } else {
                    "".into()
                },
            );
            nb.set_archived_label(
                if archived.is_empty() {
                    "".to_string()
                } else {
                    format!("Archived ({})", archived.len())
                }
                .into(),
            );
            log::info!("cb: notebooks list n={} archived={}", rows.len(), archived.len());
            nb.set_rows(Rc::new(VecModel::from(rows)).into());
            nb.set_archived_rows(Rc::new(VecModel::from(archived)).into());
        })
    };

    // Open a notebook: save the current one, swap identity + state to the
    // target account, refresh every per-notebook view, and show its home.
    let switch_notebook = {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let state = state.clone();
        let identity = identity.clone();
        let active = active.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let net = net.clone();
        let device_chunk = device_chunk.clone();
        let refresh_home = refresh_home.clone();
        let refresh_notes = refresh_notes.clone();
        let refresh_coins = refresh_coins.clone();
        let refresh_contacts = refresh_contacts.clone();
        let refresh_funding = refresh_funding.clone();
        Rc::new(move |account: u32| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if active.borrow().is_some() {
                save_state(&fs, &state.borrow());
            }
            *active.borrow_mut() = Some(account);
            *identity.borrow_mut() = notebooks
                .borrow()
                .get(account)
                .and_then(|m| derive_identity(&app_seed, m, &net.borrow()));
            let mut loaded = load_state(&fs, &net.borrow(), account);
            loaded.chunk_override = *device_chunk.borrow(); // chunk is device-level
            *state.borrow_mut() = loaded;
            let short = identity
                .borrow()
                .as_ref()
                .map(|id| short_addr(&id.address(state.borrow().network())))
                .unwrap_or_default();
            let title = notebook_name(&notebooks.borrow(), account, &short);
            ui.global::<NotebooksUi>().set_title(title.into());
            log::info!("cb: open-notebook account={account}");
            refresh_home();
            refresh_notes();
            refresh_coins();
            refresh_contacts();
            refresh_funding();
            ui.global::<Ui>().set_screen(0);
        })
    };

    // The single pick funnel (self row / recent row / manual entry / scan):
    // validates, bumps recency, sets the compose recipient + label, and
    // navigates. Invalid manual input stays on the picker with an error.
    let pick_contact = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let update_sweep = update_sweep.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        let refresh_funding = refresh_funding.clone();
        let refresh_change = refresh_change.clone();
        move |addr_raw: &str| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let addr = addr_raw.trim().to_string();
            let contacts_g = ui.global::<Contacts>();
            let sweep_mode = contacts_g.get_pick_mode() == "sweep";
            let compose = ui.global::<Compose>();
            if addr.is_empty() {
                // Self: compose only — the sweep picker hides the Self card
                // (sweep-to-self is the Coins screen's consolidate).
                if sweep_mode {
                    return;
                }
                compose.set_to_address("".into());
                compose.set_to_label("to: self — my notebook".into());
                log::info!("cb: pick-contact to=self");
            } else {
                let mut st = state.borrow_mut();
                if Recipient::parse(st.network(), &addr).is_err() {
                    contacts_g
                        .set_input_error(format!("Not a valid {} address.", st.network).into());
                    log::warn!("cb: pick-contact err=invalid address");
                    return;
                }
                upsert_contact(&mut st, &addr);
                save_state(&fs, &st);
                if sweep_mode {
                    let sweep = ui.global::<Sweep>();
                    sweep.set_kind("sweep".into());
                    sweep.set_dest(addr.as_str().into());
                    sweep.set_dest_label(to_label_for(&st, &addr).into());
                    sweep.set_tier(1);
                    log::info!("cb: sweep-open kind=sweep to={addr}");
                } else {
                    compose.set_to_address(addr.as_str().into());
                    compose.set_to_label(to_label_for(&st, &addr).into());
                    log::info!("cb: pick-contact to={addr}");
                }
            }
            contacts_g.set_input_text("".into());
            contacts_g.set_input_error("".into());
            contacts_g.set_naming_address("".into());
            if sweep_mode {
                update_sweep();
                ui.global::<Ui>().set_screen(10);
            } else {
                // Fresh compose: reset the funding/change picks to their
                // default rule (spending only when enabled AND funded).
                let st = state.borrow();
                let ix = notebooks.borrow();
                let ctx = notebook_ctx(&ix, *active.borrow())
                    .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                let section = ix.spending(&net.borrow(), ctx.0, ctx.1).cloned();
                drop(ix);
                *funding_pick.borrow_mut() = default_funding_pick(&st, section.as_ref());
                drop(st);
                *change_pick.borrow_mut() = ChangePickState::default();
                refresh_funding();
                refresh_change();
                ui.global::<Callbacks>().invoke_compose_changed();
                ui.global::<Ui>().set_screen(3);
            }
        }
    };

    {
        let pick_contact = pick_contact.clone();
        ui.global::<Callbacks>().on_pick_contact(move |addr| pick_contact(addr.as_str()));
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let pick_contact = pick_contact.clone();
        ui.global::<Callbacks>().on_scan_contact(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let opts = ScanQrOptions {
                header_title: "Scan recipient address".into(),
                message: "Point at an address QR (a companion page or another Prime's home screen)"
                    .into(),
                ..ScanQrOptions::default()
            };
            let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr(data))) | Ok(Some(ScanQrResult::Ur2(_, data))) => data,
                Ok(_) => {
                    log::info!("cb: scan-contact cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: scan-contact err=scanner {e:?}");
                    ui.global::<Contacts>()
                        .set_input_error(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            // Address QRs are plain text, possibly a BIP21 URI, and
            // legitimately ALL-UPPERCASE (our own home QR is) — normalize.
            let text = String::from_utf8(data).unwrap_or_default();
            let mut addr = text.trim();
            if addr.len() >= 8 && addr[..8].eq_ignore_ascii_case("bitcoin:") {
                addr = &addr[8..];
            }
            let addr = addr.split('?').next().unwrap_or("").trim().to_string();
            let st = state.borrow();
            let network = st.network();
            let network_name = st.network.clone();
            drop(st);
            let resolved = if Recipient::parse(network, &addr).is_ok() {
                Some(addr.clone())
            } else {
                let lower = addr.to_lowercase();
                Recipient::parse(network, &lower).is_ok().then_some(lower)
            };
            match resolved {
                Some(a) => {
                    log::info!("cb: scan-contact ok addr={a}");
                    pick_contact(&a);
                }
                None => {
                    log::warn!("cb: scan-contact err=not an address");
                    ui.global::<Contacts>().set_input_error(
                        format!("QR didn't contain a valid {network_name} address.").into(),
                    );
                }
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let refresh_contacts = refresh_contacts.clone();
        ui.global::<Callbacks>().on_save_contact_name(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let contacts_g = ui.global::<Contacts>();
            let addr = contacts_g.get_naming_address().to_string();
            if addr.is_empty() {
                return;
            }
            let name = contacts_g.get_name_text().trim().to_string();
            let mut st = state.borrow_mut();
            // Naming does NOT bump recency — only use does, so the row
            // being edited never jumps mid-interaction.
            if let Some(c) = st.contacts.iter_mut().find(|c| c.address == addr) {
                c.name = name.clone();
            }
            save_state(&fs, &st);
            drop(st);
            log::info!("cb: save-contact addr={addr} name-len={}", name.len());
            contacts_g.set_naming_address("".into());
            contacts_g.set_name_text("".into());
            refresh_contacts();
        });
    }

    {
        let refresh_coins = refresh_coins.clone();
        ui.global::<Callbacks>().on_refresh_coins(move || refresh_coins());
    }

    // Coins → the shared sweep screen with kind=consolidate, dest=self.
    {
        let ui_weak = ui_weak.clone();
        let update_sweep = update_sweep.clone();
        ui.global::<Callbacks>().on_consolidate_open(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let sweep = ui.global::<Sweep>();
            sweep.set_kind("consolidate".into());
            sweep.set_dest("".into());
            sweep.set_dest_label("to: self — one consolidated coin".into());
            sweep.set_tier(1);
            log::info!("cb: sweep-open kind=consolidate to=self");
            update_sweep();
            ui.global::<Ui>().set_screen(10);
        });
    }

    {
        let update_sweep = update_sweep.clone();
        ui.global::<Callbacks>().on_sweep_changed(move || update_sweep());
    }

    // Build + sign the sweep (ALL coins, key-path), then the confirm dialog.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let sweep_plan = sweep_plan.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let active = active.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        ui.global::<Callbacks>().on_sweep_continue(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let identity = identity.clone();
            let sweep_plan = sweep_plan.clone();
            let fs = fs.clone();
            let notebooks = notebooks.clone();
            let app_seed = app_seed.clone();
            let active = active.clone();
            let seed_idx = seed_idx.clone();
            let bip_account = bip_account.clone();
            // Let the busy overlay paint one frame before the blocking work.
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let sweep = ui.global::<Sweep>();
                let consolidate = sweep.get_kind() == "consolidate";
                let kind = if consolidate { "consolidate" } else { "sweep" };
                let dest = sweep.get_dest().trim().to_string();
                let tier = sweep.get_tier();
                let rate_text = sweep.get_rate_text().to_string();
                let st = state.borrow();
                // Flush the active notebook, then gather EVERY notebook's
                // coins — a wallet-level sweep/consolidate, one multi-key tx.
                save_state(&fs, &st);
                let sources_raw = wallet_sources(
                    &fs,
                    &notebooks.borrow(),
                    &app_seed,
                    &st.network,
                    (*seed_idx.borrow(), *bip_account.borrow()),
                );
                let dest_account = active.borrow().unwrap_or(0);
                let id_guard = identity.borrow();
                let result = id_guard
                    .as_ref()
                    .ok_or_else(|| "identity unavailable".to_string())
                    .and_then(|id| {
                        let rate = resolve_rate(tier, &rate_text, &st)?;
                        if sources_raw.is_empty() {
                            return Err("No spendable coins in the wallet.".to_string());
                        }
                        let dest_spk = if consolidate {
                            p2tr_script_pubkey(&id.output_x)
                        } else {
                            Recipient::parse(st.network(), &dest).map_err(|e| e.to_string())?.spk
                        };
                        let sources: Vec<SweepSource> = sources_raw
                            .iter()
                            .map(|(_, ox, sk, coins)| SweepSource {
                                utxos: coins,
                                output_x: *ox,
                                tweaked_seckey: sk,
                            })
                            .collect();
                        build_sweep_tx_multi(&sources, dest_spk, rate, generate_aux_rand)
                            .map_err(|e| e.to_string())
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok(tx) => {
                        let total: u64 = sources_raw.iter().flat_map(|(_, _, _, c)| c).map(|u| u.value).sum();
                        let recv = tx.tx.outputs[0].value;
                        let n_notebooks = sources_raw.len();
                        // Spent outpoints per source notebook (display txid).
                        let spent_by_account: Vec<(u32, Vec<(String, u32)>)> = sources_raw
                            .iter()
                            .map(|(acct, _, _, coins)| {
                                let outs = coins
                                    .iter()
                                    .map(|u| {
                                        let mut t = u.txid;
                                        t.reverse();
                                        (hex::encode(t), u.vout)
                                    })
                                    .collect();
                                (*acct, outs)
                            })
                            .collect();
                        log::info!(
                            "cb: sweep kind={kind} to={} inputs={} notebooks={n_notebooks} amount={recv} fee={} vsize={} txid={} ok",
                            if consolidate { "self" } else { dest.as_str() },
                            tx.tx.inputs.len(),
                            tx.fee,
                            tx.vsize,
                            tx.txid_hex
                        );
                        // On-chain linkage warning when >1 notebook contributes.
                        let link = if n_notebooks > 1 {
                            "\n\nHeads up: this spends coins from several notebooks in one tx, publicly linking their addresses on-chain."
                        } else {
                            ""
                        };
                        sweep.set_confirm_summary(
                            format!(
                                "{}\n\ninputs: {} coin(s) from {n_notebooks} notebook(s) · {total} sats\nfee: {}\n{}: {recv} sats{link}\n\ntxid:\n{}",
                                if consolidate {
                                    "Consolidates the WHOLE wallet into one coin at this notebook's address."
                                } else {
                                    "Sweeps the WHOLE wallet to the destination — this empties every notebook."
                                },
                                tx.tx.inputs.len(),
                                sats_line(tx.fee, st.btc_usd),
                                if consolidate { "new coin" } else { "destination receives" },
                                tx.txid_hex
                            )
                            .into(),
                        );
                        *sweep_plan.borrow_mut() = Some(SweepPlan {
                            tx,
                            kind: if consolidate { "consolidate" } else { "sweep" },
                            dest: (!consolidate).then(|| dest.clone()),
                            spent_by_account,
                            dest_account,
                        });
                        sweep.set_show_confirm(true);
                    }
                    Err(e) => {
                        log::warn!("cb: sweep kind={kind} err={e}");
                        sweep.set_cost_line(format!("Cannot build: {e}").into());
                    }
                }
            });
        });
    }

    // Confirmed: persist the ledger effect, export the signed tx (internal +
    // Airlock outbox), and hand off on the shared "Signed" screen (8) with
    // the broadcast QR. Money flows return home from there.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let sweep_plan = sweep_plan.clone();
        let fs = fs.clone();
        let active = active.clone();
        let net = net.clone();
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_sweep_sign(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(p) = sweep_plan.borrow_mut().take() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let fs = fs.clone();
            let active = active.clone();
            let net = net.clone();
            let refresh_home = refresh_home.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let mut st = state.borrow_mut();
                let active_acct = active.borrow().unwrap_or(p.dest_account);

                // Wallet-level ledger: remove each notebook's spent inputs
                // from its own state file (the active one via the live
                // `st`); a consolidate's single output lands in the
                // destination notebook as its new (unconfirmed) coin.
                let inputs: usize = p.spent_by_account.iter().map(|(_, o)| o.len()).sum();
                let recv = p.tx.tx.outputs[0].value;
                for (acct, spent) in &p.spent_by_account {
                    if *acct == active_acct {
                        st.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));
                    } else {
                        let mut other = load_state(&fs, &net.borrow(), *acct);
                        other.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));
                        save_state(&fs, &other);
                    }
                }
                if p.kind == "consolidate" {
                    let coin = UtxoRec { txid: p.tx.txid_hex.clone(), vout: 0, value: recv };
                    if p.dest_account == active_acct {
                        st.utxos.push(coin);
                    } else {
                        let mut dest = load_state(&fs, &net.borrow(), p.dest_account);
                        dest.utxos.push(coin);
                        save_state(&fs, &dest);
                    }
                }

                let file = format!("{OUTBOX_DIR}/{}.hex", p.tx.txid_hex);
                let internal = ensure_dir(&fs, OUTBOX_DIR, Location::User)
                    .and_then(|_| write_file(&fs, &file, Location::User, p.tx.raw_hex.as_bytes()));
                let airlock = ensure_airlock_mounted(&fs).and_then(|_| {
                    let r = ensure_dir(&fs, OUTBOX_DIR, Location::Airlock).and_then(|_| {
                        write_file(&fs, &file, Location::Airlock, p.tx.raw_hex.as_bytes())
                    });
                    unmount_airlock(&fs);
                    r
                });
                save_state(&fs, &st);
                log::info!(
                    "cb: sign-sweep kind={} txid={} fee={} internal={} airlock={}",
                    p.kind,
                    p.tx.txid_hex,
                    p.tx.fee,
                    if internal.is_ok() { "ok" } else { "err" },
                    if airlock.is_ok() { "ok" } else { "err" },
                );
                drop(st);

                let sp = ui.global::<SignPsbt>();
                sp.set_summary(
                    format!(
                        "{}\nfee {} sats · {} vB\ntxid: {}",
                        match (p.kind, &p.dest) {
                            ("consolidate", _) =>
                                format!("Consolidated {inputs} coin(s) into one · {recv} sats"),
                            (_, Some(d)) =>
                                format!("Swept {inputs} coin(s) · {recv} sats to {}", short_addr(d)),
                            _ => format!("Swept {inputs} coin(s) · {recv} sats"),
                        },
                        p.tx.fee,
                        p.tx.vsize,
                        p.tx.txid_hex
                    )
                    .into(),
                );
                if p.tx.raw_hex.len() <= MAX_QR_HEX_CHARS {
                    sp.set_qr(qr_image(&p.tx.raw_hex.to_uppercase()));
                    sp.set_has_qr(true);
                } else {
                    sp.set_has_qr(false);
                }
                sp.set_back_screen(0);

                // Reset the sweep flow so nothing leaks into the next run.
                let sweep = ui.global::<Sweep>();
                sweep.set_show_confirm(false);
                sweep.set_dest("".into());
                sweep.set_dest_label("".into());
                sweep.set_tier(1);
                sweep.set_cost_line("".into());
                sweep.set_can_continue(false);
                ui.global::<Contacts>().set_pick_mode("compose".into());

                ui.global::<Ui>().set_busy(false);
                refresh_home();
                ui.global::<Ui>().set_screen(8);
            });
        });
    }

    // Spending wallet: Settings toggle.
    {
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let refresh_funding = refresh_funding.clone();
        ui.global::<Callbacks>().on_set_spending_enabled(move |on| {
            let mut ix = notebooks.borrow_mut();
            let ctx = notebook_ctx(&ix, *active.borrow())
                .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
            let net_s = net.borrow().clone();
            ix.spending_mut(&net_s, ctx.0, ctx.1).enabled = on;
            save_notebooks(&fs, &ix);
            drop(ix);
            log::info!("cb: set-spending enabled={on}");
            refresh_funding();
        });
    }

    // Pay-from screen (25): notebook / spending-wallet per-coin selection.
    {
        let refresh_funding = refresh_funding.clone();
        ui.global::<Callbacks>().on_funding_open(move || {
            log::info!("cb: funding-open");
            refresh_funding();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let funding_pick = funding_pick.clone();
        let refresh_funding = refresh_funding.clone();
        let refresh_change = refresh_change.clone();
        ui.global::<Callbacks>().on_funding_toggle_coin(move |key| {
            let Some(ui) = ui_weak.upgrade() else { return };
            if let Some((spending_src, txid, vout)) = parse_funding_key(key.as_str()) {
                funding_pick.borrow_mut().toggle(spending_src, txid, vout);
            }
            refresh_funding();
            refresh_change();
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }
    {
        let funding_pick = funding_pick.clone();
        ui.global::<Callbacks>().on_funding_done(move || {
            let pick = funding_pick.borrow();
            log::info!(
                "cb: pay-from {} coins={}",
                pick.mode_label(),
                pick.notebook.len() + pick.spending.len()
            );
        });
    }

    // Change screen (26): compose destination for change.
    {
        let refresh_change = refresh_change.clone();
        ui.global::<Callbacks>().on_change_open(move || {
            refresh_change();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let change_pick = change_pick.clone();
        let refresh_change = refresh_change.clone();
        ui.global::<Callbacks>().on_change_pick(move |choice| {
            let Some(ui) = ui_weak.upgrade() else { return };
            change_pick.borrow_mut().choice = choice.to_string();
            ui.global::<ChangePick>().set_choice(choice.clone());
            ui.global::<ChangePick>().set_custom_error("".into());
            log::info!("cb: change-pick {choice}");
            refresh_change();
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let change_pick = change_pick.clone();
        ui.global::<Callbacks>().on_change_address_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            change_pick.borrow_mut().custom_address =
                ui.global::<ChangePick>().get_custom_address().to_string();
            ui.global::<ChangePick>().set_custom_error("".into());
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_change_done(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }

    // Edge-tracks whether the compose draft is over the broadcast ceiling, so
    // the "too large" dialog pops once on crossing — not on every keystroke.
    let compose_oversize = Rc::new(std::cell::Cell::new(false));

    // Keystroke cost estimator — pure arithmetic, no crypto runs (see
    // notes-core crypt::SEAL_OVERHEAD), so per-keystroke recompute is free.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let compose_oversize = compose_oversize.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        ui.global::<Callbacks>().on_compose_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let compose = ui.global::<Compose>();
            let st = state.borrow();
            // Tier pills drive the rate field; a manual edit set tier=3
            // first, so we never overwrite the user's custom value.
            let tier = compose.get_tier();
            if tier != 3 {
                compose.set_rate_text(format!("{}", st.fee_rate(tier)).into());
            }
            let rate = match resolve_rate(tier, compose.get_rate_text().as_str(), &st) {
                Ok(r) => r,
                Err(e) => {
                    compose.set_cost_line(e.into());
                    compose.set_can_continue(false);
                    return;
                }
            };
            // Keyboard Done: the system keyboard's Done key has no distinct
            // signal — it sends a plain '\n' (gui-app-keyboard maps
            // KeyAction::Return to Key::Char('\n')). A note is composed as
            // one paragraph on-device, so ANY newline here means "done
            // typing": strip it and bump dismiss-nonce, which the editor
            // watches to drop focus (focus loss hides the keyboard).
            let raw = compose.get_text();
            if raw.as_str().contains('\n') {
                let stripped: String = raw.as_str().replace('\n', "");
                compose.set_text(stripped.into());
                compose.set_dismiss_nonce(compose.get_dismiss_nonce() + 1);
                log::info!("cb: compose keyboard-done");
            }
            let text = compose.get_text();
            let text_len = text.as_str().len();
            if text_len == 0 {
                compose.set_cost_line("Type to see the cost.".into());
                compose.set_can_continue(false);
                compose_oversize.set(false); // clearing the draft re-arms the dialog
                return;
            }
            let ix = notebooks.borrow();
            let ctx = notebook_ctx(&ix, *active.borrow())
                .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
            let net_s = net.borrow().clone();
            let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
            drop(ix);
            if st.utxos.is_empty() && section.as_ref().map(|s| s.balance()).unwrap_or(0) == 0 {
                compose
                    .set_cost_line("No funds — fund the address and import a sync bundle.".into());
                compose.set_can_continue(false);
                return;
            }
            // Directed = non-empty To field. Validate the recipient like
            // resolve_rate validates the rate — errors land in the cost
            // line, never a panic.
            let to_address = compose.get_to_address().trim().to_string();
            let directed = !to_address.is_empty();
            let recipient_spk_len = if directed {
                match Recipient::parse(st.network(), &to_address) {
                    Ok(r) => {
                        if compose.get_private_note() && r.p2tr_x.is_none() {
                            compose.set_cost_line(
                                "Private directed notes need a taproot (…1p…) recipient — or switch to Public.".into(),
                            );
                            compose.set_can_continue(false);
                            return;
                        }
                        Some(r.spk.len())
                    }
                    Err(_) => {
                        compose.set_cost_line(
                            format!("Enter a valid {} recipient address.", st.network).into(),
                        );
                        compose.set_can_continue(false);
                        return;
                    }
                }
            } else {
                None
            };
            let gift = resolve_gift(directed, compose.get_gift_sats().as_str());
            let private = compose.get_private_note();
            let effective = st.effective_chunk();
            let est = estimate_note_cost(text_len, private, effective, 1, recipient_spk_len);
            let fit = fit_check(effective, text_len, private, recipient_spk_len);

            // Over the per-tx broadcast ceiling (vsize > 100 kB, or > 255
            // chunks). Show it in the cost line, gate Continue, and pop the
            // "too large" dialog once — on the crossing, not every keystroke.
            if !matches!(fit, FitCheck::Ok) {
                match &est {
                    Ok((chunks, vsize)) => compose.set_cost_line(
                        format!("{chunks} chunk(s) · ~{vsize} vB — too large to broadcast").into(),
                    ),
                    Err(_) => {
                        compose.set_cost_line("Too large to broadcast (> 255 chunks).".into())
                    }
                }
                compose.set_can_continue(false);
                if !compose_oversize.replace(true) {
                    match fit {
                        FitCheck::FitsAtStandard => {
                            compose.set_oversize_offer_bump(true);
                            compose.set_oversize_message(
                                "This note doesn't fit at your current chunk size. \
                                 Switch to Standard (a single large chunk) to fit it in one transaction?"
                                    .into(),
                            );
                        }
                        _ => {
                            compose.set_oversize_offer_bump(false);
                            compose.set_oversize_message(
                                "This note is too large to broadcast. A single Bitcoin \
                                 transaction can't exceed ~100 kB (the network relay limit), \
                                 whatever the chunk size. Shorten the note, or split it across \
                                 several notes. Multi-transaction notes are planned for a \
                                 future release."
                                    .into(),
                            );
                        }
                    }
                    compose.set_show_oversize(true);
                }
                return;
            }
            compose_oversize.set(false);

            let pick = funding_pick.borrow();
            let sp_participates = !pick.spending.is_empty();
            let mode_auto = !pick.touched && !sp_participates;

            if mode_auto {
                // Byte-identical to pre-funding-unification behavior.
                match est {
                    Ok((chunks, vsize)) => {
                        let fee = (vsize as f64 * rate).ceil() as u64;
                        if fee + gift > st.balance() {
                            compose.set_cost_line(
                                format!("Needs ~{} sats — balance is {}.", fee + gift, st.balance())
                                    .into(),
                            );
                            compose.set_can_continue(false);
                        } else {
                            compose.set_cost_line(
                                format!(
                                    "{text_len} bytes · {chunks} chunk(s) · ~{vsize} vB · ~{} @ {rate} sat/vB{}",
                                    sats_line(fee, st.btc_usd),
                                    if directed {
                                        format!(" + {gift} sats to recipient")
                                    } else {
                                        String::new()
                                    }
                                )
                                .into(),
                            );
                            compose.set_can_continue(true);
                        }
                    }
                    Err(e) => {
                        compose.set_cost_line(format!("{e}").into());
                        compose.set_can_continue(false);
                    }
                }
                return;
            }

            // Exact-selected-coins preview (notebook subset, spending, or
            // mixed): real selected input kinds/count and real extra
            // outputs, unlike `estimate_note_cost`'s single-taproot-input
            // approximation above (used only for `fit_check`'s ceiling test).
            let payload_lens = match payload_lens_for(text_len, private, effective) {
                Ok(v) => v,
                Err(e) => {
                    compose.set_cost_line(e.into());
                    compose.set_can_continue(false);
                    return;
                }
            };
            let chunks = payload_lens.len();
            let n_notebook = pick.notebook.len();
            let n_spending = pick.spending.len();
            if n_notebook + n_spending == 0 {
                compose.set_cost_line("Select at least one coin — \"Pay from\" above.".into());
                compose.set_can_continue(false);
                return;
            }
            let kinds: Vec<InputKind> = std::iter::repeat(InputKind::Taproot)
                .take(n_notebook)
                .chain(std::iter::repeat(InputKind::P2wpkh).take(n_spending))
                .collect();
            let cp = change_pick.borrow();
            let change_len = match change_spk_len_preview(
                &cp.choice,
                &cp.custom_address,
                st.network(),
                sp_participates,
            ) {
                Ok(l) => l,
                Err(e) => {
                    compose.set_cost_line(e.into());
                    compose.set_can_continue(false);
                    return;
                }
            };
            drop(cp);
            let nb_total: u64 = st
                .utxos
                .iter()
                .filter(|u| pick.is_selected(false, &u.txid, u.vout))
                .map(|u| u.value)
                .sum();
            let sp_total: u64 = section
                .as_ref()
                .map(|s| {
                    s.utxos
                        .iter()
                        .filter(|u| pick.is_selected(true, &u.txid, u.vout))
                        .map(|u| u.value)
                        .sum()
                })
                .unwrap_or(0);
            let in_value = nb_total + sp_total;
            let dust_needed = if sp_participates { notes_core::DUST_LIMIT } else { 0 };

            let mut extra_with_change: Vec<usize> = Vec::new();
            if let Some(l) = recipient_spk_len {
                extra_with_change.push(l);
            }
            if sp_participates {
                extra_with_change.push(34); // notebook dust spk (P2TR, always 34 bytes)
            }
            extra_with_change.push(change_len);
            let vsize_with_change = estimate_vsize_mixed(&kinds, &payload_lens, &extra_with_change);
            let fee_with_change = (vsize_with_change as f64 * rate).ceil() as u64;
            let leftover_with_change =
                in_value.checked_sub(fee_with_change + gift + dust_needed);

            let (vsize, fee, ok) = match leftover_with_change {
                Some(v) if v >= notes_core::DUST_LIMIT => (vsize_with_change, fee_with_change, true),
                _ => {
                    let mut extra_no_change: Vec<usize> = Vec::new();
                    if let Some(l) = recipient_spk_len {
                        extra_no_change.push(l);
                    }
                    if sp_participates {
                        extra_no_change.push(34);
                    }
                    let vsize2 = estimate_vsize_mixed(&kinds, &payload_lens, &extra_no_change);
                    let fee2 = (vsize2 as f64 * rate).ceil() as u64;
                    let ok2 = matches!(in_value.checked_sub(fee2 + gift + dust_needed), Some(v) if v <= notes_core::DUST_LIMIT);
                    (vsize2, fee2, ok2)
                }
            };
            if !ok {
                compose.set_cost_line(
                    format!(
                        "Needs ~{} sats — selected coins total {}.",
                        fee + gift + dust_needed,
                        in_value
                    )
                    .into(),
                );
                compose.set_can_continue(false);
            } else {
                compose.set_cost_line(
                    format!(
                        "{text_len} bytes · {chunks} chunk(s) · ~{vsize} vB · ~{} @ {rate} sat/vB{}{}",
                        sats_line(fee, st.btc_usd),
                        if directed { format!(" + {gift} sats to recipient") } else { String::new() },
                        if sp_participates {
                            format!(" + {} sats dust to notebook", notes_core::DUST_LIMIT)
                        } else {
                            String::new()
                        }
                    )
                    .into(),
                );
                compose.set_can_continue(true);
            }
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let plan = plan.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        ui.global::<Callbacks>().on_compose_continue(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let identity = identity.clone();
            let plan = plan.clone();
            let notebooks = notebooks.clone();
            let net = net.clone();
            let seed_idx = seed_idx.clone();
            let bip_account = bip_account.clone();
            let active = active.clone();
            let app_seed = app_seed.clone();
            let funding_pick = funding_pick.clone();
            let change_pick = change_pick.clone();
            // Let the busy overlay paint one frame before the blocking work.
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let compose = ui.global::<Compose>();
                let text = compose.get_text().to_string();
                let private = compose.get_private_note();
                let to_address = compose.get_to_address().trim().to_string();
                let directed = !to_address.is_empty();
                let tier = compose.get_tier();
                let rate_text = compose.get_rate_text().to_string();
                let gift = resolve_gift(directed, compose.get_gift_sats().as_str());
                let st = state.borrow();
                let id_guard = identity.borrow();
                let pick = funding_pick.borrow().clone();
                let change_choice = change_pick.borrow().clone();
                let ix = notebooks.borrow();
                let ctx = notebook_ctx(&ix, *active.borrow())
                    .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                let net_s = net.borrow().clone();
                let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
                drop(ix);

                // (note_id, note, spending inputs spent, spending change addr
                // to mark used, change went to notebook?, mandatory notebook
                // dust output present?)
                type ComposeOut = (
                    [u8; 4],
                    NoteTx,
                    Vec<(String, u32)>,
                    Option<spending::SpendingAddress>,
                    bool,
                    bool,
                );
                let result: Result<ComposeOut, String> = id_guard
                    .as_ref()
                    .ok_or_else(|| "identity unavailable".to_string())
                    .and_then(|id| {
                        let rate = resolve_rate(tier, &rate_text, &st)?;
                        let note_id = pick_unique_note_id(generate_note_id, |id| {
                            let id_hex = hex::encode(id);
                            st.notes.iter().any(|n| n.id == id_hex)
                        })
                        .map_err(|e| e.to_string())?;
                        let recipient = if directed {
                            Some(Recipient::parse(st.network(), &to_address).map_err(|e| e.to_string())?)
                        } else {
                            None
                        };
                        let sp_participates = !pick.spending.is_empty();
                        let mode_auto = !pick.touched && !sp_participates;

                        if mode_auto {
                            // Byte-identical input selection to before this
                            // feature — change destination is still
                            // independently resolvable (the picker screen).
                            let (change_spk, _) = resolve_change(
                                &change_choice.choice,
                                &change_choice.custom_address,
                                st.network(),
                                &id.output_x,
                                false,
                                &app_seed.as_ref().ok_or("identity unavailable")?,
                                ctx.0,
                                ctx.1,
                                0,
                            )?;
                            let change_is_notebook = change_choice.choice != "custom";
                            let note = if let Some(r) = &recipient {
                                compose_directed_note_with_change_amount(
                                    id,
                                    &st.core_utxos(),
                                    &text,
                                    private,
                                    note_id,
                                    r,
                                    gift,
                                    Some(&change_spk),
                                    st.effective_chunk(),
                                    rate,
                                    || generate_aux_rand(),
                                )
                            } else {
                                notes_core::bundle::compose_note_with_change(
                                    id,
                                    &st.core_utxos(),
                                    &text,
                                    private,
                                    note_id,
                                    Some(&change_spk),
                                    st.effective_chunk(),
                                    rate,
                                    || generate_aux_rand(),
                                )
                            }
                            .map_err(|e| e.to_string())?;
                            Ok((note_id, note, Vec::new(), None, change_is_notebook, false))
                        } else if !sp_participates {
                            // Notebook-only coin control (a subset was
                            // explicitly picked, or explicitly re-confirmed).
                            let inputs: Vec<Utxo> = st
                                .utxos
                                .iter()
                                .filter(|u| pick.is_selected(false, &u.txid, u.vout))
                                .filter_map(|u| {
                                    let mut txid = [0u8; 32];
                                    hex::decode_to_slice(&u.txid, &mut txid).ok()?;
                                    txid.reverse();
                                    Some(Utxo { txid, vout: u.vout, value: u.value })
                                })
                                .collect();
                            if inputs.is_empty() {
                                return Err("Select at least one coin to pay from.".into());
                            }
                            let (change_spk, _) = resolve_change(
                                &change_choice.choice,
                                &change_choice.custom_address,
                                st.network(),
                                &id.output_x,
                                false,
                                &app_seed.as_ref().ok_or("identity unavailable")?,
                                ctx.0,
                                ctx.1,
                                0,
                            )?;
                            let change_is_notebook = change_choice.choice != "custom";
                            let note = if let Some(r) = &recipient {
                                compose_directed_note_exact_amount(
                                    id,
                                    &inputs,
                                    &text,
                                    private,
                                    note_id,
                                    r,
                                    gift,
                                    Some(&change_spk),
                                    st.effective_chunk(),
                                    rate,
                                    || generate_aux_rand(),
                                )
                            } else {
                                compose_note_exact(
                                    id,
                                    &inputs,
                                    &text,
                                    private,
                                    note_id,
                                    Some(&change_spk),
                                    st.effective_chunk(),
                                    rate,
                                    || generate_aux_rand(),
                                )
                            }
                            .map_err(|e| e.to_string())?;
                            Ok((note_id, note, Vec::new(), None, change_is_notebook, false))
                        } else {
                            // Spending-wallet participates (pure spending or
                            // mixed with notebook coins) — mixed builder,
                            // mandatory notebook-dust output.
                            let seed: &[u8; 32] =
                                &app_seed.as_ref().ok_or("identity unavailable")?;
                            let notebook_dust_spk = p2tr_script_pubkey(&id.output_x);
                            let mut mixed_inputs: Vec<MixedInput> = Vec::new();
                            for u in
                                st.utxos.iter().filter(|u| pick.is_selected(false, &u.txid, u.vout))
                            {
                                let mut txid = [0u8; 32];
                                hex::decode_to_slice(&u.txid, &mut txid)
                                    .map_err(|_| "bad notebook txid".to_string())?;
                                txid.reverse();
                                mixed_inputs.push(MixedInput {
                                    utxo: Utxo { txid, vout: u.vout, value: u.value },
                                    prevout_spk: notebook_dust_spk.clone(),
                                    kind: InputKind::Taproot,
                                    seckey: id.tweaked_seckey,
                                });
                            }
                            let sec =
                                section.as_ref().ok_or("spending wallet not set up".to_string())?;
                            let mut spent_spending: Vec<(String, u32)> = Vec::new();
                            for su in
                                sec.utxos.iter().filter(|u| pick.is_selected(true, &u.txid, u.vout))
                            {
                                let key = notes_core::seeds::derive_spending_key(
                                    seed,
                                    ctx.0,
                                    st.network(),
                                    ctx.1,
                                    su.chain,
                                    su.index,
                                )
                                .map_err(|e| e.to_string())?;
                                let mut txid = [0u8; 32];
                                hex::decode_to_slice(&su.txid, &mut txid)
                                    .map_err(|_| "bad spending txid".to_string())?;
                                txid.reverse();
                                mixed_inputs.push(MixedInput {
                                    utxo: Utxo { txid, vout: su.vout, value: su.value },
                                    prevout_spk: key.script_pubkey.clone(),
                                    kind: InputKind::P2wpkh,
                                    seckey: key.seckey,
                                });
                                spent_spending.push((su.txid.clone(), su.vout));
                            }
                            if mixed_inputs.is_empty() {
                                return Err("Select at least one coin to pay from.".into());
                            }
                            let (payloads, recipient_spk) = sealed_note_payloads(
                                id,
                                &text,
                                private,
                                recipient.as_ref(),
                                note_id,
                                st.effective_chunk(),
                            )
                            .map_err(|e| e.to_string())?;
                            let recipient_amount = if recipient.is_some() { gift } else { 0 };
                            let (change_spk, change_addr) = resolve_change(
                                &change_choice.choice,
                                &change_choice.custom_address,
                                st.network(),
                                &id.output_x,
                                true,
                                seed,
                                ctx.0,
                                ctx.1,
                                sec.next_change,
                            )?;
                            let change_is_notebook = change_choice.choice == "notebook";
                            let note = build_note_tx_mixed_exact(
                                &mixed_inputs,
                                &payloads,
                                recipient_spk.as_deref(),
                                recipient_amount,
                                &notebook_dust_spk,
                                &change_spk,
                                rate,
                                || generate_aux_rand(),
                            )
                            .map_err(|e| e.to_string())?;
                            Ok((
                                note_id,
                                note,
                                spent_spending,
                                change_addr,
                                change_is_notebook,
                                true,
                            ))
                        }
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok((note_id, note, spending_spent, spending_change_addr, change_is_notebook, notebook_dust)) => {
                        let chunks = note
                            .tx
                            .outputs
                            .iter()
                            .filter(|o| o.script_pubkey.first() == Some(&0x6a))
                            .count() as u64;
                        let funded_by = pick.mode_label();
                        log::info!(
                            "cb: compose len={} private={} to={} chunks={} fee={} vsize={} gift={} funded={funded_by} txid={} ok",
                            text.len(),
                            private,
                            if directed { to_address.as_str() } else { "self" },
                            chunks,
                            note.fee,
                            note.vsize,
                            note.sent,
                            note.txid_hex
                        );
                        // Notebook balance after signing: subtract whatever
                        // notebook-owned value this tx actually spent (all of
                        // it, via fee+sent+change, when funding was pure
                        // notebook — the pre-feature formula; else exactly
                        // the selected notebook coins, 0 for pure spending),
                        // add back the mandatory dust + any change that
                        // landed back in the notebook.
                        let notebook_spent: u64 = if !pick.spending.is_empty() {
                            st.utxos
                                .iter()
                                .filter(|u| pick.is_selected(false, &u.txid, u.vout))
                                .map(|u| u.value)
                                .sum()
                        } else {
                            note.fee + note.sent + note.change
                        };
                        let notebook_gained: u64 =
                            (if notebook_dust { notes_core::DUST_LIMIT } else { 0 })
                                + if change_is_notebook { note.change } else { 0 };
                        let balance_after = st.balance() - notebook_spent + notebook_gained;
                        let change_dest_line = if note.change == 0 {
                            String::new()
                        } else if change_is_notebook {
                            format!("\nchange back to your notebook: {} sats", note.change)
                        } else if spending_change_addr.is_some() {
                            format!("\nchange to a fresh spending-wallet address: {} sats", note.change)
                        } else {
                            format!("\nchange to your custom address: {} sats", note.change)
                        };
                        ui.global::<Confirm>().set_summary(
                            format!(
                                "{}{}\n\nfunded by: {funded_by}\nsize: {} bytes in {} chunk(s)\ntx: {} vB · {} input(s)\nfee: {}{}{}{}\nbalance after: {} sats\n\ntxid:\n{}",
                                match (private, directed) {
                                    (true, true) => "PRIVATE — sealed for the recipient (ECDH)",
                                    (true, false) => "PRIVATE — encrypted with your device seed",
                                    (false, _) => "PUBLIC — plaintext, world-readable forever",
                                },
                                if directed {
                                    format!("\nto: {to_address}")
                                } else {
                                    String::new()
                                },
                                text.len(),
                                chunks,
                                note.vsize,
                                note.tx.inputs.len(),
                                sats_line(note.fee, st.btc_usd),
                                if directed {
                                    format!(" + {} sats to recipient", note.sent)
                                } else {
                                    String::new()
                                },
                                if notebook_dust {
                                    format!("\ndust to notebook (discoverability): {} sats", notes_core::DUST_LIMIT)
                                } else {
                                    String::new()
                                },
                                change_dest_line,
                                balance_after,
                                note.txid_hex
                            )
                            .into(),
                        );
                        let recipient = if directed { Some(to_address) } else { None };
                        *plan.borrow_mut() = Some(Plan {
                            note,
                            text,
                            private,
                            note_id,
                            chunks,
                            recipient,
                            spending_spent,
                            spending_change_addr,
                            change_is_notebook,
                            notebook_dust,
                        });
                        ui.global::<Ui>().set_screen(4);
                    }
                    Err(e) => {
                        log::warn!("cb: compose len={} private={} err={e}", text.len(), private);
                        compose.set_cost_line(format!("Cannot build: {e}").into());
                    }
                }
            });
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let plan = plan.clone();
        let fs = fs.clone();
        let refresh_notes = refresh_notes.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        let refresh_funding = refresh_funding.clone();
        let funding_pick = funding_pick.clone();
        let change_pick = change_pick.clone();
        ui.global::<Callbacks>().on_confirm_sign(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(p) = plan.borrow_mut().take() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let fs = fs.clone();
            let refresh_notes = refresh_notes.clone();
            let notebooks = notebooks.clone();
            let net = net.clone();
            let seed_idx = seed_idx.clone();
            let bip_account = bip_account.clone();
            let active = active.clone();
            let refresh_funding = refresh_funding.clone();
            let funding_pick = funding_pick.clone();
            let change_pick = change_pick.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let mut st = state.borrow_mut();

                // Notebook ledger: drop spent notebook inputs. Spending-wallet
                // inputs (if any) are dropped from the SEPARATE spending
                // ledger below via `p.spending_spent` — `p.note.spent_outpoints`
                // covers both kinds, but only notebook outpoints ever match
                // an entry in `st.utxos`, so this retain is safe either way.
                let spent: Vec<(String, u32)> = p
                    .note
                    .spent_outpoints
                    .iter()
                    .map(|(txid, vout)| {
                        let mut t = *txid;
                        t.reverse();
                        (hex::encode(t), *vout)
                    })
                    .collect();
                st.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));

                // Output order: OP_RETURN(s), [directed recipient], [notebook
                // dust — mandatory whenever the spending wallet funded any
                // part of this note], [change]. `p.chunks` + the recipient
                // flag place the dust; +1 more when it's present places change.
                let dust_vout = p.chunks as u32 + u32::from(p.recipient.is_some());
                if p.notebook_dust {
                    st.utxos.push(UtxoRec {
                        txid: p.note.txid_hex.clone(),
                        vout: dust_vout,
                        value: notes_core::DUST_LIMIT,
                    });
                }
                let change_vout = dust_vout + u32::from(p.notebook_dust);
                if p.note.change > 0 && p.change_is_notebook {
                    st.utxos.push(UtxoRec {
                        txid: p.note.txid_hex.clone(),
                        vout: change_vout,
                        value: p.note.change,
                    });
                }
                // Custom/external change: not our coin, nothing to track
                // (matches how a directed recipient's dust isn't tracked).

                // Spending ledger: drop spent inputs + add change (if it
                // went to a fresh spending address) in one pass — mirrors
                // the notebook ledger's unconfirmed-chaining update above.
                if !p.spending_spent.is_empty() || p.spending_change_addr.is_some() {
                    let mut ix = notebooks.borrow_mut();
                    let ctx = notebook_ctx(&ix, *active.borrow())
                        .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                    let net_s = net.borrow().clone();
                    let sec = ix.spending_mut(&net_s, ctx.0, ctx.1);
                    let change_coin =
                        if p.note.change > 0 { p.spending_change_addr.as_ref() } else { None };
                    if let Some(addr) = change_coin {
                        sec.mark_used(addr.clone());
                    }
                    sec.apply_spend(
                        &p.spending_spent,
                        change_coin.map(|addr| spending::SpendingUtxo {
                            txid: p.note.txid_hex.clone(),
                            vout: change_vout,
                            value: p.note.change,
                            chain: addr.chain,
                            index: addr.index,
                        }),
                    );
                    save_notebooks(&fs, &ix);
                }

                let rec = NoteRec {
                    id: hex::encode(p.note_id),
                    text: p.text.clone(),
                    private: p.private,
                    txid: p.note.txid_hex.clone(),
                    raw_hex: p.note.raw_hex.clone(),
                    fee: p.note.fee,
                    vsize: p.note.vsize as u64,
                    chunks: p.chunks,
                    height: None,
                    blocktime: None,
                    status: "pending".into(),
                    directed: p.recipient.is_some(),
                    to: p.recipient.clone(),
                    from: None,
                };

                // Export the signed tx for the companion to broadcast:
                // always to internal outbox; Airlock too when available.
                let file = format!("{OUTBOX_DIR}/{}.hex", p.note.txid_hex);
                let internal = ensure_dir(&fs, OUTBOX_DIR, Location::User)
                    .and_then(|_| write_file(&fs, &file, Location::User, p.note.raw_hex.as_bytes()));
                let airlock = ensure_airlock_mounted(&fs).and_then(|_| {
                    let r = ensure_dir(&fs, OUTBOX_DIR, Location::Airlock).and_then(|_| {
                        write_file(&fs, &file, Location::Airlock, p.note.raw_hex.as_bytes())
                    });
                    // Full flush so the file survives unplug (paper-wallet
                    // pattern).
                    unmount_airlock(&fs);
                    r
                });
                log::info!(
                    "cb: sign-note id={} txid={} fee={} vsize={} internal={} airlock={}",
                    rec.id,
                    rec.txid,
                    rec.fee,
                    rec.vsize,
                    if internal.is_ok() { "ok" } else { "err" },
                    if airlock.is_ok() { "ok" } else { "err" },
                );

                // Auto-save the recipient as a recent contact (usually a
                // no-op re-front after the pick, but covers every path).
                if let Some(to) = &p.recipient {
                    upsert_contact(&mut st, to);
                }
                st.notes.push(rec.clone());
                save_state(&fs, &st);
                drop(st);
                refresh_funding();

                let view = ui.global::<View>();
                view.set_id(rec.id.clone().into());
                view.set_text(rec.text.clone().into());
                view.set_badge(if rec.private { "PRIVATE" } else { "PUBLIC" }.into());
                view.set_meta(
                    format!(
                        "pending — scan the QR with the companion, or broadcast {}.hex\nfee {} sats · {} vB",
                        rec.txid, rec.fee, rec.vsize
                    )
                    .into(),
                );
                // Straight to the QR after signing — that's the broadcast path.
                set_view_qr(&view, &rec);
                view.set_show_qr(view.get_has_qr());
                ui.global::<Compose>().set_text("".into());
                // A stale recipient must never silently direct the next note.
                ui.global::<Compose>().set_to_address("".into());
                ui.global::<Compose>().set_to_label("".into());
                // Gift resets with the recipient so a large gift can't leak
                // into the next note.
                ui.global::<Compose>().set_gift_sats("330".into());
                ui.global::<Compose>().set_gift_expanded(false);
                // Funding/change picks reset too — a stale coin selection or
                // custom change address must never leak into the next note.
                *funding_pick.borrow_mut() = FundingPick::default();
                *change_pick.borrow_mut() = ChangePickState::default();
                ui.global::<ChangePick>().set_choice("auto".into());
                ui.global::<ChangePick>().set_custom_address("".into());
                ui.global::<Ui>().set_busy(false);
                refresh_notes();
                ui.global::<Ui>().set_screen(2);
            });
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        ui.global::<Callbacks>().on_open_note(move |id| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let Some(n) = st.notes.iter().find(|n| n.id == id.as_str()) else { return };
            let view = ui.global::<View>();
            view.set_id(n.id.clone().into());
            view.set_text(n.text.clone().into());
            view.set_badge(if n.private { "PRIVATE" } else { "PUBLIC" }.into());
            let where_line = match n.height {
                Some(h) => format!("confirmed at block {h}"),
                None => "pending — scan the tx QR with the companion to broadcast".to_string(),
            };
            let who_line = match (&n.from, &n.to) {
                (Some(from), _) => format!("\nfrom: {from}"),
                (None, Some(to)) => format!("\nto: {to}"),
                _ => String::new(),
            };
            view.set_meta(format!("{where_line}{who_line}\ntxid: {}", n.txid).into());
            set_view_qr(&view, n);
            view.set_show_qr(false);
            log::info!(
                "cb: open-note id={} status={}{} qr={}",
                n.id,
                n.status,
                n.from.as_deref().map(|f| format!(" from={f}")).unwrap_or_default(),
                view.get_has_qr()
            );
            ui.global::<Ui>().set_screen(2);
        });
    }

    // Shared by file import AND camera scan: parse + merge a bundle,
    // logging `cb: import-bundle {src} … ok` (src keeps the file=/loc=
    // shape the UI tests grep).
    let apply_bundle: Rc<dyn Fn(&str, &str) -> Result<String, String>> = {
        let state = state.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let active = active.clone();
        Rc::new(move |json: &str, src: &str| -> Result<String, String> {
            let id_guard = identity.borrow();
            let id = id_guard.as_ref().ok_or("identity unavailable")?;
            {
                let bundle =
                    SyncBundle::from_json(json).map_err(|e| format!("bad bundle: {e}"))?;
                let mut st = state.borrow_mut();
                if !bundle.network.is_empty() && bundle.network != st.network {
                    return Err(format!(
                        "bundle is for {}, app is on {} — switch network first",
                        bundle.network, st.network
                    ));
                }

                // Spending-unification: the self-spk SET is the notebook's
                // own spk plus every address the spending wallet has issued
                // (`SpendingSection.self_spks`) — extends OWN detection to
                // funded/mixed-source notes (extract_notes_multi ORs with
                // the producer's spends_from_self, never narrows).
                let ix = notebooks.borrow();
                let ctx = notebook_ctx(&ix, *active.borrow())
                    .unwrap_or((*seed_idx.borrow(), *bip_account.borrow()));
                let net_s = net.borrow().clone();
                let section = ix.spending(&net_s, ctx.0, ctx.1).cloned();
                drop(ix);
                let notebook_addr = id.address(st.network());
                let self_spks: Vec<Vec<u8>> = {
                    let mut v = vec![p2tr_script_pubkey(&id.output_x)];
                    if let Some(s) = &section {
                        v.extend(s.self_spks());
                    }
                    v
                };

                let recovered = extract_notes_multi(&bundle, id, st.network(), &self_spks);
                let mut new_notes = 0usize;
                let mut received_notes = 0usize;
                for r in &recovered {
                    let id_hex = hex::encode(r.note_id);
                    if r.received {
                        received_notes += 1;
                    }
                    // Merge keyed by (id, from): a received note can never
                    // overwrite an own note sharing its note_id.
                    match st
                        .notes
                        .iter_mut()
                        .find(|n| n.id == id_hex && n.from.as_deref() == r.sender.as_deref())
                    {
                        Some(existing) => {
                            existing.height = r.height.or(existing.height);
                            existing.blocktime = r.blocktime.or(existing.blocktime);
                            if existing.height.is_some() {
                                existing.status = "confirmed".into();
                            }
                        }
                        None => {
                            new_notes += 1;
                            st.notes.push(NoteRec {
                                id: id_hex,
                                text: r.text.clone().unwrap_or_else(|| {
                                    if r.received {
                                        "(directed note — could not decrypt)".into()
                                    } else {
                                        "(sealed under another key)".into()
                                    }
                                }),
                                private: r.private,
                                txid: r.txids.first().cloned().unwrap_or_default(),
                                raw_hex: String::new(),
                                fee: 0,
                                vsize: 0,
                                chunks: 0,
                                height: r.height,
                                blocktime: r.blocktime,
                                status: if r.height.is_some() {
                                    "confirmed".into()
                                } else {
                                    "pending".into()
                                },
                                directed: r.directed,
                                to: r.recipient.clone(),
                                from: r.sender.clone(),
                            });
                        }
                    }
                }

                // Split the bundle's UTXOs by owner: no `owner_address` (or
                // one matching the notebook's own address) is a notebook
                // coin; an address matching a KNOWN spending-wallet `used`
                // entry routes to the spending ledger (tagged with its
                // chain/index so signing can re-derive the key). A coin at
                // an owner address the device hasn't recorded as used yet
                // is dropped — see the Settings spending card / DEVELOPMENT
                // notes for the sync-flow limitation this implies.
                let mut nb_utxos: Vec<UtxoRec> = Vec::new();
                let mut sp_utxos: Vec<spending::SpendingUtxo> = Vec::new();
                for u in &bundle.utxos {
                    match &u.owner_address {
                        None => {
                            nb_utxos.push(UtxoRec { txid: u.txid.clone(), vout: u.vout, value: u.value })
                        }
                        Some(a) if *a == notebook_addr => {
                            nb_utxos.push(UtxoRec { txid: u.txid.clone(), vout: u.vout, value: u.value })
                        }
                        Some(a) => {
                            if let Some(used) =
                                section.as_ref().and_then(|s| s.used.iter().find(|x| &x.address == a))
                            {
                                sp_utxos.push(spending::SpendingUtxo {
                                    txid: u.txid.clone(),
                                    vout: u.vout,
                                    value: u.value,
                                    chain: used.chain,
                                    index: used.index,
                                });
                            }
                        }
                    }
                }
                st.utxos = nb_utxos;
                if section.is_some() {
                    let mut ix = notebooks.borrow_mut();
                    ix.spending_mut(&net_s, ctx.0, ctx.1).set_utxos(sp_utxos);
                    save_notebooks(&fs, &ix);
                }
                st.tip_height = Some(bundle.tip_height);
                st.bundle_time = Some(bundle.bundle_time);
                // Chunk size is a pure device setting — any relay-policy
                // field in the bundle is deliberately ignored.
                if bundle.fee_rates.economy > 0.0 {
                    st.fee_economy = bundle.fee_rates.economy;
                }
                if bundle.fee_rates.half_hour > 0.0 {
                    st.fee_normal = bundle.fee_rates.half_hour;
                }
                if bundle.fee_rates.fastest > 0.0 {
                    st.fee_fast = bundle.fee_rates.fastest;
                }
                st.btc_usd = bundle.btc_usd.or(st.btc_usd);
                save_state(&fs, &st);

                log::info!(
                    "cb: import-bundle {src} notes={} new={new_notes} received={received_notes} utxos={} tip={} ok",
                    recovered.len(),
                    st.utxos.len(),
                    bundle.tip_height
                );
                Ok(format!(
                    "Imported ({src}): {} note(s) ({new_notes} new), {} utxo(s), height {}.",
                    recovered.len(),
                    st.utxos.len(),
                    bundle.tip_height
                ))
            }
        })
    };

    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let refresh_home = refresh_home.clone();
        let apply_bundle = apply_bundle.clone();
        ui.global::<Callbacks>().on_import_bundle(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let result = (|| -> Result<String, String> {
                let (name, loc, loc_label) =
                    first_inbox_bundle(&fs).ok_or("no .json bundle in /chain-notes/inbox")?;
                let json = read_text(&fs, &format!("{INBOX_DIR}/{name}"), loc)?;
                if loc == Location::Airlock {
                    unmount_airlock(&fs);
                }
                apply_bundle(&json, &format!("file={name} loc={loc_label}"))
            })();
            match result {
                Ok(msg) => {
                    ui.global::<Sync>().set_result(msg.into());
                    ui.global::<Ui>().set_error("".into());
                }
                Err(e) => {
                    log::warn!("cb: import-bundle err={e}");
                    ui.global::<Sync>().set_result(e.into());
                }
            }
            refresh_home();
        });
    }

    // Import picker: list the bundle files actually present in the inboxes
    // so the user chooses one, instead of silently auto-picking the first.
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_list_bundles(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let sync = ui.global::<Sync>();
            let found = list_inbox_bundles(&fs);
            let rows: Vec<BundleRow> = found
                .iter()
                .map(|(name, loc, _)| {
                    let (loc_name, loc_idx) = if *loc == Location::Airlock {
                        ("Airlock", 1)
                    } else {
                        ("Internal", 0)
                    };
                    BundleRow {
                        name: name.clone().into(),
                        label: format!("{name}  ·  {loc_name}").into(),
                        loc: loc_idx,
                    }
                })
                .collect();
            sync.set_bundles(Rc::new(VecModel::from(rows)).into());
            sync.set_empty_hint(
                "No bundle files found. Put a .json bundle in /chain-notes/inbox on Internal (or the Airlock volume), then tap Refresh — or use \"Scan bundle\" to import by QR from the companion.".into(),
            );
            sync.set_picking(true);
            log::info!("cb: list-bundles n={}", found.len());
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let refresh_home = refresh_home.clone();
        let apply_bundle = apply_bundle.clone();
        ui.global::<Callbacks>().on_pick_bundle(move |name, loc_idx| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let loc = if loc_idx == 1 { Location::Airlock } else { Location::User };
            let result = (|| -> Result<String, String> {
                if loc == Location::Airlock {
                    ensure_airlock_mounted(&fs)?;
                }
                let json = read_text(&fs, &format!("{INBOX_DIR}/{name}"), loc);
                if loc == Location::Airlock {
                    unmount_airlock(&fs);
                }
                let loc_label = if loc == Location::Airlock { "airlock" } else { "internal" };
                apply_bundle(&json?, &format!("file={name} loc={loc_label}"))
            })();
            let sync = ui.global::<Sync>();
            sync.set_picking(false);
            match result {
                Ok(msg) => {
                    sync.set_result(msg.into());
                    ui.global::<Ui>().set_error("".into());
                }
                Err(e) => {
                    log::warn!("cb: pick-bundle err={e}");
                    sync.set_result(e.into());
                }
            }
            refresh_home();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let refresh_home = refresh_home.clone();
        let apply_bundle = apply_bundle.clone();
        ui.global::<Callbacks>().on_scan_bundle(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let opts = ScanQrOptions {
                header_title: "Scan sync bundle".into(),
                message: "Point at the companion's bundle QR (static or animated)".into(),
                ..ScanQrOptions::default()
            };
            // Blocks while the system scanner modal owns the screen; it
            // reassembles animated UR sequences itself (foundation-ur).
            let (kind, data) = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr(data))) => ("qr", data),
                Ok(Some(ScanQrResult::Ur2(ur_type, data))) => {
                    log::info!("cb: scan-bundle ur-type={ur_type}");
                    ("ur", data)
                }
                Ok(_) => {
                    log::info!("cb: scan-bundle cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: scan-bundle err=scanner {e:?}");
                    ui.global::<Sync>()
                        .set_result(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            log::info!("cb: scan-bundle kind={kind} bytes={}", data.len());
            let result = decode_scanned(&data)
                .map_err(|e| e.to_string())
                .and_then(|json| apply_bundle(&json, &format!("src=scan-{kind}")));
            match result {
                Ok(msg) => {
                    ui.global::<Sync>().set_result(msg.into());
                    ui.global::<Ui>().set_error("".into());
                }
                Err(e) => {
                    log::warn!("cb: scan-bundle err={e}");
                    ui.global::<Sync>().set_result(format!("Scan failed: {e}").into());
                }
            }
            refresh_home();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_export_pending(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let pending: Vec<&NoteRec> = st
                .notes
                .iter()
                .filter(|n| n.status == "pending" && !n.raw_hex.is_empty())
                .collect();
            let mut written = 0usize;
            let airlock_ok = ensure_airlock_mounted(&fs).is_ok();
            for n in &pending {
                let file = format!("{OUTBOX_DIR}/{}.hex", n.txid);
                if ensure_dir(&fs, OUTBOX_DIR, Location::User)
                    .and_then(|_| write_file(&fs, &file, Location::User, n.raw_hex.as_bytes()))
                    .is_ok()
                {
                    written += 1;
                }
                if airlock_ok {
                    let _ = ensure_dir(&fs, OUTBOX_DIR, Location::Airlock).and_then(|_| {
                        write_file(&fs, &file, Location::Airlock, n.raw_hex.as_bytes())
                    });
                }
            }
            if airlock_ok {
                unmount_airlock(&fs);
            }
            log::info!(
                "cb: export-pending n={written} airlock={}",
                if airlock_ok { "ok" } else { "err" }
            );
            ui.global::<Sync>()
                .set_result(format!("Exported {written} pending tx(s) to {OUTBOX_DIR}.").into());
        });
    }

    // Sign an external transaction (PSBT): scan it, sign every input that pays
    // THIS device's taproot address, and hand back the signed PSBT as a QR.
    {
        let ui_weak = ui_weak.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_sign_psbt(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let id_guard = identity.borrow();
            let Some(id) = id_guard.as_ref() else {
                ui.global::<Sync>().set_result("Device locked — no signing key.".into());
                return;
            };
            let opts = ScanQrOptions {
                header_title: "Scan transaction".into(),
                message: "Point at the desktop app's PSBT QR".into(),
                ..ScanQrOptions::default()
            };
            let data = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(ScanQrResult::Qr(d))) | Ok(Some(ScanQrResult::Ur2(_, d))) => d,
                Ok(_) => {
                    log::info!("cb: sign-psbt cancelled");
                    return;
                }
                Err(e) => {
                    log::warn!("cb: sign-psbt err=scanner {e:?}");
                    ui.global::<Sync>().set_result(format!("QR scanner unavailable: {e:?}").into());
                    return;
                }
            };
            let bytes = normalize_psbt_bytes(&data);
            let mut psbt = match notes_core::psbt::Psbt::deserialize(&bytes) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("cb: sign-psbt err={e}");
                    ui.global::<Sync>().set_result(format!("Not a PSBT: {e}").into());
                    return;
                }
            };
            let (ours, signed) =
                match psbt.sign_own_taproot(&id.output_x, &id.tweaked_seckey, generate_aux_rand) {
                    Ok(x) => x,
                    Err(e) => {
                        ui.global::<Sync>().set_result(format!("Sign failed: {e}").into());
                        return;
                    }
                };
            log::info!("cb: sign-psbt inputs={ours} signed={signed} ok");
            if ours == 0 {
                ui.global::<Sync>()
                    .set_result("No inputs belong to this device's address.".into());
                return;
            }
            let hex_str = hex::encode_upper(psbt.serialize());
            let txid = psbt.unsigned_tx.txid_hex();
            let file = format!("{OUTBOX_DIR}/{txid}.psbt.hex");
            let _ = ensure_dir(&fs, OUTBOX_DIR, Location::User)
                .and_then(|_| write_file(&fs, &file, Location::User, hex_str.as_bytes()));
            let fee = psbt_fee(&psbt);
            let note = psbt_note_summary(&psbt);
            let sp = ui.global::<SignPsbt>();
            sp.set_summary(
                format!("Signed {signed} of {ours} input(s) · fee {fee} sats\n{note}").into(),
            );
            if hex_str.len() <= MAX_QR_HEX_CHARS {
                sp.set_qr(qr_image(&hex_str));
                sp.set_has_qr(true);
            } else {
                sp.set_has_qr(false);
            }
            ui.global::<Ui>().set_error("".into());
            ui.global::<Ui>().set_screen(8);
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        let net = net.clone();
        let active = active.clone();
        let device_chunk = device_chunk.clone();
        let notebooks = notebooks.clone();
        let app_seed = app_seed.clone();
        let persist_config = persist_config.clone();
        let refresh_home = refresh_home.clone();
        let refresh_notes = refresh_notes.clone();
        let refresh_coins = refresh_coins.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        ui.global::<Callbacks>().on_cycle_network(move || {
            // Network is device-level (wallet-wide): flush the active
            // notebook, cycle the shared network, persist it in config, and
            // reload the active notebook's ledger for the new chain (each
            // notebook keeps a per-network ledger in state-<net>-<account>).
            if active.borrow().is_some() {
                save_state(&fs, &state.borrow());
            }
            let next = match net.borrow().as_str() {
                "mainnet" => "testnet4",
                "testnet4" => "signet",
                "signet" => "regtest",
                _ => "mainnet",
            }
            .to_string();
            *net.borrow_mut() = next.clone();
            persist_config();
            log::info!("cb: set-network {next}");
            if let Some(account) = *active.borrow() {
                let mut fresh = load_state(&fs, &next, account);
                fresh.chunk_override = *device_chunk.borrow();
                *state.borrow_mut() = fresh;
                // Legacy identities are network-independent (only the
                // address ENCODING changes), but bip86 notebooks use the
                // BIP-44 coin type — their keys differ per network, so
                // always re-derive from the meta.
                if let Some(m) = notebooks.borrow().get(account) {
                    *identity.borrow_mut() = derive_identity(&app_seed, m, &next);
                }
            }
            let _ = &ui_weak;
            refresh_home();
            refresh_notes();
            refresh_coins();
            refresh_notebooks();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let device_chunk = device_chunk.clone();
        let persist_config = persist_config.clone();
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_chunk_changed(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let settings = ui.global::<Settings>();
            let mut st = state.borrow_mut();
            match settings.get_chunk_mode() {
                0 => st.chunk_override = None,
                1 => st.chunk_override = Some(80),
                _ => {
                    match settings.get_chunk_text().trim().parse::<usize>() {
                        Ok(n) if (MIN_CHUNK..=DEFAULT_CHUNK).contains(&n) => {
                            st.chunk_override = Some(n);
                        }
                        _ => {
                            let msg = format!(
                                "Chunk size must be {MIN_CHUNK}–{DEFAULT_CHUNK} bytes."
                            );
                            log::warn!("cb: set-chunk-size err={msg}");
                            settings.set_chunk_error(msg.into());
                            // Leave the user's text in place to fix.
                            return;
                        }
                    }
                }
            }
            log::info!(
                "cb: set-chunk-size {} ok",
                st.chunk_override.map(|n| n.to_string()).unwrap_or("auto".into())
            );
            settings.set_chunk_error("".into());
            save_state(&fs, &st);
            // Chunk is device-level (wallet-wide): persist it in config too.
            *device_chunk.borrow_mut() = st.chunk_override;
            persist_config();
            drop(st);
            // Reflect the effective size back into the field (auto/compat),
            // without touching a valid custom value.
            refresh_home();
            // Re-price the draft immediately so the compose cost line is
            // already current when the user returns to it.
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }

    // Compose "too large" dialog → raise the chunk size to Standard (auto) and
    // reprice the draft in place. Only offered when the note fits at Standard.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        ui.global::<Callbacks>().on_oversize_bump(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            {
                let mut st = state.borrow_mut();
                st.chunk_override = None; // Standard / auto = DEFAULT_CHUNK
                save_state(&fs, &st);
            }
            log::info!("cb: set-chunk-size auto ok (oversize-bump)");
            let compose = ui.global::<Compose>();
            compose.set_show_oversize(false);
            ui.global::<Settings>().set_chunk_mode(0); // mirror into the settings pill
            ui.global::<Callbacks>().invoke_compose_changed();
        });
    }

    {
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_refresh_home(move || refresh_home());
    }
    {
        let refresh_notes = refresh_notes.clone();
        ui.global::<Callbacks>().on_refresh_notes(move || refresh_notes());
    }
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let refresh_notes = refresh_notes.clone();
        ui.global::<Callbacks>().on_toggle_sender(move |key, excluded| {
            let Some(_ui) = ui_weak.upgrade() else { return };
            {
                let mut st = state.borrow_mut();
                st.set_excluded(key.as_str(), excluded);
                save_state(&fs, &st);
                log::info!(
                    "cb: toggle-sender excluded={excluded} hidden={}",
                    st.excluded_senders.len()
                );
            }
            refresh_notes();
        });
    }
    {
        let refresh_contacts = refresh_contacts.clone();
        ui.global::<Callbacks>().on_refresh_contacts(move || refresh_contacts());
    }

    // ---- notebook callbacks (screen 20 list) ----
    {
        let switch_notebook = switch_notebook.clone();
        ui.global::<NotebookCb>().on_open(move |account| switch_notebook(account.max(0) as u32));
    }
    {
        // Create: open the name dialog in create mode (-2). Nothing is
        // derived/persisted until Save — the device create is name-only
        // (no address picker: no network on-device to probe used/new).
        let ui_weak = ui_weak.clone();
        ui.global::<NotebookCb>().on_create(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let nb = ui.global::<NotebooksUi>();
            nb.set_name_text("".into());
            nb.set_name_account(-2);
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let notebooks = notebooks.clone();
        ui.global::<NotebookCb>().on_rename(move |account| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let nb = ui.global::<NotebooksUi>();
            // Prefill the RAW local name (the display name may be an addr
            // short form, which must not become a name by accident).
            let raw = notebooks
                .borrow()
                .get(account.max(0) as u32)
                .map(|m| m.name.clone())
                .unwrap_or_default();
            nb.set_name_text(raw.into());
            nb.set_name_account(account);
        });
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<NotebookCb>().on_name_cancel(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.global::<NotebooksUi>().set_name_account(-1);
            }
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let active = active.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        let switch_notebook = switch_notebook.clone();
        ui.global::<NotebookCb>().on_name_save(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let nb = ui.global::<NotebooksUi>();
            let sel = nb.get_name_account();
            if sel == -1 {
                return;
            }
            let name = nb.get_name_text().trim().to_string();
            nb.set_name_account(-1);
            nb.set_name_text("".into());
            if sel == -2 {
                // CREATE: a bip86 notebook at the next unused receive
                // index of the active (seed, account) context — the
                // recovery-seeds scheme, words-recoverable anywhere.
                // (Legacy notebooks are never created anymore.)
                if app_seed.is_none() {
                    ui.global::<Ui>().set_error("Device locked — can't create a notebook.".into());
                    return;
                }
                let (seed, bacct) = (*seed_idx.borrow(), *bip_account.borrow());
                let account = {
                    let mut ix = notebooks.borrow_mut();
                    let account = ix.create_bip86(seed, bacct, &name);
                    save_notebooks(&fs, &ix);
                    account
                };
                let index = notebooks.borrow().get(account).map(|m| m.index).unwrap_or(0);
                log::info!(
                    "cb: create-notebook account={account} scheme=bip86 seed={seed} bip-account={bacct} index={index}"
                );
                refresh_notebooks();
                switch_notebook(account);
            } else {
                let account = sel as u32;
                {
                    let mut ix = notebooks.borrow_mut();
                    ix.rename(account, &name);
                    save_notebooks(&fs, &ix);
                }
                log::info!("cb: rename-notebook account={account}");
                refresh_notebooks();
                // If it's the open notebook, update its home title.
                if *active.borrow() == Some(account) {
                    let title = notebooks
                        .borrow()
                        .get(account)
                        .map(|m| m.name.clone())
                        .filter(|n| !n.trim().is_empty());
                    if let Some(t) = title {
                        nb.set_title(t.into());
                    }
                }
            }
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let notebooks = notebooks.clone();
        let net = net.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        ui.global::<NotebookCb>().on_archive(move |account, archived| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let account = account.max(0) as u32;
            if archived {
                // Guard: a notebook with coins must be emptied first
                // (sweep/consolidate). Zero active notebooks is allowed.
                let bal = load_state(&fs, &net.borrow(), account).balance();
                if bal > 0 {
                    ui.global::<Ui>()
                        .set_error(format!("This notebook holds {bal} sats — empty it first.").into());
                    return;
                }
            }
            {
                let mut ix = notebooks.borrow_mut();
                ix.set_archived(account, archived);
                save_notebooks(&fs, &ix);
            }
            log::info!("cb: archive-notebook account={account} archived={archived}");
            refresh_notebooks();
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let state = state.clone();
        let active = active.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        ui.global::<NotebookCb>().on_back_to_list(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if active.borrow().is_some() {
                save_state(&fs, &state.borrow());
            }
            refresh_notebooks();
            ui.global::<Ui>().set_screen(20);
        });
    }

    // ---- recovery seeds (screen 21 + wallet context) ----

    // Derive the ACTIVE seed's 24 words + SeedQR into the Recovery props.
    // Everything is re-derived on demand and lives only in UI properties
    // until reveal-close wipes them; nothing is persisted or logged. Shared
    // by the reveal button AND the Switch action (which refreshes the words
    // to the new seed while they're shown). Keeps the SeedQR in sync.
    let reveal_words: Rc<dyn Fn()> = {
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        Rc::new(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let recovery = ui.global::<Recovery>();
            let index = *seed_idx.borrow();
            let Some(seed) = app_seed.as_ref() else {
                ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
                log::warn!("cb: reveal-seed index={index} err=locked");
                return;
            };
            let entropy = notes_core::keys::derive_seed_entropy(seed, index);
            let words = match notes_core::bip39::entropy_to_mnemonic(&entropy) {
                Ok(w) => w,
                Err(e) => {
                    ui.global::<Ui>().set_error(format!("Derivation failed: {e}").into());
                    log::warn!("cb: reveal-seed index={index} err={e}");
                    return;
                }
            };
            let list: Vec<&str> = words.split_whitespace().collect();
            let col = |range: std::ops::Range<usize>| -> String {
                range
                    .map(|i| format!("{:2}. {}", i + 1, list[i]))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            recovery.set_words_col1(col(0..12).into());
            recovery.set_words_col2(col(12..24).into());
            // Standard SeedQR: the 4-digit wordlist indices, concatenated.
            let digits: String = notes_core::bip39::entropy_to_indices(&entropy)
                .unwrap_or_default()
                .iter()
                .map(|i| format!("{i:04}"))
                .collect();
            recovery.set_qr(qr_image(&digits));
            recovery.set_show_qr(false);
            recovery.set_title_line(format!("Seed {index} · 24 words").into());
            log::info!("cb: reveal-seed index={index} ok");
        })
    };
    {
        let reveal_words = reveal_words.clone();
        ui.global::<Callbacks>().on_reveal_seed(move || reveal_words());
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_reveal_close(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let recovery = ui.global::<Recovery>();
            recovery.set_words_col1("".into());
            recovery.set_words_col2("".into());
            recovery.set_title_line("".into());
            recovery.set_qr(Image::default());
            recovery.set_show_qr(false);
            log::info!("cb: reveal-seed cancelled");
        });
    }
    // ---- export keys (screen 23) ----
    // Reveal the active (seed, account) context's importable formats:
    // account xpub + tr() descriptor cover the WHOLE account (all
    // addresses); hex + WIF are one notebook's leaf, picked from the
    // notebook list. No private xprv on the device (the 24 words recover
    // the whole seed). Values live in UI props only, wiped on close;
    // never logged.
    let apply_export: Rc<dyn Fn(i32)> = {
        let ui_weak = ui_weak.clone();
        Rc::new(move |which: i32| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let nb = r.get_export_nb_name();
            let (label, value): (String, _) = match which {
                0 => {
                    ("Account xpub · all addresses · watch-only".to_string(), r.get_export_xpub())
                }
                1 => (
                    "Descriptor (tr) · all addresses · watch-only".to_string(),
                    r.get_export_descriptor(),
                ),
                2 => (format!("Notebook \"{nb}\" · hex"), r.get_export_hex()),
                _ => (format!("Notebook \"{nb}\" · WIF"), r.get_export_wif()),
            };
            r.set_export_which(which);
            r.set_export_label(label.into());
            r.set_export_value(value.clone());
            r.set_export_qr(qr_image(value.as_str()));
        })
    };
    // The active account's notebooks as picker rows (index/name/short addr)
    // plus the default selection (first notebook, else a synthetic index 0).
    let export_rows: Rc<dyn Fn(u32, u32, &str, Network) -> (Vec<ExportNbRow>, i32, String)> = {
        let app_seed = app_seed.clone();
        let notebooks = notebooks.clone();
        Rc::new(move |si: u32, acct: u32, net_s: &str, network: Network| {
            let mut rows: Vec<ExportNbRow> = Vec::new();
            let ixb = notebooks.borrow();
            for m in ixb.visible(si, acct) {
                let addr = derive_identity(&app_seed, m, net_s)
                    .map(|id| id.address(network))
                    .unwrap_or_default();
                let short = short_addr(&addr);
                let name = if m.name.trim().is_empty() { short.clone() } else { m.name.clone() };
                rows.push(ExportNbRow {
                    index: m.index as i32,
                    name: name.into(),
                    addr: short.into(),
                });
            }
            let (sel, sel_name) = rows
                .first()
                .map(|r0| (r0.index, r0.name.to_string()))
                .unwrap_or((0, "index 0".to_string()));
            if rows.is_empty() {
                rows.push(ExportNbRow { index: 0, name: "index 0".into(), addr: "".into() });
            }
            (rows, sel, sel_name)
        })
    };
    {
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let net = net.clone();
        let apply_export = apply_export.clone();
        let export_rows = export_rows.clone();
        ui.global::<Callbacks>().on_reveal_public(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let si = *seed_idx.borrow();
            let acct = *bip_account.borrow();
            let Some(seed) = app_seed.as_ref() else {
                ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
                log::warn!("cb: reveal-public seed={si} account={acct} err=locked");
                return;
            };
            let network = Network::from_str_opt(&net.borrow()).unwrap_or(Network::Mainnet);
            let derived = (|| -> Result<(), notes_core::Error> {
                r.set_export_xpub(notes_core::export::account_xpub(seed, si, network, acct)?.into());
                r.set_export_descriptor(
                    notes_core::export::account_descriptor(seed, si, network, acct)?.into(),
                );
                Ok(())
            })();
            if let Err(e) = derived {
                ui.global::<Ui>().set_error(format!("Export failed: {e}").into());
                log::warn!("cb: reveal-public seed={si} account={acct} err={e}");
                return;
            }
            r.set_export_seed_view(false);
            r.set_export_title(export_title(seed, si, acct).into());
            apply_export(0);
            log::info!("cb: reveal-public seed={si} account={acct} ok");
        });
    }
    {
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let net = net.clone();
        let apply_export = apply_export.clone();
        let export_rows = export_rows.clone();
        let reveal_words = reveal_words.clone();
        ui.global::<Callbacks>().on_reveal_private(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let si = *seed_idx.borrow();
            let acct = *bip_account.borrow();
            let Some(seed) = app_seed.as_ref() else {
                ui.global::<Ui>().set_error("Device locked — seed unavailable.".into());
                log::warn!("cb: reveal-private seed={si} account={acct} err=locked");
                return;
            };
            let net_s = net.borrow().clone();
            let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
            let (rows, sel, sel_name) = export_rows(si, acct, &net_s, network);
            let derived = (|| -> Result<(), notes_core::Error> {
                let (hex, wif) = export_leaf_formats(seed, si, network, acct, sel as u32)?;
                r.set_export_hex(hex.into());
                r.set_export_wif(wif.into());
                Ok(())
            })();
            if let Err(e) = derived {
                ui.global::<Ui>().set_error(format!("Export failed: {e}").into());
                log::warn!("cb: reveal-private seed={si} account={acct} err={e}");
                return;
            }
            r.set_export_notebooks(Rc::new(VecModel::from(rows)).into());
            r.set_export_nb_index(sel);
            r.set_export_nb_name(sel_name.into());
            // The 24 words (whole seed) into words-col1/2 + SeedQR.
            reveal_words();
            r.set_export_title(export_title(seed, si, acct).into());
            r.set_export_seed_view(true); // default to the seed-words view
            apply_export(2); // pre-load the hex value/QR for a quick pill switch
            log::info!("cb: reveal-private seed={si} account={acct} ok");
        });
    }
    {
        let apply_export = apply_export.clone();
        ui.global::<Callbacks>().on_export_select(move |which| apply_export(which));
    }
    {
        // Pick which notebook's private key hex/WIF export (hex/WIF only).
        let ui_weak = ui_weak.clone();
        let app_seed = app_seed.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let net = net.clone();
        let notebooks = notebooks.clone();
        let apply_export = apply_export.clone();
        ui.global::<Callbacks>().on_export_pick_notebook(move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            let si = *seed_idx.borrow();
            let acct = *bip_account.borrow();
            let Some(seed) = app_seed.as_ref() else { return };
            let net_s = net.borrow().clone();
            let network = Network::from_str_opt(&net_s).unwrap_or(Network::Mainnet);
            let name = {
                let ixb = notebooks.borrow();
                let n = ixb
                    .visible(si, acct)
                    .find(|m| m.index as i32 == index)
                    .map(|m| {
                        if m.name.trim().is_empty() {
                            let addr = derive_identity(&app_seed, m, &net_s)
                                .map(|id| id.address(network))
                                .unwrap_or_default();
                            short_addr(&addr)
                        } else {
                            m.name.clone()
                        }
                    })
                    .unwrap_or_else(|| format!("index {index}"));
                n
            };
            r.set_export_nb_index(index);
            r.set_export_nb_name(name.into());
            if let Ok((hex, wif)) = export_leaf_formats(seed, si, network, acct, index as u32) {
                r.set_export_hex(hex.into());
                r.set_export_wif(wif.into());
            }
            let which = r.get_export_which();
            if which >= 2 {
                apply_export(which);
            }
        });
    }
    {
        let ui_weak = ui_weak.clone();
        ui.global::<Callbacks>().on_export_close(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let r = ui.global::<Recovery>();
            r.set_export_xpub("".into());
            r.set_export_descriptor("".into());
            r.set_export_hex("".into());
            r.set_export_wif("".into());
            r.set_export_value("".into());
            r.set_export_label("".into());
            r.set_export_title("".into());
            r.set_export_qr(Image::default());
            r.set_export_which(0);
            r.set_export_notebooks(Rc::new(VecModel::from(Vec::<ExportNbRow>::new())).into());
            r.set_export_nb_index(0);
            r.set_export_nb_name("".into());
            // Also wipe the seed-words view (shared with reveal-seed props).
            r.set_export_seed_view(false);
            r.set_words_col1("".into());
            r.set_words_col2("".into());
            r.set_title_line("".into());
            r.set_qr(Image::default());
            r.set_show_qr(false);
            log::info!("cb: reveal-export cancelled");
        });
    }
    {
        // Commit the wallet context (seed index + BIP-86 account) from the
        // Recovery fields, then STAY on the Recovery screen (Sal 2026-07-12
        // — Switch used to jump to the list): persist, flush the open
        // notebook, refresh the list underneath so it's ready when the user
        // navigates back themselves, re-derive the revealed words/SeedQR for
        // the new seed, and show an inline saved confirmation.
        let ui_weak = ui_weak.clone();
        let fs = fs.clone();
        let state = state.clone();
        let active = active.clone();
        let seed_idx = seed_idx.clone();
        let bip_account = bip_account.clone();
        let persist_config = persist_config.clone();
        let refresh_notebooks = refresh_notebooks.clone();
        let reveal_words = reveal_words.clone();
        ui.global::<Callbacks>().on_set_context(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let recovery = ui.global::<Recovery>();
            let parse = |s: &str| -> Option<u32> {
                s.trim().parse::<u32>().ok().filter(|n| *n <= 9999)
            };
            let (Some(new_seed), Some(new_acct)) = (
                parse(recovery.get_seed_text().as_str()),
                parse(recovery.get_account_text().as_str()),
            ) else {
                recovery.set_saved_msg("".into());
                recovery.set_context_error("Seed and account must be 0–9999.".into());
                return;
            };
            recovery.set_context_error("".into());
            let seed_changed = *seed_idx.borrow() != new_seed;
            let acct_changed = *bip_account.borrow() != new_acct;
            if seed_changed || acct_changed {
                if active.borrow().is_some() {
                    save_state(&fs, &state.borrow());
                    *active.borrow_mut() = None;
                }
                *seed_idx.borrow_mut() = new_seed;
                *bip_account.borrow_mut() = new_acct;
                persist_config();
                if seed_changed {
                    log::info!("cb: set-seed-index {new_seed}");
                }
                if acct_changed {
                    log::info!("cb: set-account {new_acct}");
                }
                // Rebuild the (now background) notebook list for the new
                // context, and refresh the revealed words to the new seed.
                refresh_notebooks();
                if !recovery.get_words_col1().is_empty() {
                    reveal_words();
                }
            }
            recovery.set_saved_msg(
                format!("Saved · seed {new_seed} · account {new_acct}").into(),
            );
        });
    }

    // Boot: the notebook list is the main screen. Migrate/seed the index,
    // then land on the list (a fresh install starts empty). Seed/account
    // fields mirror the persisted wallet context; the reveal is enabled
    // whenever the app seed is present (wallet-level — no open notebook).
    ui.global::<Recovery>().set_seed_available(app_seed.is_some());
    ui.global::<Recovery>().set_seed_text(format!("{}", *seed_idx.borrow()).into());
    ui.global::<Recovery>().set_account_text(format!("{}", *bip_account.borrow()).into());
    refresh_notebooks();
    ui.global::<Ui>().set_screen(20);

    ui.run().expect("UI running");
}

/// A single QR (v40, alphanumeric via uppercase hex) holds ~4000 chars —
/// plenty for any normal note tx. Larger txs fall back to file export
/// (animated multi-part UR is future work, with the bundle-in leg).
const MAX_QR_HEX_CHARS: usize = 4000;

fn set_view_qr(view: &View<'_>, n: &NoteRec) {
    let eligible =
        n.status == "pending" && !n.raw_hex.is_empty() && n.raw_hex.len() <= MAX_QR_HEX_CHARS;
    view.set_has_qr(eligible);
    if eligible {
        view.set_qr(qr_image(&n.raw_hex.to_uppercase()));
    }
}

fn qr_image(payload: &str) -> Image {
    qrcode::render(
        payload.as_bytes(),
        Color::from_rgb_u8(0, 0, 0),
        Color::from_rgb_u8(255, 255, 255),
    )
}

/// Raw PSBT bytes from a scanned payload: the system scanner reassembles a
/// crypto-psbt UR into raw bytes; a plain QR may instead carry a hex string.
fn normalize_psbt_bytes(data: &[u8]) -> Vec<u8> {
    if data.starts_with(b"psbt\xff") {
        return data.to_vec();
    }
    // A spec crypto-psbt UR message wraps the PSBT in a CBOR byte string
    // (BCR-2020-006) — what Sparrow, our desktop app, and the KeyOS scanner
    // hand back. Unwrap it.
    if let Some(inner) = cbor_unwrap_bstr(data) {
        if inner.starts_with(b"psbt\xff") {
            return inner;
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(b) = hex::decode(s.trim()) {
            if b.starts_with(b"psbt\xff") {
                return b;
            }
        }
    }
    data.to_vec()
}

/// Minimal CBOR byte-string unwrap (major type 2) — enough for crypto-psbt;
/// avoids a CBOR dependency on-device.
fn cbor_unwrap_bstr(data: &[u8]) -> Option<Vec<u8>> {
    let b0 = *data.first()?;
    let (len, hdr) = match b0 {
        0x40..=0x57 => ((b0 - 0x40) as usize, 1),
        0x58 => (*data.get(1)? as usize, 2),
        0x59 => (u16::from_be_bytes([*data.get(1)?, *data.get(2)?]) as usize, 3),
        0x5a => (
            u32::from_be_bytes([*data.get(1)?, *data.get(2)?, *data.get(3)?, *data.get(4)?]) as usize,
            5,
        ),
        _ => return None,
    };
    data.get(hdr..hdr + len).map(<[u8]>::to_vec)
}

/// Fee = sum(input amounts from witness_utxo) − sum(output amounts).
fn psbt_fee(p: &notes_core::psbt::Psbt) -> u64 {
    let ins: u64 = p.inputs.iter().filter_map(|i| i.witness_utxo.as_ref().map(|w| w.value)).sum();
    let outs: u64 = p.unsigned_tx.outputs.iter().map(|o| o.value).sum();
    ins.saturating_sub(outs)
}

/// A one-line note summary decoded from the PSBT's OP_RETURN output.
fn psbt_note_summary(p: &notes_core::psbt::Psbt) -> String {
    for o in &p.unsigned_tx.outputs {
        if let Some(payload) = notes_core::tx::op_return_payload(&o.script_pubkey) {
            let Some(chunk) = notes_core::envelope::decode(payload) else { continue };
            if chunk.flags & notes_core::envelope::FLAG_PRIVATE != 0 {
                return "Note: encrypted".into();
            }
            if let Ok(body) = notes_core::envelope::reassemble(&[chunk]) {
                if let Ok(t) = String::from_utf8(body) {
                    let short: String = t.chars().take(40).collect();
                    return format!("Note: {short}");
                }
            }
            return "Note: (public)".into();
        }
    }
    "Note: (no note found)".into()
}
