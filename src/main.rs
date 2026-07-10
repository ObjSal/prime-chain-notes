mod theme;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use notes_core::address::Recipient;
use notes_core::bundle::{
    compose_directed_note_with_change_amount, compose_note, decode_scanned, estimate_note_cost,
    extract_notes, Identity, SyncBundle,
};
use notes_core::address::p2tr_script_pubkey;
use notes_core::keys::{generate_aux_rand, generate_note_id, pick_unique_note_id};
use notes_core::tx::{build_sweep_tx, estimate_sweep_vsize, NoteTx, Utxo};
use notes_core::Network;
use serde::{Deserialize, Serialize};
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
const STATE_PATH: &str = "/.chain-notes/state.json";
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
    network: String,
    notes: Vec<NoteRec>,
    utxos: Vec<UtxoRec>,
    contacts: Vec<ContactRec>,
    tip_height: Option<u64>,
    bundle_time: Option<u64>,
    /// User-picked chunk size; None = DEFAULT_CHUNK. Purely device-side.
    chunk_override: Option<usize>,
    fee_economy: f64,
    fee_normal: f64,
    fee_fast: f64,
    btc_usd: Option<f64>,
}

impl Default for State {
    fn default() -> Self {
        State {
            network: "mainnet".into(),
            notes: Vec::new(),
            utxos: Vec::new(),
            contacts: Vec::new(),
            tip_height: None,
            bundle_time: None,
            chunk_override: None,
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
}

/// A built-and-signed sweep/consolidate waiting for user confirmation.
struct SweepPlan {
    tx: NoteTx,
    kind: &'static str,      // "sweep" | "consolidate"
    dest: Option<String>,    // None = self (consolidate)
}

// ------------------------------------------------------------- helpers

fn load_state(fs: &Fs) -> State {
    read_text(fs, STATE_PATH, Location::User)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

fn save_state(fs: &Fs, state: &State) {
    let json = serde_json::to_string(state).expect("state serializes");
    if let Err(e) = ensure_dir(fs, STATE_DIR, Location::User)
        .and_then(|_| write_file(fs, STATE_PATH, Location::User, json.as_bytes()))
    {
        log::warn!("state save failed: {e}");
    }
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

// ---------------------------------------------------------------- main

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let fs = cx.fs.clone();
    let ui_weak = ui.as_weak();

    let state = Rc::new(RefCell::new(load_state(&fs)));
    let plan: Rc<RefCell<Option<Plan>>> = Rc::new(RefCell::new(None));
    let sweep_plan: Rc<RefCell<Option<SweepPlan>>> = Rc::new(RefCell::new(None));

    // Identity from GetAppSeed — PIN-gated on hardware. Everything (address,
    // signing key, encryption key) re-derives from the device seed backup.
    let identity: Rc<Option<Identity>> = Rc::new(
        match Security::default()
            .app_seed()
            .map_err(|_| "Device locked or seed unavailable".to_string())
            .and_then(|app_seed| Identity::from_app_seed(&app_seed).map_err(|e| e.to_string()))
        {
            Ok(id) => Some(id),
            Err(e) => {
                log::warn!("identity unavailable: {e}");
                ui.global::<Ui>().set_error(e.into());
                None
            }
        },
    );

    let refresh_home = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let home = ui.global::<Home>();
            home.set_network(st.network.clone().into());
            if let Some(id) = identity.as_ref() {
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
            settings.set_chunk_mode(match st.chunk_override {
                None => 0,
                Some(80) => 1,
                Some(_) => 2,
            });
            settings.set_chunk_text(format!("{}", st.effective_chunk()).into());
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
            let mut recs: Vec<&NoteRec> = st.notes.iter().collect();
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
            log::info!("cb: refresh-notes n={}", rows.len());
            ui.global::<Notes>().set_rows(Rc::new(VecModel::from(rows)).into());
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
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let st = state.borrow();
            let mut recs: Vec<&UtxoRec> = st.utxos.iter().collect();
            recs.sort_by_key(|u| std::cmp::Reverse(u.value));
            let rows: Vec<CoinRow> = recs
                .iter()
                .map(|u| CoinRow {
                    label: format!("{} sats", u.value).into(),
                    meta: format!("txid {} · output {}", short_addr(&u.txid), u.vout).into(),
                })
                .collect();
            let coins = ui.global::<Coins>();
            coins.set_summary(
                format!("{} coin(s) · {}", rows.len(), sats_line(st.balance(), st.btc_usd)).into(),
            );
            coins.set_can_consolidate(rows.len() >= 2);
            log::info!("cb: refresh-coins n={} total={}", rows.len(), st.balance());
            coins.set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    // Sweep screen (10) repricing — every tier tap / rate keystroke. Pure
    // arithmetic (estimate_sweep_vsize is byte-exact vs build_sweep_tx).
    let update_sweep = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let sweep = ui.global::<Sweep>();
            let st = state.borrow();
            let tier = sweep.get_tier();
            if tier != 3 {
                sweep.set_rate_text(format!("{}", st.fee_rate(tier)).into());
            }
            let n = st.utxos.len();
            let total = st.balance();
            sweep.set_inputs_line(format!("Inputs · {n} coin(s) · {total} sats (all)").into());
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

    // The single pick funnel (self row / recent row / manual entry / scan):
    // validates, bumps recency, sets the compose recipient + label, and
    // navigates. Invalid manual input stays on the picker with an error.
    let pick_contact = {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
        let update_sweep = update_sweep.clone();
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
        ui.global::<Callbacks>().on_sweep_continue(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let identity = identity.clone();
            let sweep_plan = sweep_plan.clone();
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
                let result = identity
                    .as_ref()
                    .as_ref()
                    .ok_or_else(|| "identity unavailable".to_string())
                    .and_then(|id| {
                        let rate = resolve_rate(tier, &rate_text, &st)?;
                        let dest_spk = if consolidate {
                            p2tr_script_pubkey(&id.output_x)
                        } else {
                            Recipient::parse(st.network(), &dest).map_err(|e| e.to_string())?.spk
                        };
                        build_sweep_tx(
                            &st.core_utxos(),
                            &id.output_x,
                            dest_spk,
                            rate,
                            &id.tweaked_seckey,
                            || generate_aux_rand(),
                        )
                        .map_err(|e| e.to_string())
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok(tx) => {
                        let total: u64 = st.balance();
                        let recv = tx.tx.outputs[0].value;
                        log::info!(
                            "cb: sweep kind={kind} to={} inputs={} amount={recv} fee={} vsize={} txid={} ok",
                            if consolidate { "self" } else { dest.as_str() },
                            tx.tx.inputs.len(),
                            tx.fee,
                            tx.vsize,
                            tx.txid_hex
                        );
                        sweep.set_confirm_summary(
                            format!(
                                "{}\n\ninputs: {} coin(s) · {total} sats\nfee: {}\n{}: {recv} sats\n\ntxid:\n{}",
                                if consolidate {
                                    "Consolidates every coin into one — back to your own address."
                                } else {
                                    "Sweeps EVERYTHING to the destination — this empties the notes address."
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
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_sweep_sign(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(p) = sweep_plan.borrow_mut().take() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let fs = fs.clone();
            let refresh_home = refresh_home.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let mut st = state.borrow_mut();

                // Ledger: every input is spent; a consolidate's single
                // output comes straight back as our own (unconfirmed) coin.
                let spent: Vec<(String, u32)> = p
                    .tx
                    .spent_outpoints
                    .iter()
                    .map(|(txid, vout)| {
                        let mut t = *txid;
                        t.reverse();
                        (hex::encode(t), *vout)
                    })
                    .collect();
                let inputs = spent.len();
                st.utxos.retain(|u| !spent.contains(&(u.txid.clone(), u.vout)));
                let recv = p.tx.tx.outputs[0].value;
                if p.kind == "consolidate" {
                    st.utxos.push(UtxoRec { txid: p.tx.txid_hex.clone(), vout: 0, value: recv });
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

    // Edge-tracks whether the compose draft is over the broadcast ceiling, so
    // the "too large" dialog pops once on crossing — not on every keystroke.
    let compose_oversize = Rc::new(std::cell::Cell::new(false));

    // Keystroke cost estimator — pure arithmetic, no crypto runs (see
    // notes-core crypt::SEAL_OVERHEAD), so per-keystroke recompute is free.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let compose_oversize = compose_oversize.clone();
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
            let text = compose.get_text();
            let text_len = text.as_str().len();
            if text_len == 0 {
                compose.set_cost_line("Type to see the cost.".into());
                compose.set_can_continue(false);
                compose_oversize.set(false); // clearing the draft re-arms the dialog
                return;
            }
            if st.utxos.is_empty() {
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
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let plan = plan.clone();
        ui.global::<Callbacks>().on_compose_continue(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let identity = identity.clone();
            let plan = plan.clone();
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
                let result = identity
                    .as_ref()
                    .as_ref()
                    .ok_or_else(|| "identity unavailable".to_string())
                    .and_then(|id| {
                        let rate = resolve_rate(tier, &rate_text, &st)?;
                        let note_id = pick_unique_note_id(generate_note_id, |id| {
                            let id_hex = hex::encode(id);
                            st.notes.iter().any(|n| n.id == id_hex)
                        })
                        .map_err(|e| e.to_string())?;
                        let note = if directed {
                            let recipient = Recipient::parse(st.network(), &to_address)
                                .map_err(|e| e.to_string())?;
                            // Gift amount: the recipient output carries `gift`
                            // sats (>= dust). change_spk None = change to self.
                            compose_directed_note_with_change_amount(
                                id,
                                &st.core_utxos(),
                                &text,
                                private,
                                note_id,
                                &recipient,
                                gift,
                                None,
                                st.effective_chunk(),
                                rate,
                                || generate_aux_rand(),
                            )
                        } else {
                            compose_note(
                                id,
                                &st.core_utxos(),
                                &text,
                                private,
                                note_id,
                                st.effective_chunk(),
                                rate,
                                || generate_aux_rand(),
                            )
                        };
                        note.map(|n| (note_id, n)).map_err(|e| e.to_string())
                    });
                ui.global::<Ui>().set_busy(false);
                match result {
                    Ok((note_id, note)) => {
                        let chunks = note
                            .tx
                            .outputs
                            .iter()
                            .filter(|o| o.script_pubkey.first() == Some(&0x6a))
                            .count() as u64;
                        log::info!(
                            "cb: compose len={} private={} to={} chunks={} fee={} vsize={} gift={} txid={} ok",
                            text.len(),
                            private,
                            if directed { to_address.as_str() } else { "self" },
                            chunks,
                            note.fee,
                            note.vsize,
                            note.sent,
                            note.txid_hex
                        );
                        let balance_after = st.balance() - note.fee - note.sent;
                        ui.global::<Confirm>().set_summary(
                            format!(
                                "{}{}\n\nsize: {} bytes in {} chunk(s)\ntx: {} vB · {} input(s)\nfee: {}{}\nchange back to you: {} sats\nbalance after: {} sats\n\ntxid:\n{}",
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
                                note.change,
                                balance_after,
                                note.txid_hex
                            )
                            .into(),
                        );
                        let recipient = if directed { Some(to_address) } else { None };
                        *plan.borrow_mut() =
                            Some(Plan { note, text, private, note_id, chunks, recipient });
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
        ui.global::<Callbacks>().on_confirm_sign(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(p) = plan.borrow_mut().take() else { return };
            ui.global::<Ui>().set_busy(true);
            let ui_weak = ui_weak.clone();
            let state = state.clone();
            let fs = fs.clone();
            let refresh_notes = refresh_notes.clone();
            Timer::single_shot(Duration::from_millis(150), move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                let mut st = state.borrow_mut();

                // Ledger: drop spent inputs, add our own change (chaining
                // between syncs — several notes can queue unconfirmed).
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
                if p.note.change > 0 {
                    st.utxos.push(UtxoRec {
                        txid: p.note.txid_hex.clone(),
                        // Change follows the OP_RETURNs — and, for directed
                        // notes, the recipient dust output.
                        vout: p.chunks as u32 + u32::from(p.recipient.is_some()),
                        value: p.note.change,
                    });
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
        Rc::new(move |json: &str, src: &str| -> Result<String, String> {
            let id = identity.as_ref().as_ref().ok_or("identity unavailable")?;
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

                let recovered = extract_notes(&bundle, id, st.network());
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

                st.utxos = bundle
                    .utxos
                    .iter()
                    .map(|u| UtxoRec { txid: u.txid.clone(), vout: u.vout, value: u.value })
                    .collect();
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
            let Some(id) = identity.as_ref() else {
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
        let state = state.clone();
        let fs = fs.clone();
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_cycle_network(move || {
            let mut st = state.borrow_mut();
            st.network = match st.network.as_str() {
                "mainnet" => "testnet4".into(),
                "testnet4" => "signet".into(),
                "signet" => "regtest".into(),
                _ => "mainnet".into(),
            };
            log::info!("cb: set-network {}", st.network);
            save_state(&fs, &st);
            drop(st);
            refresh_home();
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let fs = fs.clone();
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
        let refresh_contacts = refresh_contacts.clone();
        ui.global::<Callbacks>().on_refresh_contacts(move || refresh_contacts());
    }

    refresh_home();
    refresh_notes();
    refresh_contacts();

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
