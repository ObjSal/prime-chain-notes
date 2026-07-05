mod theme;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use notes_core::bundle::{compose_note, estimate_note_cost, extract_notes, Identity, SyncBundle};
use notes_core::keys::{generate_aux_rand, generate_note_id};
use notes_core::tx::{NoteTx, Utxo};
use notes_core::Network;
use serde::{Deserialize, Serialize};
use slint_keyos_platform::app_ui;
use slint_keyos_platform::fs::{self, Location, OpenFlags};
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
}

#[derive(Serialize, Deserialize, Clone)]
struct UtxoRec {
    txid: String, // display hex
    vout: u32,
    value: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct State {
    network: String,
    notes: Vec<NoteRec>,
    utxos: Vec<UtxoRec>,
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

fn preview_of(text: &str) -> String {
    let one_line: String = text.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    let mut p: String = one_line.chars().take(40).collect();
    if one_line.chars().count() > 40 {
        p.push('…');
    }
    p
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
                    "network: {}\nbalance: {} sats · {} utxos\ntip: {}\nfees (sat/vB): {}/{}/{} · chunk: {} bytes",
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
                    meta: match n.height {
                        Some(h) => format!("block {h} · {} chunk(s)", n.chunks.max(1)),
                        None => format!("pending · fee {} sats", n.fee),
                    }
                    .into(),
                    badge: if n.private { "PRIVATE" } else { "PUBLIC" }.into(),
                })
                .collect();
            log::info!("cb: refresh-notes n={}", rows.len());
            ui.global::<Notes>().set_rows(Rc::new(VecModel::from(rows)).into());
        }
    };

    // Keystroke cost estimator — pure arithmetic, no crypto runs (see
    // notes-core crypt::SEAL_OVERHEAD), so per-keystroke recompute is free.
    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
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
                return;
            }
            if st.utxos.is_empty() {
                compose
                    .set_cost_line("No funds — fund the address and import a sync bundle.".into());
                compose.set_can_continue(false);
                return;
            }
            match estimate_note_cost(
                text_len,
                compose.get_private_note(),
                st.effective_chunk(),
                1,
            ) {
                Ok((chunks, vsize)) => {
                    let fee = (vsize as f64 * rate).ceil() as u64;
                    if fee > st.balance() {
                        compose.set_cost_line(
                            format!("Needs ~{fee} sats — balance is {}.", st.balance()).into(),
                        );
                        compose.set_can_continue(false);
                    } else {
                        compose.set_cost_line(
                            format!(
                                "{text_len} bytes · {chunks} chunk(s) · ~{vsize} vB · ~{} @ {rate} sat/vB",
                                sats_line(fee, st.btc_usd)
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
                let tier = compose.get_tier();
                let rate_text = compose.get_rate_text().to_string();
                let st = state.borrow();
                let result = identity
                    .as_ref()
                    .as_ref()
                    .ok_or_else(|| "identity unavailable".to_string())
                    .and_then(|id| {
                        let rate = resolve_rate(tier, &rate_text, &st)?;
                        let note_id = generate_note_id().map_err(|e| e.to_string())?;
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
                        .map(|n| (note_id, n))
                        .map_err(|e| e.to_string())
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
                            "cb: compose len={} private={} chunks={} fee={} vsize={} txid={} ok",
                            text.len(),
                            private,
                            chunks,
                            note.fee,
                            note.vsize,
                            note.txid_hex
                        );
                        let balance_after = st.balance() - note.fee;
                        ui.global::<Confirm>().set_summary(
                            format!(
                                "{}\n\nsize: {} bytes in {} chunk(s)\ntx: {} vB · {} input(s)\nfee: {}\nchange back to you: {} sats\nbalance after: {} sats\n\ntxid:\n{}",
                                if private {
                                    "PRIVATE — encrypted with your device seed"
                                } else {
                                    "PUBLIC — plaintext, world-readable forever"
                                },
                                text.len(),
                                chunks,
                                note.vsize,
                                note.tx.inputs.len(),
                                sats_line(note.fee, st.btc_usd),
                                note.change,
                                balance_after,
                                note.txid_hex
                            )
                            .into(),
                        );
                        *plan.borrow_mut() = Some(Plan { note, text, private, note_id, chunks });
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
                        vout: p.chunks as u32, // change follows the OP_RETURNs
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
            view.set_meta(format!("{where_line}\ntxid: {}", n.txid).into());
            set_view_qr(&view, n);
            view.set_show_qr(false);
            log::info!("cb: open-note id={} status={} qr={}", n.id, n.status, view.get_has_qr());
            ui.global::<Ui>().set_screen(2);
        });
    }

    {
        let ui_weak = ui_weak.clone();
        let state = state.clone();
        let identity = identity.clone();
        let fs = fs.clone();
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_import_bundle(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            let result = (|| -> Result<String, String> {
                let id = identity.as_ref().as_ref().ok_or("identity unavailable")?;
                let (name, loc, loc_label) =
                    first_inbox_bundle(&fs).ok_or("no .json bundle in /chain-notes/inbox")?;
                let json = read_text(&fs, &format!("{INBOX_DIR}/{name}"), loc)?;
                if loc == Location::Airlock {
                    unmount_airlock(&fs);
                }
                let bundle =
                    SyncBundle::from_json(&json).map_err(|e| format!("bad bundle: {e}"))?;
                let mut st = state.borrow_mut();
                if !bundle.network.is_empty() && bundle.network != st.network {
                    return Err(format!(
                        "bundle is for {}, app is on {} — switch network first",
                        bundle.network, st.network
                    ));
                }

                let recovered = extract_notes(&bundle, &id.enc_key);
                let mut new_notes = 0usize;
                for r in &recovered {
                    let id_hex = hex::encode(r.note_id);
                    match st.notes.iter_mut().find(|n| n.id == id_hex) {
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
                                text: r
                                    .text
                                    .clone()
                                    .unwrap_or("(sealed under another key)".into()),
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
                    "cb: import-bundle file={name} loc={loc_label} notes={} new={new_notes} utxos={} tip={} ok",
                    recovered.len(),
                    st.utxos.len(),
                    bundle.tip_height
                );
                Ok(format!(
                    "Imported {name}: {} note(s) ({new_notes} new), {} utxo(s), tip {}.",
                    recovered.len(),
                    st.utxos.len(),
                    bundle.tip_height
                ))
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

    {
        let state = state.clone();
        let fs = fs.clone();
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_cycle_network(move || {
            let mut st = state.borrow_mut();
            st.network = match st.network.as_str() {
                "mainnet" => "signet".into(),
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

    {
        let refresh_home = refresh_home.clone();
        ui.global::<Callbacks>().on_refresh_home(move || refresh_home());
    }
    {
        let refresh_notes = refresh_notes.clone();
        ui.global::<Callbacks>().on_refresh_notes(move || refresh_notes());
    }

    refresh_home();
    refresh_notes();

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
