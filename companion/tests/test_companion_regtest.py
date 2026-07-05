#!/usr/bin/env python3
"""Drive the companion page headlessly against the local regtest shim.

Flow (the page does the work — this script only clicks and types):
  faucet → build bundle → download bundle.json → notes_cli compose →
  upload .hex → broadcast (auto-mined) → rebuild bundle → notes_cli scan
  → note text recovered.

Prereqs: companion/server.py running with regtest on :8091, and
`cargo build -p notes-core --example notes_cli` done (target/debug).
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = "http://localhost:8091"
REPO = Path(__file__).resolve().parents[2]
NOTES_CLI = REPO / "target/debug/examples/notes_cli"
SHOTS = Path(__file__).resolve().parent / "screenshots"
SHOTS.mkdir(exist_ok=True)

NOTE_TEXT = "companion-page note: built, broadcast and rescanned through the real UI"


def cli(*args, env=None):
    out = subprocess.run([str(NOTES_CLI), *args], capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def wait_log(section, needle, page, timeout=30000):
    page.wait_for_function(
        "([sel, needle]) => (document.querySelector(sel)?.textContent || '').includes(needle)",
        arg=[section, needle], timeout=timeout,
    )


def build_and_download(page, tmp):
    page.click("#buildBtn")
    with page.expect_download() as dl:
        wait_log("#syncLog", "Bundle ready", page)
        page.click("#downloadBtn")
    path = tmp / dl.value.suggested_filename
    dl.value.save_as(path)
    return path


def main():
    address = cli("address", "regtest")
    print(f"notes address: {address}")
    tmp = Path(tempfile.mkdtemp(prefix="companion_e2e_"))

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(BASE)
        page.wait_for_function("document.querySelector('#modePill').textContent.includes('regtest')")
        assert page.locator('#network').input_value() == "regtest", "regtest should be auto-selected in server mode"

        page.fill("#address", address)
        page.click("#faucetBtn")
        wait_log("#syncLog", "Faucet sent", page)
        print("PASS faucet through the page")

        bundle1 = build_and_download(page, tmp)
        b1 = json.loads(bundle1.read_text())
        assert b1["network"] == "regtest" and b1["utxos"], b1
        assert "max_op_return_bytes" not in b1, "chunk policy is device-side now"
        print(f"PASS bundle built+downloaded ({bundle1.name}: {len(b1['utxos'])} utxo, tip {b1['tip_height']})")
        page.screenshot(path=str(SHOTS / "companion-bundle.png"), full_page=True)

        note = json.loads(cli("compose", str(bundle1), "private", "2", "100000", NOTE_TEXT))
        hex_file = tmp / f"{note['txid']}.hex"
        hex_file.write_text(note["raw_hex"])
        assert note["op_returns"] == 1, "100k policy → single OP_RETURN"

        page.set_input_files("#hexFiles", str(hex_file))
        page.click("#broadcastBtn")
        wait_log("#bcastLog", "accepted", page)
        assert note["txid"] in page.locator("#bcastLog").text_content()
        print(f"PASS broadcast through the page, txid {note['txid']}")
        page.screenshot(path=str(SHOTS / "companion-broadcast.png"), full_page=True)

        # Negative: garbage hex must surface a reject reason, not a txid.
        page.fill("#hexPaste", "02" * 60)
        page.set_input_files("#hexFiles", [])
        page.click("#broadcastBtn")
        wait_log("#bcastLog", "REJECTED", page)
        print("PASS reject-reason surfaced for bad hex")

        bundle2 = build_and_download(page, tmp)
        b2 = json.loads(bundle2.read_text())
        assert any(t["txid"] == note["txid"] and t["spends_from_self"] for t in b2["notes_onchain"]), b2
        scan = json.loads(cli("scan", str(bundle2)))
        texts = [n["text"] for n in scan]
        assert NOTE_TEXT in texts, texts
        confirmed = next(n for n in scan if n["text"] == NOTE_TEXT)
        assert confirmed["height"] is not None, "auto-mine should have confirmed it"
        print(f"PASS note recovered from page-built bundle, confirmed at height {confirmed['height']}")

        browser.close()
    print("COMPANION REGTEST E2E PASSED")


if __name__ == "__main__":
    sys.exit(main())
