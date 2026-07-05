#!/usr/bin/env bash
# End-to-end proof of the chain-notes pipeline on a private regtest chain.
#
#   device role   = notes_cli (notes-core example, host build)
#   companion role = bitcoin-cli against a throwaway bitcoind -regtest
#
# Covers: funding, private note, public note, multi-chunk 80-byte-policy
# note, >80-byte single-OP_RETURN note (Core v30 datacarrier default),
# unconfirmed-change chaining, full-history rescan ("wipe restore"), and
# the wrong-seed negative check.
set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; NC=$'\033[0m'
pass() { echo "${GRN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*"; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${E2E_WORK:-$(mktemp -d /tmp/chain-notes-e2e.XXXXXX)}"
DATADIR="$WORK/bitcoind"
mkdir -p "$DATADIR"
CLI() { bitcoin-cli -regtest -datadir="$DATADIR" "$@"; }
WATCH() { CLI -rpcwallet=watch "$@"; }
MINER() { CLI -rpcwallet=miner "$@"; }
NOTES="$WORK/notes_cli"

cleanup() { CLI stop >/dev/null 2>&1 || true; sleep 1; }
trap cleanup EXIT

echo "== build notes_cli (host) =="
( cd "$REPO" && cargo build -q -p notes-core --example notes_cli )
cp "$REPO/target/debug/examples/notes_cli" "$NOTES"

echo "== start throwaway bitcoind -regtest in $WORK =="
# -txindex: the companion resolves arbitrary prevouts to compute
# spends_from_self (mempool.space has this by construction).
bitcoind -regtest -datadir="$DATADIR" -daemonwait -txindex=1 -fallbackfee=0.0001 >/dev/null
CLI createwallet miner >/dev/null

ADDR="$("$NOTES" address regtest)"
echo "notes address: $ADDR"
[[ "$ADDR" == bcrt1p* ]] || fail "expected a bcrt1p taproot address"

echo "== watch-only companion wallet (descriptor import — the 'scanner') =="
CLI createwallet watch true true >/dev/null   # disable_private_keys, blank
DESC="$(CLI getdescriptorinfo "addr($ADDR)" | jq -r .descriptor)"
WATCH importdescriptors "[{\"desc\":\"$DESC\",\"timestamp\":0}]" >/dev/null

echo "== fund: miner matures coins, sends 0.001 BTC to the notes address =="
MINER generatetoaddress 101 "$(MINER getnewaddress)" >/dev/null
MINER sendtoaddress "$ADDR" 0.001 >/dev/null
MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null

# ---------------------------------------------------------------------------
# Companion role: build a sync bundle from the watch wallet.
#   - UTXOs from listunspent minconf=0 (unconfirmed chaining support)
#   - history from listtransactions; per tx, OP_RETURN payloads and the
#     spends-from-self flag (does any input's prevout pay our address?)
# ---------------------------------------------------------------------------
build_bundle() { # $1 = output path
    local tip utxos txids notes_onchain
    tip="$(CLI getblockcount)"
    utxos="$(WATCH listunspent 0 9999999 | jq '[.[] | {txid, vout, value: (.amount*1e8|round), height: (if .confirmations > 0 then '"$tip"' - .confirmations + 1 else null end)}]')"
    txids="$(WATCH listtransactions '*' 1000 | jq -r '[.[].txid] | unique | .[]')"
    notes_onchain="[]"
    for txid in $txids; do
        local raw payloads self height blocktime
        raw="$(CLI getrawtransaction "$txid" 2 2>/dev/null || CLI -rpcwallet=watch gettransaction "$txid" true true | jq .decoded)"
        # asm for nulldata is "OP_RETURN <payload-hex>"; take the data token.
        payloads="$(jq '[.vout[] | select(.scriptPubKey.type=="nulldata") | .scriptPubKey.asm | split(" ") | .[-1]]' <<<"$raw")"
        [[ "$payloads" == "[]" ]] && continue
        self=false
        for prev in $(jq -r '.vin[] | "\(.txid):\(.vout)"' <<<"$raw"); do
            local ptxid=${prev%%:*} pvout=${prev##*:}
            local pspk_addr
            pspk_addr="$(CLI getrawtransaction "$ptxid" 2 2>/dev/null | jq -r ".vout[$pvout].scriptPubKey.address // empty")"
            [[ "$pspk_addr" == "$ADDR" ]] && self=true && break
        done
        local conf
        conf="$(WATCH gettransaction "$txid" true | jq .confirmations)"
        if (( conf > 0 )); then
            height=$(( tip - conf + 1 ))
            blocktime="$(WATCH gettransaction "$txid" true | jq .blocktime)"
        else
            height=null; blocktime=null
        fi
        notes_onchain="$(jq --argjson tx "{\"txid\":\"$txid\",\"height\":$height,\"blocktime\":$blocktime,\"spends_from_self\":$self,\"payloads\":$payloads}" '. + [$tx]' <<<"$notes_onchain")"
    done
    jq -n --argjson utxos "$utxos" --argjson notes "$notes_onchain" --argjson tip "$tip" '{
        network: "regtest", full: true, tip_height: $tip,
        bundle_time: 1750000000, max_op_return_bytes: 80,
        fee_rates: {fastestFee: 2, halfHourFee: 2, hourFee: 1, economyFee: 1, minimumFee: 1},
        utxos: $utxos, notes_onchain: $notes
    }' > "$1"
}

broadcast() { # $1 = compose json -> txid
    local hex txid
    hex="$(jq -r .raw_hex <<<"$1")"
    CLI testmempoolaccept "[\"$hex\"]" | jq -e '.[0].allowed' >/dev/null \
        || fail "testmempoolaccept rejected: $(CLI testmempoolaccept "[\"$hex\"]" | jq -r '.[0]["reject-reason"]')"
    txid="$(CLI sendrawtransaction "$hex")"
    [[ "$txid" == "$(jq -r .txid <<<"$1")" ]] || fail "txid mismatch: ours $(jq -r .txid <<<"$1") vs node $txid"
    echo "$txid"
}

echo "== note 1: private, 80-byte chunk policy =="
build_bundle "$WORK/bundle1.json"
N1="$("$NOTES" compose "$WORK/bundle1.json" private 2 80 'private note #1: remember the airlock lifecycle')"
T1="$(broadcast "$N1")"; pass "note1 broadcast+txid-match $T1 (fee $(jq .fee <<<"$N1") sats, $(jq .op_returns <<<"$N1") OP_RETURNs)"

echo "== note 2: public, spends note1's UNCONFIRMED change =="
build_bundle "$WORK/bundle2.json"
jq -e '.utxos | length == 1' "$WORK/bundle2.json" >/dev/null || fail "expected exactly the unconfirmed change UTXO, got: $(jq .utxos "$WORK/bundle2.json")"
jq -e '.utxos[0].height == null' "$WORK/bundle2.json" >/dev/null || fail "change UTXO should be unconfirmed"
N2="$("$NOTES" compose "$WORK/bundle2.json" public 2 80 'public note: hello, blockchain — proof I existed on regtest')"
T2="$(broadcast "$N2")"; pass "note2 chained onto unconfirmed change $T2"

MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null

echo "== note 3: long private note → multiple 80-byte OP_RETURN outputs =="
build_bundle "$WORK/bundle3.json"
LONG="chunked note: $(printf '~%.0s' {1..200})"   # 214 chars → 4 chunks sealed
N3="$("$NOTES" compose "$WORK/bundle3.json" private 2 80 "$LONG")"
(( $(jq .op_returns <<<"$N3") > 1 )) || fail "expected multiple OP_RETURN outputs"
T3="$(broadcast "$N3")"; pass "note3 multi-chunk ($(jq .op_returns <<<"$N3") OP_RETURNs) $T3"

echo "== note 4: >80-byte SINGLE OP_RETURN (Core v30 datacarrier default) =="
BIG="big single-output note $(printf '=%.0s' {1..300})"   # 323 bytes, one output
build_bundle "$WORK/bundle4.json"
N4="$("$NOTES" compose "$WORK/bundle4.json" public 2 100000 "$BIG")"
jq -e '.op_returns == 1' <<<"$N4" >/dev/null || fail "expected one big OP_RETURN"
T4="$(broadcast "$N4")"; pass "note4 large single OP_RETURN relayed by v30 defaults $T4"

MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null

echo "== wipe-restore: full rescan from chain, no local state =="
build_bundle "$WORK/restore.json"
SCAN="$("$NOTES" scan "$WORK/restore.json")"
echo "$SCAN" | jq -r '.[] | "\(.height)\t\(.private)\t\(.text | tostring | .[0:60])"'
(( $(jq length <<<"$SCAN") == 4 )) || fail "expected 4 recovered notes, got $(jq length <<<"$SCAN")"
jq -e '[.[] | select(.text == null)] | length == 0' >/dev/null <<<"$SCAN" || fail "null text in scan"
grep -q 'private note #1' <<<"$SCAN" || fail "note1 text missing"
grep -q 'proof I existed' <<<"$SCAN" || fail "note2 text missing"
grep -q 'chunked note' <<<"$SCAN" || fail "note3 text missing"
grep -q 'big single-output note' <<<"$SCAN" || fail "note4 text missing"
jq -e '[.[] | select(.height != null)] | length == 4' >/dev/null <<<"$SCAN" || fail "all notes should be confirmed"
pass "all 4 notes recovered from bare chain data (texts, heights, visibility)"

echo "== negative: a different seed cannot read the private notes =="
WRONG="$(NOTES_APP_SEED=$(printf '99%.0s' {1..32}) "$NOTES" scan "$WORK/restore.json")"
jq -e '[.[] | select(.private and .text != null)] | length == 0' >/dev/null <<<"$WRONG" \
    || fail "foreign seed decrypted a private note!"
jq -e '[.[] | select(.private == false and .text != null)] | length == 2' >/dev/null <<<"$WRONG" \
    || fail "public notes should still be readable by anyone"
pass "private notes unreadable under a foreign seed; public notes readable"

echo "== public note is genuinely plaintext on-chain =="
CLI getrawtransaction "$T2" 2 | jq -r '.vout[].scriptPubKey.asm' | grep -q "$(printf 'public note: hello, blockchain — proof I existed on regtest' | xxd -p -c 10000 | head -c 40)" \
    && pass "note2 plaintext visible in raw chain data" \
    || fail "could not find plaintext payload in note2's tx"

echo
echo "${GRN}ALL E2E CHECKS PASSED${NC}  (workdir: $WORK)"
