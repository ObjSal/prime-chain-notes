#!/usr/bin/env bash
# Companion-role helper against a local bitcoind -regtest, shared by the
# regtest e2e and the simulator UI test. The DATADIR node must already run
# (bitcoind -regtest -datadir=$DATADIR -txindex=1 -fallbackfee=0.0001).
#
#   regtest-companion.sh setup <notes_address>            # miner+watch wallets, fund 0.001, mine
#   regtest-companion.sh bundle <out.json> [owner_addr ...]  # sync bundle from watch wallet,
#                                                          # + owner_address-tagged coins for
#                                                          # each extra address (spending wallet;
#                                                          # mirrors companion/index.html's
#                                                          # "Spending wallet addresses" merge —
#                                                          # scanned via scantxoutset, no wallet
#                                                          # import needed since these addresses
#                                                          # are never mined-to/spent-from here)
#   regtest-companion.sh broadcast <file.hex>    # sendrawtransaction
#   regtest-companion.sh mine [n]                # confirm
set -euo pipefail

DATADIR="${DATADIR:?set DATADIR to the regtest datadir}"
CLI() { bitcoin-cli -regtest -datadir="$DATADIR" "$@"; }
WATCH() { CLI -rpcwallet=watch "$@"; }
MINER() { CLI -rpcwallet=miner "$@"; }
ADDR_FILE="$DATADIR/notes-address"

case "${1:?subcommand}" in
setup)
    ADDR="${2:?notes address}"
    echo "$ADDR" > "$ADDR_FILE"
    CLI createwallet miner >/dev/null
    CLI createwallet watch true true >/dev/null
    DESC="$(CLI getdescriptorinfo "addr($ADDR)" | jq -r .descriptor)"
    WATCH importdescriptors "[{\"desc\":\"$DESC\",\"timestamp\":0}]" >/dev/null
    MINER generatetoaddress 101 "$(MINER getnewaddress)" >/dev/null
    MINER sendtoaddress "$ADDR" 0.001 >/dev/null
    MINER generatetoaddress 1 "$(MINER getnewaddress)" >/dev/null
    echo "funded $ADDR with 100000 sats"
    ;;
bundle)
    OUT="${2:?output path}"
    shift 2
    ADDR="$(cat "$ADDR_FILE")"
    tip="$(CLI getblockcount)"
    utxos="$(WATCH listunspent 0 9999999 | jq '[.[] | {txid, vout, value: (.amount*1e8|round), height: (if .confirmations > 0 then '"$tip"' - .confirmations + 1 else null end)}]')"
    # Extra owner-tagged addresses (funding-unification spending wallet):
    # scanned directly via scantxoutset (node-level, no wallet import
    # needed — these addresses are only ever funded/observed, never
    # mined-to or spent-from by this script).
    for OWNER in "$@"; do
        owner_utxos="$(CLI scantxoutset start "[\"addr($OWNER)\"]" \
            | jq --arg a "$OWNER" '[.unspents[] | {txid, vout, value: (.amount*1e8|round), height: (if .height > 0 then .height else null end), owner_address: $a}]')"
        utxos="$(jq -c --argjson extra "$owner_utxos" '. + $extra' <<<"$utxos")"
    done
    notes_onchain="[]"
    for txid in $(WATCH listtransactions '*' 1000 | jq -r '[.[].txid] | unique | .[]'); do
        raw="$(CLI getrawtransaction "$txid" 2)"
        payloads="$(jq '[.vout[] | select(.scriptPubKey.type=="nulldata") | .scriptPubKey.asm | split(" ") | .[-1]]' <<<"$raw")"
        [[ "$payloads" == "[]" ]] && continue
        self=false
        for prev in $(jq -r '.vin[] | "\(.txid):\(.vout)"' <<<"$raw"); do
            pspk_addr="$(CLI getrawtransaction "${prev%%:*}" 2 | jq -r ".vout[${prev##*:}].scriptPubKey.address // empty")"
            [[ "$pspk_addr" == "$ADDR" ]] && self=true && break
        done
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
        bundle_time: 1750000000, max_op_return_bytes: 100000,
        fee_rates: {fastestFee: 3, halfHourFee: 2, hourFee: 1, economyFee: 1, minimumFee: 1},
        btc_usd: 100000,
        utxos: $utxos, notes_onchain: $notes
    }' > "$OUT"
    echo "bundle → $OUT ($(jq '.utxos|length' "$OUT") utxos, $(jq '.notes_onchain|length' "$OUT") note-txs, tip $tip)"
    ;;
broadcast)
    HEX="$(cat "${2:?hex file}")"
    CLI testmempoolaccept "[\"$HEX\"]" | jq -e '.[0].allowed' >/dev/null || {
        echo "REJECTED: $(CLI testmempoolaccept "[\"$HEX\"]" | jq -r '.[0]["reject-reason"]')" >&2
        exit 1
    }
    CLI sendrawtransaction "$HEX"
    ;;
mine)
    MINER generatetoaddress "${2:-1}" "$(MINER getnewaddress)" >/dev/null
    echo "mined ${2:-1}"
    ;;
*)
    echo "unknown subcommand $1" >&2
    exit 2
    ;;
esac
