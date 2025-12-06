    """
    Heuristically extract 4-byte selectors from runtime bytecode.

    We scan for PUSH4 (0x63) opcodes followed by 4 bytes, which matches
    the common Solidity dispatcher pattern:
        PUSH4 <selector> ; EQ ; ...
    This may miss selectors in non-standard dispatch code paths.
    """

from __future__ import annotations

import os
import sys
import json
import time
import argparse
from typing import Dict, List, Set, Tuple, Any, Optional

from web3 import Web3
from eth_utils import keccak

SelectorHex = str            # 8 hex chars, no 0x
SelectorSet = Set[SelectorHex]
SignatureMap = Dict[str, SelectorHex]  # "foo(uint256)" -> selector

DEFAULT_RPC = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY")
RPC_TIMEOUT = int(os.getenv("RPC_TIMEOUT", "30"))

MAX_PREVIEW = 20  # max selectors to preview in logs


# --- basic helpers ---------------------------------------------------------


def checksum(addr: str) -> str:
    if not isinstance(addr, str) or not Web3.is_address(addr):
        print(f"❌ Invalid Ethereum address: {addr!r}", file=sys.stderr)
        sys.exit(2)
    return Web3.to_checksum_address(addr)


def connect(rpc: str, timeout: int = RPC_TIMEOUT) -> Web3:
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": timeout}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC endpoint.", file=sys.stderr)
        sys.exit(1)
    return w3


def load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Failed to load JSON from {path}: {e}", file=sys.stderr)
        sys.exit(2)


def fmt_utc(ts: int) -> str:
    """Format UNIX timestamp (seconds) as UTC string."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


# --- selector helpers ------------------------------------------------------


def abi_function_signatures(abi: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Return mapping: signature_str -> 4-byte hex selector (no 0x).
    Only includes type == 'function'.
    """
    sig_to_selector: Dict[str, str] = {}
    for entry in abi:
        if entry.get("type") != "function":
            continue
        name = entry.get("name")
        if not name:
            continue
              inputs = entry.get("inputs") or []
        types = [inp.get("type", "unknown") for inp in inputs]
        signature = f"{name}({','.join(types)})"
        selector = keccak(text=signature)[:4].hex()
        sig_to_selector[signature] = selector
    return sig_to_selector


def parse_push4_selectors(bytecode: bytes) -> Set[str]:
    """
    Heuristically extract 4-byte selectors from runtime bytecode.

    Look for PUSH4 (0x63) opcode followed by 4 bytes. This matches typical
    Solidity dispatch patterns, but is not guaranteed for all contracts.
    """
    selectors: Set[str] = set()
    i = 0
    n = len(bytecode)
    while i < n:
        op = bytecode[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            push_len = op - 0x5F
            if op == 0x63 and i + 1 + 4 <= n:  # PUSH4
                data = bytecode[i + 1 : i + 5]
                selectors.add(data.hex())
            i += 1 + push_len
        else:
            i += 1
    return selectors


# --- core logic ------------------------------------------------------------

def selector_commitment(selectors: Set[str]) -> str:
    """Compute keccak over lexicographically sorted selectors (as bytes)."""
    ordered = sorted(selectors)
    buf = b"".join(bytes.fromhex(s) for s in ordered)
    return "0x" + keccak(buf).hex()

def scan_block(
    w3: Web3,
    address: str,
    sig_map: Dict[str, str],
    block_number: int,
) -> Dict[str, Any]:
    """
    Scan a single block for selector surface.

    Returns a dict with:
      - blockNumber, timestamp, timestampUtc
      - bytecodeLength
      - abiSelectorCount, byteSelectorCount
      - missingInBytecode, extraInBytecode
      - selectorsByte (sorted list of hex selectors)
    """
    blk = w3.eth.get_block(block_number)
    code = w3.eth.get_code(address, block_identifier=block_number)
    if not code:
        # Probably pre-deployment or selfdestruct; still scan (will yield zero selectors)
        pass

    abi_selectors = set(sig_map.values())
    byte_selectors = parse_push4_selectors(code)

    missing = sorted(abi_selectors - byte_selectors)
    extra = sorted(byte_selectors - abi_selectors)


    return {
        "selectorCommitment": selector_commitment(byte_selectors),
        "blockNumber": block_number,
        "timestamp": int(blk.timestamp),
        "timestampUtc": fmt_utc(blk.timestamp),
        "bytecodeLength": len(code),
        "abiSelectorCount": len(abi_selectors),
        "byteSelectorCount": len(byte_selectors),
        "missingInBytecode": missing,
        "extraInBytecode": extra,
        "selectorsByte": sorted(byte_selectors),
    }


def diff_selector_sets(prev: Set[str], curr: Set[str]) -> Tuple[List[str], List[str]]:
    """Return (gained, lost) selectors going from prev -> curr."""
    gained = sorted(curr - prev)
    lost = sorted(prev - curr)
    return gained, lost


# --- CLI -------------------------------------------------------------------

# Example usage:
#   python selector_history.py \
#       --address 0xYourContract \
#       --abi ./YourContract.abi.json \
#       --start 18000000 --end 18100000 \
#       --step 100 --json --csv history.csv

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan selector surface over a block range and report changes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument("--rpc", default=DEFAULT_RPC, help="EVM RPC URL (default from RPC_URL)")
    p.add_argument("--address", required=True, help="Contract address to analyze")
    p.add_argument("--label", help="Optional label/name for the contract")
    p.add_argument("--abi", required=True, help="Path to ABI JSON file")
    p.add_argument(
        "--start",
        required=True,
        help="Start block/tag (inclusive, e.g. 18000000 or latest)",
    )
    p.add_argument(
        "--end",
        required=True,
        help="End block/tag (inclusive, e.g. 19000000 or finalized)",
    )
    p.add_argument(
        "--step",
        type=int,
        default=100,
        help="Step size between sampled blocks (e.g. 1 = every block)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=RPC_TIMEOUT,
        help="HTTP timeout seconds",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON array of per-block records to stdout",
    )
    p.add_argument(
        "--csv",
        help="Optional CSV output path (one row per sampled block)",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable logs on stderr",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 2 if any selector changes are observed",
    )
    return p.parse_args()


def parse_block_arg(w3: Web3, value: str) -> int:
    low = value.lower()
    if low in ("latest", "finalized", "safe", "earliest", "pending"):
        return w3.eth.get_block(low).number
    try:
        return int(value, 0)
    except ValueError:
        print(f"❌ Invalid block identifier: {value!r}", file=sys.stderr)
        sys.exit(2)

def main() -> None:
    args = parse_args()



    addr = checksum(args.address)

    # Load ABI & selectors
    abi_json = load_json(args.abi)
    if not isinstance(abi_json, list):
        print("❌ ABI must be a JSON array.", file=sys.stderr)
        sys.exit(2)

    sig_map = abi_function_signatures(abi_json)
    if not sig_map:
        print("⚠️ ABI has no function entries; selector scan still runs but ABI comparison will be trivial.", file=sys.stderr)

    # Connect
    w3 = connect(args.rpc, timeout=args.timeout)
    chain_id = w3.eth.chain_id
    tip = w3.eth.block_number

    # Resolve block arguments
    start = parse_block_arg(w3, args.start)
    end = parse_block_arg(w3, args.end)

    if start < 0 or end < 0:
        print("❌ --start and --end must resolve to >= 0", file=sys.stderr)
        sys.exit(2)
    if args.step <= 0:
        print("❌ --step must be > 0", file=sys.stderr)
        sys.exit(2)
    if start > end:
        start, end = end, start
        if not args.quiet:
            print("🔄 Swapped start/end for ascending range.", file=sys.stderr)

    if end > tip:
        if not args.quiet:
            print(f"⚠️ end block {end} > tip {tip}; clamping to tip.", file=sys.stderr)
        end = tip

    if not args.quiet:
        print(f"🌐 Connected: chainId={chain_id}, tip={tip}", file=sys.stderr)
              label = f" ({args.label})" if args.label else ""
        print(
            f"🔍 Scanning {addr}{label} from block {start} to {end} (step={args.step})",
            file=sys.stderr,
        )

    records: List[Dict[str, Any]] = []
    prev_selectors: Optional[Set[str]] = None
    prev_block: Optional[int] = None

    # Optional CSV setup
    csv_writer = None
    csv_file = None
    if args.csv:
        import csv

        # simple "append" semantics; write header if file is empty/new
        file_exists = os.path.exists(args.csv) and os.path.getsize(args.csv) > 0
        csv_file = open(args.csv, "a", newline="", encoding="utf-8")
        fieldnames = [
            "block",
            "timestampUtc",
            "bytecodeLength",
            "abiSelectorCount",
            "byteSelectorCount",
            "missingCount",
            "extraCount",
            "changedVsPrev",
            "gainedCount",
            "lostCount",
        ]
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        if not file_exists:
            csv_writer.writeheader()

    t0 = time.monotonic()

    try:
        for blk in range(start, end + 1, args.step):
            info = scan_block(w3, addr, sig_map, blk)
            selectors_curr = set(info["selectorsByte"])

            gained: List[str] = []
            lost: List[str] = []
            changed = False
            if prev_selectors is not None:
                gained, lost = diff_selector_sets(prev_selectors, selectors_curr)
                changed = bool(gained or lost)

            # Human logs
            if not args.quiet:
                            base_line = (
                    f"📦 #{info['blockNumber']} "
                    f"ts={info['timestampUtc']} "
                    f"byteLen={info['bytecodeLength']} "
                    f"ABI={info['abiSelectorCount']} "
                    f"byte={info['byteSelectorCount']} "
                    f"missing={len(info['missingInBytecode'])} "
                    f"extra={len(info['extraInBytecode'])} "
                    f"commit={info.get('selectorCommitment', '0x')}"
                )
                if changed:
                    # show a preview of gains/losses
                    preview_gained = gained[:MAX_PREVIEW]
                    preview_lost = lost[:MAX_PREVIEW]
                    print(base_line, file=sys.stderr)
                    print(
                        f"   ⚡ selector set changed vs #{prev_block}: "
                        f"gained={len(gained)}, lost={len(lost)}",
                        file=sys.stderr,
                    )
                    if preview_gained:
                        suff = " …" if len(gained) > MAX_PREVIEW else ""
                        print(f"     + {preview_gained}{suff}", file=sys.stderr)
                    if preview_lost:
                        suff = " …" if len(lost) > MAX_PREVIEW else ""
                        print(f"     - {preview_lost}{suff}", file=sys.stderr)
                else:
                    print(base_line, file=sys.stderr)

            # Record structured data
            rec = {
                "block": info["blockNumber"],
                "timestamp": info["timestamp"],
                "timestampUtc": info["timestampUtc"],
                "bytecodeLength": info["bytecodeLength"],
                "abiSelectorCount": info["abiSelectorCount"],
                "byteSelectorCount": info["byteSelectorCount"],
                "missingCount": len(info["missingInBytecode"]),
                "extraCount": len(info["extraInBytecode"]),
                "missingInBytecode": info["missingInBytecode"],
                "extraInBytecode": info["extraInBytecode"],
                "changedVsPrev": changed,
                "gained": gained,
                "lost": lost,
                "hasMissing": len(info["missingInBytecode"]) > 0,
                "hasExtra": len(info["extraInBytecode"]) > 0,
            }
            records.append(rec)

            # CSV row
            if csv_writer is not None:
                csv_writer.writerow(
                    {
                        "block": rec["block"],
                        "timestampUtc": rec["timestampUtc"],
                        "bytecodeLength": rec["bytecodeLength"],
                        "abiSelectorCount": rec["abiSelectorCount"],
                        "byteSelectorCount": rec["byteSelectorCount"],
                        "missingCount": rec["missingCount"],
                        "extraCount": rec["extraCount"],
                        "changedVsPrev": "YES" if changed else "NO",
                        "gainedCount": len(gained),
                        "lostCount": len(lost),
                    }
                )

            prev_selectors = selectors_curr
            prev_block = info["blockNumber"]

    finally:
        if csv_file is not None:
            csv_file.close()

     elapsed = time.monotonic() - t0
    if not args.quiet:
        blocks_scanned = len(records)
        speed = blocks_scanned / elapsed if elapsed > 0 else 0.0
        print(f"\n⏱️  Elapsed: {elapsed:.2f}s for {blocks_scanned} blocks ({speed:.2f} blocks/s)", file=sys.stderr)

       if args.json:
        out = {
            "rpc": args.rpc,
            "chainId": int(chain_id),
            "address": addr,
            "abiSelectors": sig_map,
            "startBlock": start,
            "endBlock": end,
            "step": args.step,
            # Use wall-clock time (UTC) for report generation timestamp
            "generatedAtUtc": fmt_utc(int(time.time())),
            "records": records,
        }
        print(json.dumps(out, indent=2, sort_keys=True))
        return


if __name__ == "__main__":
    main()
