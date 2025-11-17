"""Diff a contract's function selectors between two blocks.

- Computes canonical ABI-based selectors.
- Scans runtime bytecode for PUSH4-derived selectors.
- Compares selector surface at two block heights and emits a JSON / human summary.
"""

import os
import sys
import json
import time
import argparse
from typing import Dict, List, Set, Tuple, Any, Optional

from web3 import Web3
from eth_utils import keccak

DEFAULT_RPC = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")
MAX_PREVIEW = 20

# --- helpers ---------------------------------------------------------------

def checksum(addr: str) -> str:
    if not isinstance(addr, str) or not Web3.is_address(addr):
        print("❌ Invalid Ethereum address.", file=sys.stderr)
        sys.exit(2)
    return Web3.to_checksum_address(addr)

def _confusion(
    y_true: Iterable[str], y_pred: Iterable[str]
) -> Tuple[List[str], Dict[Tuple[str, str], int]]:

def connect(rpc: str) -> Web3:
       w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": RPC_TIMEOUT}))
    if not w3.is_connected():
        print("❌ Failed to connect to RPC endpoint.", file=sys.stderr)
        sys.exit(1)
    return w3


def load_abi(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"❌ Failed to load ABI from {path}: {e}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, list):
        print("❌ ABI JSON must be an array of entries.", file=sys.stderr)
        sys.exit(2)
    return data

def _read_rows(
    path: pathlib.Path,
    *,
    id_col: str,
    truth_col: str,
    pred_col: str,
    selector_col: str | None,
) -> Tuple[List[str], List[str], List[str], List[str] | None]:
def abi_selectors(abi_json: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Return mapping: signature_str -> 4-byte hex selector (no 0x).
    Only includes type == 'function'.
    """
    result: Dict[str, str] = {}
    for entry in abi_json:
        if entry.get("type") != "function":
            continue
        name = entry.get("name")
        inputs = entry.get("inputs", [])
        if not isinstance(name, str):
            continue
        types = [inp.get("type", "unknown") for inp in inputs]
        sig = f"{name}({','.join(types)})"
        sel = keccak(text=sig)[:4].hex()
        result[sig] = sel
    return result


def scan_selectors_from_bytecode(bytecode_hex: str) -> Set[str]:
    """
    Heuristically scan EVM runtime bytecode for PUSH4 opcodes and collect
    the 4-byte immediates as candidate function selectors (hex without 0x).
    """
    code = bytecode_hex[2:] if bytecode_hex.startswith("0x") else bytecode_hex
    b = bytes.fromhex(code)
    out: Set[str] = set()
    i = 0
    while i < len(b):
        op = b[i]
        if op == 0x63 and i + 4 < len(b):  # PUSH4
            sel_bytes = b[i + 1:i + 5]
            out.add(sel_bytes.hex())
            i += 5
        else:
            # PUSH1..PUSH32 have opcodes 0x60..0x7f
            if 0x60 <= op <= 0x7f:
                push_len = op - 0x5f
                i += 1 + push_len
            else:
                i += 1
    return out


def selector_set_commitment(selectors: Set[str]) -> str:
    """
    Compute a simple keccak-based commitment to a set of selectors.
    Sort the selectors lexicographically and hash the concatenated bytes.
    Returns a 0x-prefixed hex string.
    """
    ordered = sorted(selectors)
    buf = b"".join(bytes.fromhex(s) for s in ordered)
    return "0x" + keccak(buf).hex()


def as_block_id(s: str) -> Any:
    """
    Accept either an integer-like string (decimal / 0xHEX) or a tag:
    latest | finalized | safe | earliest | pending
    """
    low = s.lower()
    if low in ("latest", "finalized", "safe", "earliest", "pending"):
        return low
    try:
        return int(s, 0)
    except Exception:
        print(f"❌ Invalid block identifier: {s!r}", file=sys.stderr)
        sys.exit(2)


def resolve_block_number(w3: Web3, tag_or_num: Any) -> int:
    """
    For tags, fetch block and return its number. For ints, return as-is.
    """
    if isinstance(tag_or_num, int):
        return tag_or_num
    blk = w3.eth.get_block(tag_or_num)
    return int(blk.number)


def fmt_utc(ts: int) -> str:
    """Format a UNIX timestamp (seconds) as a UTC timestamp string."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))

    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


# --- core logic -----------------------------------------------------------

def analyze_at_block(
    w3: Web3,
    address: str,
    abi_sels: Dict[str, str],
    block_id: Any,
) -> Dict[str, Any]:
    """
    Fetch runtime bytecode at block_id, scan for selectors, and compare
    against ABI selectors.
    """
    block_num = resolve_block_number(w3, block_id)
    blk = w3.eth.get_block(block_num)
    code = w3.eth.get_code(address, block_identifier=block_num)
    byte_sel = scan_selectors_from_bytecode(code.hex())

    abi_sel_set = set(abi_sels.values())

    abi_only = abi_sel_set - byte_sel
    byte_only = byte_sel - abi_sel_set
    common = abi_sel_set & byte_sel

    return {
        "blockNumber": block_num,
        "blockTag": block_id if not isinstance(block_id, int) else None,
        "timestamp": int(blk.timestamp),
        "timestampUtc": fmt_utc(blk.timestamp),
        "bytecodeLength": len(code),
        "abiSelectorCount": len(abi_sel_set),
        "byteSelectorCount": len(byte_sel),
        "abiOnly": sorted(abi_only),
        "byteOnly": sorted(byte_only),
        "intersection": sorted(common),
        "abiCommitment": selector_set_commitment(abi_sel_set),
        "byteCommitment": selector_set_commitment(byte_sel),
        "selectorsByte": sorted(byte_sel),
    }


def diff_blocks(
    a: Dict[str, Any],
    b: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare selector sets between two block snapshots.
    a / b are results from analyze_at_block.
    """
    set_a = set(a["selectorsByte"])
    set_b = set(b["selectorsByte"])

    gained = sorted(set_b - set_a)
    lost = sorted(set_a - set_b)
    unchanged = sorted(set_a & set_b)

    return {
        "gained": gained,
        "lost": lost,
        "unchanged": unchanged,
    }


# --- CLI ------------------------------------------------------------------
# Example:
#   python selector_diff.py 0xYourContract your_abi.json \
#       --block-a 18000000 --block-b 19000000 --json --strict

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Diff a contract's function selectors between two blocks.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
        ap.add_argument(
        "--chain-id",
        type=int,
        help="Override chain ID reported by RPC",
    )
    ap.add_argument("address", help="Contract address (0x...)")
    ap.add_argument("abi", help="Path to ABI JSON file")
    ap.add_argument(
        "--block-a",
        required=True,
        help="First block number or tag (e.g. 18000000, latest, finalized)",
    )
    ap.add_argument(
        "--block-b",
        required=True,
        help="Second block number or tag (e.g. 19000000, safe)",
    )
    ap.add_argument(
        "--rpc",
        default=DEFAULT_RPC,
        help="RPC URL (default from RPC_URL env)",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Also print machine-readable JSON summary to stdout",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 2 if gained/lost selectors are detected",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=RPC_TIMEOUT,
        help="RPC HTTP timeout in seconds",
    )
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    addr = checksum(args.address)
        # Quick check at latest to see if code exists at all
    tmp_w3 = connect(args.rpc)
    if not tmp_w3.eth.get_code(addr):
        print("⚠️  Target has no contract code at latest block — likely an EOA.", file=sys.stderr)

    abi_json = load_abi(args.abi)
    abi_sels = abi_selectors(abi_json)
    if not abi_sels:
        print("⚠️ ABI has no function entries; nothing to compare.", file=sys.stderr)

    w3 = connect(args.rpc)
     chain_id = w3.eth.chain_id
    if args.chain_id is not None:
        print(f"ℹ️  Overriding chainId {chain_id} with {args.chain_id}", file=sys.stderr)
        chain_id = args.chain_id
    tip = w3.eth.block_number

    tip = w3.eth.block_number
    print(f"🌐 Connected to chainId {chain_id}, tip {tip}", file=sys.stderr)
    print(f"🔗 Address: {addr}", file=sys.stderr)

    block_a_id = as_block_id(args.block_a)
    block_b_id = as_block_id(args.block_b)

    t0 = time.monotonic()
    snap_a = analyze_at_block(w3, addr, abi_sels, block_a_id)
    snap_b = analyze_at_block(w3, addr, abi_sels, block_b_id)
    delta = diff_blocks(snap_a, snap_b)
    elapsed = time.monotonic() - t0

       # Human-readable summary
    print("\n📦 ABI", file=sys.stderr)
    print(f"  Functions: {len(abi_sels)}", file=sys.stderr)

    print("\n🔢 Snapshot A")
    print(
        f"  Block: {snap_a['blockNumber']}  ts={snap_a['timestampUtc']}  bytecodeLen={snap_a['bytecodeLength']}",
        file=sys.stderr,
    )
    print(
        f"  ABI selectors:   {snap_a['abiSelectorCount']}  commit={snap_a['abiCommitment']}",
        file=sys.stderr,
    )
    print(
        f"  Byte selectors:  {snap_a['byteSelectorCount']}  commit={snap_a['byteCommitment']}",
        file=sys.stderr,
    )
    print(
        f"  ABI-only: {len(snap_a['abiOnly'])}  Byte-only: {len(snap_a['byteOnly'])}",
        file=sys.stderr,
    )

    print("\n🔢 Snapshot B")
    print(
        f"  Block: {snap_b['blockNumber']}  ts={snap_b['timestampUtc']}  bytecodeLen={snap_b['bytecodeLength']}",
        file=sys.stderr,
    )
    print(
        f"  ABI selectors:   {snap_b['abiSelectorCount']}  commit={snap_b['abiCommitment']}",
        file=sys.stderr,
    )
    print(
        f"  Byte selectors:  {snap_b['byteSelectorCount']}  commit={snap_b['byteCommitment']}",
        file=sys.stderr,
    )
    print(
        f"  ABI-only: {len(snap_b['abiOnly'])}  Byte-only: {len(snap_b['byteOnly'])}",
        file=sys.stderr,
    )

    print("\n🔍 Selector diff (bytecode-level)", file=sys.stderr)
    print(f"  Gained selectors:   {len(delta['gained'])}", file=sys.stderr)
        if delta["gained"]:
        preview = delta["gained"][:MAX_PREVIEW]
        suffix = " …" if len(delta["gained"]) > MAX_PREVIEW else ""
        print(f"    {preview}{suffix}", file=sys.stderr)
    print(f"  Lost selectors:     {len(delta['lost'])}", file=sys.stderr)
    if delta["lost"]:
        print(f"    {delta['lost'][:20]}{' …' if len(delta['lost']) > 20 else ''}", file=sys.stderr)
    print(f"  Unchanged selectors:{len(delta['unchanged'])}", file=sys.stderr)

    print(f"\n⏱️  Elapsed: {elapsed:.2f}s", file=sys.stderr)

    # JSON summary
    if args.json:
        summary = {
            "network": int(chain_id),
            "address": addr,
            "blockA": snap_a,
            "blockB": snap_b,
            "diff": delta,
            "generatedAtUtc": fmt_utc(int(time.time())),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))

    # Strict exit code if surface changed
    if args.strict and (delta["gained"] or delta["lost"]):
        sys.exit(2)


if __name__ == "__main__":
    main()

