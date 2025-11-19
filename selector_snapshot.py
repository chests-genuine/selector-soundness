    """
    Heuristically extract 4-byte selectors from runtime bytecode.

    Scan for PUSH4 (0x63) opcodes followed by 4 bytes, which matches
    the common Solidity dispatcher pattern:
        PUSH4 <selector> ; EQ ; ...

    This may miss selectors in non-standard dispatch logic (Yul, custom proxies).
    """
from __future__ import annotations

import os
import sys
import json
import time
import argparse
from typing import Any, Dict, List, Set
SelectorHex = str            # 8 hex chars, no 0x
SelectorSet = Set[SelectorHex]
SignatureMap = Dict[str, SelectorHex]  # "foo(uint256)" -> selector

from web3 import Web3
from eth_utils import keccak

DEFAULT_RPC = os.getenv("RPC_URL", "https://mainnet.infura.io/v3/your_api_key")
RPC_TIMEOUT = float(os.getenv("RPC_TIMEOUT", "30"))
__version__ = "0.1.0"

__all__ = [
    "checksum",
    "connect",
    "load_json",
    "fmt_utc",
    "as_block_id",
    "abi_selectors",
    "parse_push4_selectors",
    "selector_commitment",
]

# --- helpers ---------------------------------------------------------------


def checksum(addr: str) -> str:
    if not isinstance(addr, str) or not Web3.is_address(addr):
             print(f"❌ Invalid Ethereum address: {addr!r}", file=sys.stderr)
        sys.exit(2)
    return Web3.to_checksum_address(addr)


def connect(rpc: str, timeout: float = RPC_TIMEOUT) -> Web3:
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
    """
    Format a UNIX timestamp (seconds since epoch) as a UTC time string.
    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))

def _is_block_tag(value: str) -> bool:
    return value.lower() in ("latest", "finalized", "safe", "earliest", "pending")

def as_block_id(s: str | None) -> str | int:
    """
    Accept either an integer-like string (decimal / 0xHEX) or a tag:
    latest | finalized | safe | earliest | pending
    """
    if s is None:
        return "latest"
    low = s.lower()
    if _is_block_tag(low):
        return low
    try:
        return int(s, 0)
    except Exception:
        print(f"❌ Invalid block identifier: {s!r}", file=sys.stderr)
        sys.exit(2)


# --- selector logic --------------------------------------------------------


def abi_selectors(abi_json: List[Dict[str, Any]]) -> SignatureMap:
    """
    Return mapping: signature_str -> 4-byte hex selector (no 0x).
    Only includes entries with type == 'function'.
    """
    sig_to_sel: Dict[str, str] = {}
    for entry in abi_json:
        if entry.get("type") != "function":
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        inputs = entry.get("inputs") or []
        types = [inp.get("type", "unknown") for inp in inputs]
        sig = f"{name}({','.join(types)})"
        sel = keccak(text=sig)[:4].hex()
        sig_to_sel[sig] = sel
    return sig_to_sel


def parse_push4_selectors(bytecode: bytes) -> SelectorSet:
    """
    Heuristically extract 4-byte selectors from runtime bytecode.

    Scan for PUSH4 (0x63) opcodes followed by 4 bytes, which matches
    the common Solidity dispatcher pattern:
        PUSH4 <selector> ; EQ ; ...
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


def selector_commitment(selectors: SelectorSet) -> str:
    """Compute keccak over lexicographically sorted selectors (as bytes)."""
    ordered = sorted(selectors)
    # Hash of empty set is keccak(b"") if there are no selectors.
    buf = b"".join(bytes.fromhex(s) for s in ordered)
    return "0x" + keccak(buf).hex()


# --- CLI -------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
     ap = argparse.ArgumentParser(
        description="Snapshot a contract's selector surface at a single block.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-r", "--rpc", default=DEFAULT_RPC, help="RPC URL (default from RPC_URL)")
       ap.add_argument("-a", "--address", required=True, help="Contract address (0x...)")
    ap.add_argument(
        "--label",
        help="Optional label/name for the contract (for logs only)",
    )
    ap.add_argument("--abi", required=True, help="Path to ABI JSON file")
     ap.add_argument(
        "--block",
        help="Block number or tag (latest|finalized|safe|earliest|pending, default: latest)",
    )

    ap.add_argument(
        "--timeout",
        type=float,
        default=RPC_TIMEOUT,
        help="RPC HTTP timeout in seconds",
    )
      ap.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON snapshot to stdout (in addition to logs)",
    )
       ap.add_argument(
        "--raw-json",
        action="store_true",
        help="Emit compact JSON (no pretty-printing)",
    )

    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable logs on stderr",
    )
        ap.add_argument(
        "--chain-id",
        type=int,
        help="Override chain ID reported by RPC",
    )

    return ap.parse_args()


# --- main ------------------------------------------------------------------


def main() -> None:
    args = parse_args()

    addr = checksum(args.address)
    abi_json = load_json(args.abi)
      if not isinstance(abi_json, list):
        # Common case: Truffle/Hardhat artifact with {"abi": [...]} wrapper.
        if isinstance(abi_json, dict) and isinstance(abi_json.get("abi"), list):
            abi_json = abi_json["abi"]
        else:
            print("❌ ABI JSON must be an array of entries or an artifact with an 'abi' array.", file=sys.stderr)
            sys.exit(2)

       abi_map = abi_selectors(abi_json)
    if not abi_map:
        print("⚠️ ABI has no function entries; ABI comparison will be trivial.", file=sys.stderr)

    # Detect selector collisions within the ABI
    sel_to_sigs: Dict[str, List[str]] = {}
    for sig, sel in abi_map.items():
        sel_to_sigs.setdefault(sel, []).append(sig)
    collisions = {sel: sigs for sel, sigs in sel_to_sigs.items() if len(sigs) > 1}
    if collisions:
        print(f"⚠️ ABI has selector collisions (same 4-byte id for multiple signatures): {collisions}", file=sys.stderr)


    w3 = connect(args.rpc, timeout=args.timeout)
    chain_id = w3.eth.chain_id
    if args.chain_id is not None:
        print(f"ℹ️  Overriding chainId {chain_id} with {args.chain_id}", file=sys.stderr)
        chain_id = args.chain_id
    block_id = as_block_id(args.block)

    block_id = as_block_id(args.block)

    # Resolve block number
    if isinstance(block_id, int):
        blk = w3.eth.get_block(block_id)
    else:
        blk = w3.eth.get_block(block_id)
        block_id = int(blk.number)
    resolved_block = int(block_id)

     code = w3.eth.get_code(addr, block_identifier=block_id)
    if not code:
        print("⚠️ Target has no contract code at this block — likely an EOA or pre-deploy.", file=sys.stderr)
    byte_selectors = parse_push4_selectors(code)
    abi_selectors_set = set(abi_map.values())

    missing_in_bytecode = sorted(abi_selectors_set - byte_selectors)
    extra_in_bytecode = sorted(byte_selectors - abi_selectors_set)
    common = sorted(abi_selectors_set & byte_selectors)

    abi_commit = selector_commitment(abi_selectors_set)
    byte_commit = selector_commitment(byte_selectors)

    snapshot = {
        "hasBytecode": bool(code),
        "rpc": args.rpc,
        "chainId": int(chain_id),
        "address": addr,
        "blockNumber": int(block_id),
        "timestamp": int(blk.timestamp),
        "timestampUtc": fmt_utc(blk.timestamp),
        "bytecodeLength": len(code),
        "abiSelectorCount": len(abi_selectors_set),
        "byteSelectorCount": len(byte_selectors),
        "abiCommitment": abi_commit,
        "byteCommitment": byte_commit,
        "missingInBytecode": missing_in_bytecode,
        "extraInBytecode": extra_in_bytecode,
        "intersection": common,
        "generatedAtUtc": fmt_utc(int(time.time())),
    }

    if not args.quiet:
        print(f"🌐 chainId={chain_id}  addr={addr}", file=sys.stderr)
             print(
            f"📦 block={snapshot['blockNumber']}  ts={snapshot['timestampUtc']}  "
            f"byteLen={snapshot['bytecodeLength']}",
            file=sys.stderr,
        
        )
         # snapshot['blockNumber'] == resolved_block
        print(
            f"🔑 ABI selectors={snapshot['abiSelectorCount']}  "
            f"byte selectors={snapshot['byteSelectorCount']}",
            file=sys.stderr,
        )
        print(f"   abiCommit = {abi_commit}", file=sys.stderr)
        print(f"   byteCommit= {byte_commit}", file=sys.stderr)
        print(
            f"   missing={len(missing_in_bytecode)}  extra={len(extra_in_bytecode)}  "
            f"common={len(common)}",
            file=sys.stderr,
        )

        if missing_in_bytecode:
            print(f"   ⚠️  ABI selectors missing in bytecode (first 10): {missing_in_bytecode[:10]}", file=sys.stderr)
        if extra_in_bytecode:
            print(f"   ⚠️  Selectors in bytecode but not ABI (first 10): {extra_in_bytecode[:10]}", file=sys.stderr)
    if args.json:
        if args.raw_json:
            print(json.dumps(snapshot, separators=(",", ":"), sort_keys=True))
        else:
            print(json.dumps(snapshot, indent=2, sort_keys=True))



if __name__ == "__main__":
    main()
