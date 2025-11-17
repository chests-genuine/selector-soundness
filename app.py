# app.py
"""Application entrypoint and lightweight utilities.

Importing this module has no side effects; all behavior is opt-in.
"""
import os
import sys
import json
import time  # add this with your imports if not already there
import argparse
from typing import List, Set, Dict, Any, Tuple
from web3 import Web3
from eth_abi.abi import abi_to_signature
from eth_utils import keccak, to_bytes

DEFAULT_RPC = os.environ.get("RPC_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY")

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main() -> None:
    start = time.time()   # <--- add here

    # (existing code...)

    ok = (len(missing_in_bytecode) == 0 and len(extra_in_bytecode) == 0 and (not args.allowed or len(allowed_violations) == 0))
    
    # Print duration summary
    elapsed = time.time() - start
    print(f"⏱️ Completed in {elapsed:.2f} seconds")

    sys.exit(0 if ok else 2)



def get_runtime_code(w3: Web3, address: str, block: Any) -> bytes:
    addr = Web3.to_checksum_address(address)
    return w3.eth.get_code(addr, block_identifier=block)

def abi_function_signatures(abi: List[Dict[str, Any]]) -> Dict[str, str]:
    sig_to_selector: Dict[str, str] = {}
    for entry in abi:
        if entry.get("type") != "function":
            continue
        name = entry.get("name")
        if not name:
            continue
        inputs = entry.get("inputs", [])
        # Build canonical types list
        types = [inp["type"] for inp in inputs]
        signature = f"{name}({','.join(types)})"
        selector = keccak(text=signature)[:4].hex()
        sig_to_selector[signature] = selector
    return sig_to_selector

def parse_push4_selectors(bytecode: bytes) -> Set[str]:
    """
    Heuristically extract 4-byte selectors from runtime bytecode:
    Look for PUSH4 (0x63) opcode followed by 4 bytes.
    """
    selectors: Set[str] = set()
    i = 0
    n = len(bytecode)
    while i < n:
        op = bytecode[i]
        if 0x60 <= op <= 0x7f:  # PUSH1..PUSH32
            push_len = op - 0x5f
            if op == 0x63 and i + 1 + 4 <= n:
                data = bytecode[i + 1 : i + 5]
                selectors.add(data.hex())
            i += 1 + push_len
        else:
            i += 1
    return selectors

def load_allowed(path: str) -> Set[str]:
    """
    Allowed file may be:
    - A JSON array of hex selectors ["a9059cbb", ...]
    - A JSON object { "name(sig)": "a9059cbb", ... }
    """
    data = load_json(path)
    selectors: Set[str] = set()
    if isinstance(data, list):
        for s in data:
            if isinstance(s, str):
                selectors.add(s.lower().replace("0x", ""))
    elif isinstance(data, dict):
        for s in data.values():
            if isinstance(s, str):
                selectors.add(s.lower().replace("0x", ""))
    else:
        raise ValueError("Unsupported allowed format. Use array or object of hex selectors.")
    return selectors

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="selector-soundness — compare ABI function selectors to selectors detected in runtime bytecode (useful for Aztec/Zama L1 contracts and general Web3 soundness checks)."
    )
    p.add_argument("--rpc", default=DEFAULT_RPC, help="EVM RPC URL (default from RPC_URL)")
    p.add_argument("--address", required=True, help="Contract address to analyze")
    p.add_argument("--abi", required=True, help="Path to ABI JSON file")
    p.add_argument("--allowed", help="Optional JSON of allowed selectors (array or object)")
    p.add_argument("--block", default="finalized", help="Block tag or number (default: finalized)")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    w3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": args.timeout}))
    if not w3.is_connected():
        print("❌ RPC connection failed. Check --rpc or RPC_URL.")
        sys.exit(1)
def network_name(chain_id: int) -> str:
    networks = {
        1: "Ethereum Mainnet",
        11155111: "Sepolia Testnet",
        137: "Polygon",
        10: "Optimism",
        42161: "Arbitrum One",
    }
    return networks.get(chain_id, f"Unknown (chain ID {chain_id})")

print(f"🌐 Connected to {network_name(w3.eth.chain_id)} (chainId {w3.eth.chain_id})")
    try:
        abi = load_json(args.abi)
        if not isinstance(abi, list):
            raise ValueError("ABI must be a JSON array.")
    except Exception as e:
        print(f"❌ Failed to load ABI: {e}")
        sys.exit(1)

    try:
        code = get_runtime_code(w3, args.address, args.block)
    except Exception as e:
        print(f"❌ Failed to fetch bytecode: {e}")
        sys.exit(1)

    if len(code) == 0:
        print("❌ No runtime bytecode at the provided address (EOA or selfdestructed).")
        sys.exit(2)

    sig_map = abi_function_signatures(abi)
    abi_selectors = set(sig_map.values())
    bytecode_selectors = parse_push4_selectors(code)

    missing_in_bytecode = sorted(abi_selectors - bytecode_selectors)
    extra_in_bytecode = sorted(bytecode_selectors - abi_selectors)
    print(f"🔹 ABI selectors found: {len(abi_selectors)}")
print(f"🔸 Bytecode selectors found: {len(bytecode_selectors)}")


    allowed_set: Set[str] = set()
    allowed_violations: Set[str] = set()
    if args.allowed:
        try:
            allowed_set = load_allowed(args.allowed)
            # any selector present in bytecode but not allowed is a violation
            allowed_violations = set(s for s in bytecode_selectors if s not in allowed_set)
        except Exception as e:
            print(f"❌ Failed to load allowed selectors: {e}")
            sys.exit(1)

    # Human-readable output
    print("🔧 selector-soundness")
    print(f"🔗 RPC: {args.rpc}")
    try:
        print(f"🧭 Chain ID: {w3.eth.chain_id}")
    except Exception:
        pass
    print(f"🏷️ Address: {Web3.to_checksum_address(args.address)}")
    print(f"🧱 Block: {args.block}")
    print(f"📦 Bytecode bytes: {len(code)}")
    print(f"📚 ABI functions: {len(abi_selectors)}")
    print(f"🧩 Bytecode selectors detected: {len(bytecode_selectors)}")

    if missing_in_bytecode:
        print(f"⚠️ Missing selectors in bytecode (present in ABI, not detected): {len(missing_in_bytecode)}")
        print("   " + ", ".join(missing_in_bytecode[:20]) + (" ..." if len(missing_in_bytecode) > 20 else ""))
    else:
        print("✅ All ABI selectors appear present in bytecode (heuristic).")

    if extra_in_bytecode:
        print(f"⚠️ Extra selectors in bytecode (not in ABI): {len(extra_in_bytecode)}")
        print("   " + ", ".join(extra_in_bytecode[:20]) + (" ..." if len(extra_in_bytecode) > 20 else ""))
    else:
        print("✅ No extra selectors beyond ABI detected (heuristic).")

    if args.allowed:
        if allowed_violations:
            print(f"🚫 Disallowed selectors detected: {len(allowed_violations)}")
            print("   " + ", ".join(sorted(list(allowed_violations))[:20]) + (" ..." if len(allowed_violations) > 20 else ""))
        else:
            print("🛡️ Allowed-policy check passed: no disallowed selectors detected.")

    # JSON output
    if args.json:
        out = {
            "rpc": args.rpc,
            "chain_id": None,
            "address": Web3.to_checksum_address(args.address),
            "block": args.block,
            "bytecode_len": len(code),
            "abi_selectors_count": len(abi_selectors),
            "bytecode_selectors_count": len(bytecode_selectors),
            "missing_in_bytecode": missing_in_bytecode,
            "extra_in_bytecode": extra_in_bytecode,
            "allowed_violations": sorted(list(allowed_violations)) if args.allowed else None,
            "sample": {
                "abi_selectors_sample": sorted(list(abi_selectors))[:20],
                "bytecode_selectors_sample": sorted(list(bytecode_selectors))[:20]
            }
        }
        # best-effort chain id
        try:
            out["chain_id"] = w3.eth.chain_id
        except Exception:
            pass
        print(json.dumps(out, ensure_ascii=False, indent=2))

    # Exit code: 0 if everything looks consistent, 2 otherwise
    ok = (len(missing_in_bytecode) == 0 and len(extra_in_bytecode) == 0 and (not args.allowed or len(allowed_violations) == 0))
    sys.exit(0 if ok else 2)

if __name__ == "__main__":
    main()
