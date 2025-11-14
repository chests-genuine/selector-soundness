# selector-soundness

Overview
A tiny CLI to assess smart contract soundness by comparing function selectors defined in an ABI with selectors heuristically detected in the deployed runtime bytecode. This helps catch ABI drift, stealthy upgrades, or misconfigurations in L1 contracts frequently used by zk ecosystems like Aztec and FHE/zk integrations like Zama. It also supports an optional allowed-list policy to flag unexpected selectors in production deployments.

How it works
1) Loads the ABI and computes canonical function selectors (keccak of name(types), first 4 bytes).
2) Downloads the contract’s runtime bytecode at a chosen block.
3) Scans the bytecode for PUSH4 opcodes to collect candidate selectors (a common Solidity dispatch pattern).
4) Compares ABI selectors vs bytecode selectors to find:
   - missing selectors (in ABI but not seen in bytecode)
   - extra selectors (in bytecode but not in ABI)
5) Optionally checks that all bytecode selectors are included in a provided allowed-list.

## Installation

1. Install **Python 3.9+**.
2. Install dependencies:

   ```bash
   pip install web3 eth-abi eth-utils
3. Provide an EVM RPC endpoint, either via env:
export RPC_URL="https://your-node.example"

##Usage
Minimal run (informational soundness scan):
   python app.py --address 0xYourContract --abi ./YourContract.abi.json

Fixed block for reproducibility (finality-aware):
   python app.py --address 0xYourContract --abi ./YourContract.abi.json --block finalized
   python app.py --address 0xYourContract --abi ./YourContract.abi.json --block 21000000

With a selectors allowlist policy:
   python app.py --address 0xYourContract --abi ./YourContract.abi.json --allowed ./allowed.json

Machine-readable output (CI integration):
   python app.py --address 0xYourContract --abi ./YourContract.abi.json --json --block safe

Allowed file format
allowed.json can be:
- An array of hex selectors:
  ["a9059cbb", "095ea7b3", "23b872dd"]
- Or an object mapping any names to selectors:
  { "transfer(address,uint256)": "a9059cbb", "approve(address,uint256)": "095ea7b3" }

Expected output
You’ll see:
- RPC, chain id, address, block, bytecode length
- Counts of ABI selectors and selectors detected in bytecode
- Lists of missing and extra selectors (first 20 items for readability)
- Allowed-policy result when provided
Exit code is 0 if no inconsistencies are found, otherwise 2 (useful for CI pipelines).

Notes
- Selector extraction via PUSH4 is heuristic but effective for standard Solidity dispatch. Optimized or Yul-heavy contracts may require deeper analysis.
- For proxy setups, run this tool against the implementation contract address.
- Works across mainnet, L2s, and private devnets. Just point the RPC accordingly.
- This tool does not validate storage layout, event topics, or source verification; it focuses solely on the function selector surface for quick soundness checks.
- Relevant to security posture in Aztec-bridged L1s and Zama-integrated deployments where minimizing the callable surface is critical.
