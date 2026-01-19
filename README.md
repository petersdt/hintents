# Erst By Hintents

**Erst** is a specialized developer tool for the Stellar network, designed to solve the "black box" debugging experience on Soroban.

> **Status**: Active Development (Pre-Alpha)
> **Focus**: Soroban Error Decoding & Transaction Replay

## Scope & Objective

The primary goal of `erst` is to clarify **why** a Stellar smart contract transaction failed.

Currently, when a Soroban transaction fails on mainnet, developers receive a generic XDR error code. `erst` aims to bridge the gap between this opaque network error and the developer's source code.

**Core Features (Planned):**
1.  **Transaction Replay**: Fetch a failed transaction's envelope and ledger state from an RPC provider.
2.  **Local Simulation**: Re-execute the transaction logically in a local environment.
3.  **Trace decoding**: Map execution steps and failures back to readable instructions or Rust source lines.

## Technical Analysis

### The Challenge
Stellar's `soroban-env-host` executes WASM. When it traps (crashes), the specific reason is often sanitized or lost in the XDR result to keep the ledger size small.

### The Solution Architecture
`erst` will likely operate by:
1.  **Fetching Data**: Using the Stellar RPC to get the `TransactionEnvelope` and `LedgerFootprint` (read/write set) for the block where the tx failed.
2.  **Simulation Environment**: integrating with the `soroban-sdk` (likely via Rust FFI or a mock environment) to load the contract WASM.
3.  **Execution**: Feeding the inputs into the VM and capturing `diagnostic_events`.

## How to Contribute

We are building this open-source to help the entire Stellar community.

### Prerequisites
-   Go 1.21+
-   Rust (for Soroban FFI bindings)
-   Stellar CLI (for comparing results)

### Getting Started
1.  Clone the repo:
    ```bash
    git clone https://github.com/dotandev/hintent.git
    cd erst
    ```
2.  Run tests:
    ```bash
    go test ./...
    ```

### Development Roadmap
See [docs/proposal.md](docs/proposal.md) for the detailed proposal.

1.  [ ] **Phase 1**: Research RPC endpoints for fetching historical ledger keys.
2.  [ ] **Phase 2**: Build a basic "Replay Harness" that can execute a loaded WASM file.
3.  [ ] **Phase 3**: Connect the harness to live mainnet data.

---
*Erst is an open-source initiative. Contributions, PRs, and Issues are welcome.*
