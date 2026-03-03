# Local Event Testing Guide

> **Package:** `github.com/dotandev/hintents/internal/simulator`
> **Applies to:** Protocol versions 20, 21, 22

---

## Overview

The `simulator` package re-plays Stellar/Soroban transactions locally using `EnvelopeXDR` and `ResultMetaXDR`. It emits the same contract events that the live network produces, but with **a different event ID structure**. Writing assertions without accounting for this difference is the most common source of flaky or incorrect tests.

This guide explains:

1. How event IDs are structured on the live network
2. How they differ in the simulator
3. How to write assertions that work correctly in both environments
4. Protocol-specific behaviour that affects event emission
5. Worked examples using the builder pattern

---

## 1. Event ID structure: live network vs. simulator

### 1.1 Live network

On the live Stellar network every event carries a globally unique, **ledger-scoped** ID:

```
<ledger_sequence>-<operation_index>-<event_index>
```

| Component | Type | Example | Meaning |
|---|---|---|---|
| `ledger_sequence` | `uint32` | `54321` | Ledger the transaction was included in |
| `operation_index` | `uint32` | `0` | 0-based index of the operation within the transaction |
| `event_index` | `uint32` | `2` | 0-based index of the event within the operation |

A full live-network ID therefore looks like `"54321-0-2"`.

### 1.2 Simulator

The simulator has no real ledger. It assigns IDs that are **local and deterministic**, starting from a fixed synthetic ledger number:

```
<synthetic_ledger>-<operation_index>-<event_index>
```

| Component | Value | Notes |
|---|---|---|
| `synthetic_ledger` | **`0`** (always) | Not a real ledger sequence |
| `operation_index` | 0-based, same as live | Reflects operation order in the envelope |
| `event_index` | 0-based, same as live | Reflects emission order within the operation |

A simulator ID for the same event is `"0-0-2"`.

**Key takeaway:** never hard-code the ledger prefix (`54321`) in test assertions. Always use the synthetic prefix `0` when asserting on the full ID string, or — better — assert only on the suffix components.

---

## 2. Asserting on event IDs correctly

### 2.1 Anti-pattern — hard-coding the ledger prefix

```go
// BAD: breaks in both directions
//   - passes on live network only if ledger happens to equal 54321
//   - always fails in simulator (ledger is 0)
assert.Equal(t, "54321-0-2", event.ID)
```

### 2.2 Recommended: assert only the operation and event index

Parse the ID and compare only the parts that are stable across environments:

```go
// helpers_test.go

import (
    "fmt"
    "strconv"
    "strings"
    "testing"

    "github.com/stretchr/testify/require"
)

// EventID holds the three components of a Soroban event ID.
type EventID struct {
    Ledger    uint32
    Operation uint32
    Event     uint32
}

// ParseEventID parses "<ledger>-<operation>-<event>".
func ParseEventID(t *testing.T, raw string) EventID {
    t.Helper()
    parts := strings.Split(raw, "-")
    require.Len(t, parts, 3, "event ID %q has unexpected format", raw)

    parse := func(s string) uint32 {
        v, err := strconv.ParseUint(s, 10, 32)
        require.NoError(t, err)
        return uint32(v)
    }
    return EventID{
        Ledger:    parse(parts[0]),
        Operation: parse(parts[1]),
        Event:     parse(parts[2]),
    }
}

// AssertEventPosition asserts the operation and event-index components,
// ignoring the ledger prefix. Safe in both simulator and live-network contexts.
func AssertEventPosition(t *testing.T, rawID string, wantOp, wantEvt uint32) {
    t.Helper()
    id := ParseEventID(t, rawID)
    require.Equal(t, wantOp,  id.Operation, "operation index mismatch in event ID %q", rawID)
    require.Equal(t, wantEvt, id.Event,      "event index mismatch in event ID %q", rawID)
}
```

Usage:

```go
func TestTransferEventPosition(t *testing.T) {
    resp := runSimulation(t, envelopeXDR, resultMetaXDR)
    require.NotEmpty(t, resp.Events)

    // Assert the first event is at operation 0, event 0 — ignores ledger prefix.
    AssertEventPosition(t, resp.Events[0].ID, 0, 0)
}
```

### 2.3 Simulator-specific assertions (full ID)

When you only target the simulator, asserting the full ID is fine because the ledger prefix is always `0`:

```go
assert.Equal(t, "0-0-0", resp.Events[0].ID)  // safe in simulator only
assert.Equal(t, "0-0-1", resp.Events[1].ID)
```

Document these tests clearly:

```go
// simulatorOnly marks a test that is only valid against the local simulator.
// Do not promote these assertions to integration tests against testnet/mainnet.
func simulatorOnly(t *testing.T) {
    t.Helper()
    if os.Getenv("TEST_ENV") == "testnet" || os.Getenv("TEST_ENV") == "mainnet" {
        t.Skip("skipping simulator-only assertion in non-local environment")
    }
}
```

---

## 3. Building simulation requests

Use `SimulationRequestBuilder` to construct requests. All examples below follow the same pattern.

### 3.1 Minimal request

```go
req, err := simulator.NewSimulationRequestBuilder().
    WithEnvelopeXDR("AAAAAgAAAACE...").
    WithResultMetaXDR("AAAAAQAAAAA...").
    Build()
if err != nil {
    t.Fatalf("build failed: %v", err)
}
```

Both `EnvelopeXDR` and `ResultMetaXDR` are required. Omitting `ResultMetaXDR` returns:

```
Validation error: result meta XDR is required
```

### 3.2 Adding ledger entries for state injection

Inject contract storage state by adding ledger entries before simulation. This is necessary when the contract reads keys that are not present in the `ResultMetaXDR`.

```go
// Single entries
req, err := simulator.NewSimulationRequestBuilder().
    WithEnvelopeXDR(envelopeXDR).
    WithResultMetaXDR(resultMetaXDR).
    WithLedgerEntry("owner_address", "GABC...").
    WithLedgerEntry("balance",       "1000000").
    Build()

// Bulk entries (order-independent; use when loading from a fixture file)
entries := map[string]string{
    "contract_key_1": "contract_value_1",
    "contract_key_2": "contract_value_2",
}
req, err := simulator.NewSimulationRequestBuilder().
    WithEnvelopeXDR(envelopeXDR).
    WithResultMetaXDR(resultMetaXDR).
    WithLedgerEntries(entries).
    Build()
```

### 3.3 Enabling the profiling flamegraph

Set `Profile: true` (via `WithProfiling()` if a method exists, or by setting the field directly) to receive an SVG flamegraph in `SimulationResponse.Flamegraph`:

```go
req := simulator.SimulationRequest{
    EnvelopeXdr:    envelopeXDR,
    ResultMetaXdr:  resultMetaXDR,
    Profile:        true,
}
resp, err := simulator.Run(req)
if err != nil {
    t.Fatal(err)
}
if resp.Flamegraph != "" {
    // write to file or assert structure
    _ = os.WriteFile("flamegraph.svg", []byte(resp.Flamegraph), 0644)
}
```

Profiling does **not** change event emission or event IDs.

### 3.4 Builder reuse

Call `Reset()` to clear all fields and reuse a builder across sub-tests:

```go
builder := simulator.NewSimulationRequestBuilder()

req1, _ := builder.
    WithEnvelopeXDR("envelope1").
    WithResultMetaXDR("result1").
    Build()

req2, _ := builder.
    Reset().
    WithEnvelopeXDR("envelope2").
    WithResultMetaXDR("result2").
    Build()
```

Without `Reset()`, fields from a previous `Build()` call are retained — this can cause silent test pollution.

---

## 4. Protocol-specific event behaviour

The simulator selects a `Protocol` version via `simulator.GetOrDefault`. Protocol version affects instruction limits, storage limits, and available opcodes, all of which can influence whether a contract emits events at all.

| Protocol | `max_instruction_limit` | Notable opcodes added | Event impact |
|---|---|---|---|
| 20 | 100 000 000 | `invoke_contract`, `create_contract` | Baseline event set |
| 21 | 150 000 000 | + `extend_contract`, enhanced metering | Additional lifecycle events possible |
| 22 | 200 000 000 | + `upgrade_contract`, optimised storage | Upgrade events; storage-change events are cheaper |

### 4.1 Default protocol version

`simulator.LatestVersion()` returns `22`. When no version is specified via `GetOrDefault(nil)`, the simulator uses protocol 22.

### 4.2 Asserting under a specific protocol

If your contract emits events only from protocol 21 onwards (e.g. `extend_contract` lifecycle events), guard accordingly:

```go
func TestExtendContractEvent(t *testing.T) {
    proto, err := simulator.Get(21)
    require.NoError(t, err, "protocol 21 must be supported")

    // Confirm opcode availability before asserting on the event
    opcodes, _ := proto.Features["supported_opcodes"].([]string)
    require.Contains(t, opcodes, "extend_contract",
        "extend_contract opcode not present in protocol 21")

    resp := runSimulationWithProtocol(t, envelopeXDR, resultMetaXDR, 21)
    require.NotEmpty(t, resp.Events, "extend_contract should emit at least one event")
}
```

### 4.3 Feature-gating assertions

Use `simulator.Feature` / `simulator.FeatureOrDefault` to make assertions conditional on protocol capabilities:

```go
instrLimit, err := simulator.Feature(22, "max_instruction_limit")
require.NoError(t, err)
require.EqualValues(t, 200_000_000, instrLimit)

// Non-fatal: falls back to default when key is absent
limit := simulator.FeatureOrDefault(20, "optimized_storage", false)
assert.False(t, limit.(bool)) // protocol 20 does not have this feature
```

---

## 5. Complete test example

The following test demonstrates all recommended patterns together.

```go
package simulator_test

import (
    "strings"
    "testing"

    "github.com/dotandev/hintents/internal/simulator"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestContractTransferEvents(t *testing.T) {
    const (
        envelopeXDR    = "AAAAAgAAAACE..."
        resultMetaXDR  = "AAAAAQAAAAA..."
    )

    req, err := simulator.NewSimulationRequestBuilder().
        WithEnvelopeXDR(envelopeXDR).
        WithResultMetaXDR(resultMetaXDR).
        WithLedgerEntry("sender_balance",   "5000000").
        WithLedgerEntry("receiver_balance", "0").
        Build()
    require.NoError(t, err)

    resp, err := simulator.Run(req)
    require.NoError(t, err)
    require.Equal(t, "success", resp.Status)
    require.Len(t, resp.Events, 2, "expected debit and credit events")

    // ── Event 0: debit ───────────────────────────────────────────────────────
    debit := resp.Events[0]
    assert.Equal(t, "transfer", debit.Type)
    // Use position-only assertion — safe in simulator and on live network
    AssertEventPosition(t, debit.ID, 0, 0)

    // ── Event 1: credit ──────────────────────────────────────────────────────
    credit := resp.Events[1]
    assert.Equal(t, "transfer", credit.Type)
    AssertEventPosition(t, credit.ID, 0, 1)

    // ── Simulator-only full-ID check (guarded) ───────────────────────────────
    if !strings.HasPrefix(debit.ID, "0-") {
        t.Logf("running against live network; skipping simulator-specific ID assertions")
    } else {
        assert.Equal(t, "0-0-0", debit.ID)
        assert.Equal(t, "0-0-1", credit.ID)
    }
}
```

---

## 6. Common mistakes and fixes

| Mistake | Symptom | Fix |
|---|---|---|
| Asserting full ID including ledger prefix against testnet | Test always fails on testnet | Use `AssertEventPosition` or strip the ledger prefix |
| Not calling `Reset()` between builder reuses | Second request carries ledger entries from first | Always call `Reset()` before rebuilding |
| Omitting `ResultMetaXDR` | `Build()` returns `"result meta XDR is required"` | Always provide both XDR fields |
| Asserting event count without considering protocol version | Flaky count assertions across protocol upgrades | Guard with `simulator.Feature` checks |
| Using `Profile: true` and asserting event IDs by position on profiled output | Profiling adds no extra events, so this is safe, but the flamegraph field is ignored if empty | Check `resp.Flamegraph != ""` before writing |

---

## 7. Quick reference

```go
// Supported protocol versions
versions := simulator.Supported()       // []uint32{20, 21, 22}
latest   := simulator.LatestVersion()   // 22

// Validate a version
err := simulator.Validate(23)           // "unsupported protocol version: 23"

// Get protocol details
proto, err := simulator.Get(21)
proto.Name       // "Soroban Protocol 21"
proto.Features   // map[string]interface{}{...}

// Feature lookup
val, err := simulator.Feature(22, "max_contract_size")    // 131072, nil
def      := simulator.FeatureOrDefault(20, "optimized_storage", false) // false

// Merge custom features over protocol defaults
merged := simulator.MergeFeatures(22, map[string]interface{}{
    "custom_flag": true,
})

// Build a request
req, err := simulator.NewSimulationRequestBuilder().
    WithEnvelopeXDR("...").
    WithResultMetaXDR("...").
    WithLedgerEntry("k", "v").
    Build()

// Event ID format
//   live network: "<ledger_seq>-<op_idx>-<evt_idx>"  e.g. "54321-0-2"
//   simulator:    "0-<op_idx>-<evt_idx>"              e.g. "0-0-2"
```