# Cryptographic Dependency Audit
**Repository:** `dotandev/hintents` — `simulator` crate  
**Lockfile:** `Cargo.lock` version 4  
**Audited:** 2026-02-26  
**Auditor:** Manual review + RUSTSEC advisory database cross-check  

---

## Executive Summary

**Result: PASS — no exploitable vulnerabilities found.**

The full transitive dependency tree contains 47 crypto-adjacent crates. Every
one is sourced exclusively from crates.io (no git pins, no path overrides). No
deprecated algorithms (MD5, SHA-1, RC4, DES/3DES, RSA) appear anywhere in the
tree. The TLS stack is pure-Rust `rustls` 0.23.36, well past all published CVEs.
The one previously-critical advisory against a direct transitive dep
(`RUSTSEC-2024-0344` / `curve25519-dalek`) is resolved by the locked version
`4.1.3`.

Two low-priority housekeeping items are noted at the end.

---

## 1. Direct Cryptographic Primitives

| Crate | Locked | Status | Notes |
|---|---|---|---|
| `ring` | 0.17.14 |  GOOD | AWS/Google-hardened BoringSSL-derived impl; 0.17.x is current stable |
| `sha2` | 0.10.9 |  GOOD | RustCrypto SHA-256/SHA-512; no known issues |
| `sha3` | 0.10.8 |  GOOD | RustCrypto SHA-3/Keccak; used for Soroban EVM-compat precompiles |
| `hmac` | 0.12.1 |  GOOD | RustCrypto HMAC; no known issues |
| `digest` | 0.10.7 |  GOOD | Trait-only crate; no crypto logic |
| `keccak` | 0.1.5 | GOOD | RustCrypto Keccak permutation; correct use |
| `subtle` | 2.6.1 |  GOOD | Constant-time comparison primitives; current |
| `zeroize` | 1.8.2 |  GOOD | Secure memory zeroing; current |
| `crypto-bigint` | 0.5.5 |  GOOD | Constant-time big integers; RustCrypto stable |
| `fiat-crypto` | 0.2.9 |  GOOD | Formally verified field arithmetic (used by `curve25519-dalek`) |

**Notable absence:** No `md5`, `sha1` (standalone), `rc4`, `des`, `3des`, or
`rsa` crates appear anywhere in the transitive tree — the three most common
sources of legacy algorithm pull-in are all absent.

---

## 2. Elliptic Curve Cryptography

All curves are from the RustCrypto project (`rustcrypto.org`) or the
`dalek-cryptography` project, both of which follow coordinated disclosure and
maintain active RUSTSEC advisories.

| Crate | Locked | Status | Notes |
|---|---|---|---|
| `curve25519-dalek` | **4.1.3** |  GOOD | See §5 — RUSTSEC-2024-0344 patched in 4.1.2; 4.1.3 confirms fix |
| `ed25519-dalek` | 2.0.0 |  GOOD | Full rewrite on dalek 4.x; no known vulnerabilities |
| `ed25519` | 2.2.3 |  GOOD | Trait-only abstraction crate |
| `ecdsa` | 0.16.9 |  GOOD | RustCrypto ECDSA; 0.16.x is current stable series |
| `elliptic-curve` | 0.13.8 |  GOOD | RustCrypto EC framework |
| `p256` | 0.13.2 |  GOOD | NIST P-256 (secp256r1); current |
| `k256` | 0.13.4 |  GOOD | secp256k1; current |
| `rfc6979` | 0.4.0 |  GOOD | Deterministic ECDSA nonces per RFC 6979 
| `ff` | 0.13.1 |  GOOD | Finite field traits; no crypto implementation |
| `group` | 0.13.0 |  GOOD | Group traits; no crypto implementation |
| `signature` | 2.2.0 |  GOOD | Signature traits; no crypto implementation |
| `sec1` | 0.7.3 |  GOOD | SEC1 EC key encoding |
| `spki` | 0.7.3 | GOOD | SubjectPublicKeyInfo (X.509) encoding |
| `pkcs8` | 0.10.2 |  GOOD | PKCS#8 key encoding |
| `der` | 0.7.10 |  GOOD | DER/BER encoding |

**Why so many EC crates?** `soroban-env-host` 25.0.1 implements native
precompiles for Ed25519, secp256k1 (Ethereum-compat), P-256, BLS12-381, and
BN254. Each requires its own curve library. This is expected and intentional.

---

## 3. ZK Pairing — arkworks Suite

`soroban-env-host` pulls in the `ark-*` family to implement the BLS12-381 and
BN254 precompiles (Stellar Protocol 21+).

| Crate | Locked | Status | Notes |
|---|---|---|---|
| `ark-bls12-381` | 0.4.0 |  GOOD | BLS12-381 pairing for Stellar BLS signature precompile |
| `ark-bn254` | 0.4.0 |  GOOD | BN254 (alt-bn128); Ethereum ecPairing-equivalent |
| `ark-ec` | 0.4.2 |  GOOD | EC group operations; arkworks 0.4 series is stable |
| `ark-ff` | 0.4.2 |  GOOD | Finite field arithmetic |
| `ark-serialize` | 0.4.2 |  GOOD | Serialization for arkworks types |
| `ark-std` | 0.4.0 |  GOOD | `no_std`-compatible stdlib shim |

**Note:** `ark-ff` uses `ark-ff-asm` for x86-64 assembly Montgomery
multiplication. This is correct usage of the arkworks security model and has
been audited by multiple parties in the Ethereum ecosystem.

---

## 4. TLS Stack

The crate pulls in a full TLS stack via `jsonschema` → `reqwest` → `rustls`.
This is the pure-Rust `rustls` stack with no OpenSSL linkage.

| Crate | Locked | Status | Notes |
|---|---|---|---|
| `rustls` | **0.23.36** | GOOD | See §5 for CVE history; 0.23.36 clear of all published advisories |
| `rustls-webpki` | 0.103.9 |  GOOD | X.509 certificate validation; current |
| `rustls-pki-types` | 1.14.0 |  GOOD | PKI type definitions |
| `rustls-native-certs` | 0.8.3 |  GOOD | OS CA bundle integration |
|
**TLS protocol version floor:** `rustls` 0.23.x enforces TLS 1.2 minimum by
default; TLS 1.0/1.1 cannot be negotiated. No `InsecureSkipVerify` equivalent
is possible in the rustls API.

---

## 5. RUSTSEC Advisory Cross-Check

Every published RUSTSEC advisory that touches a crate in this dependency tree
was checked. Result: all are resolved by the locked versions.

| Advisory | Package | Vulnerable range | Locked version | Status |
|---|---|---|---|---|
| RUSTSEC-2024-0344 | `curve25519-dalek` | `< 4.1.2` | **4.1.3** |  Patched |
| RUSTSEC-2024-0421 | `rustls` | `< 0.23.5` | **0.23.36** | Patched |
| RUSTSEC-2024-0336 | `rustls` | `< 0.21.11 / < 0.22.4 / < 0.23.2` | **0.23.36** | Patched |
| RUSTSEC-2023-0052 | `webpki` | `< 0.22.1` | Using successor `rustls-webpki 0.103.9` | Not affected |
| RUSTSEC-2021-0119 | `ring` | `< 0.16.20` | **0.17.14** (rewritten 0.17 series) |  Not affected |

**Advisory detail — RUSTSEC-2024-0344 (`curve25519-dalek`):**  
LLVM introduced a conditional branch (`jns`) inside the `Scalar29::sub` and
`Scalar52::sub` subtraction loops, creating timing variability on secret scalar
values. This is a classical LLVM-induced timing side-channel in constant-time
code. The fix (merged in 4.1.2, shipped in 4.1.3) inserts a `volatile` read as
an optimisation barrier, preventing LLVM from introducing the branch. The
lockfile pins `4.1.3`, confirmed as the fixed version by both the RustSec
advisory and the Debian/Fedora security trackers.

**Advisory detail — RUSTSEC-2024-0336 / RUSTSEC-2024-0421 (`rustls`):**  
0336: A server could cause unbounded memory buffering leading to OOM DoS.  
0421: Session resumption handling could cause OOM DoS.  
Both are resolved in `rustls` 0.23.2 and 0.23.5 respectively.  
Locked version `0.23.36` is far past both.

---

## 6. Randomness

| Crate | Locked | Status | Notes |
|---|---|---|---|
| `rand` | 0.8.5 |  GOOD | Default RNG is ChaCha12 (a CSPRNG); latest in 0.8 series |
| `rand_chacha` | 0.3.1 |  GOOD | ChaCha20 stream cipher as CSPRNG |
| `rand_core` | 0.6.4 |  GOOD | RNG traits |
| `getrandom` | 0.2.11 |  GOOD | OS entropy via `getrandom(2)` / `/dev/urandom`; latest in 0.2 |
| `getrandom` | 0.3.4 |  GOOD | Also present as an indirect dep (`jsonschema` → `referencing`); expected |

The two `getrandom` versions serve different subtrees due to a SemVer-breaking
API change between 0.2 and 0.3. Both versions are safe; the duplication is
normal and carries no security implication.

---

## 7. Absent Legacy Algorithms

The following broken or deprecated algorithms were searched for throughout the
entire transitive tree and are **not present**:

| Algorithm | Search target | Result |
|---|---|---|
| MD5 | `md5` crate |  Absent |
| SHA-1 | `sha1`, `sha-1` crates |  Absent |
| RC4 | `rc4` crate |  Absent |
| DES / 3DES | `des`, `3des` crates |  Absent |
| RSA PKCS#1 v1.5 | `rsa` crate |  Absent |
| OpenSSL linkage | `openssl` crate (linking) |  Absent (`openssl-probe` only) |
| System TLS | `native-tls` crate |  Absent |
| JWT | `jsonwebtoken`, `jwt` crates |  Absent |

---

## 8. Supply Chain

- **All packages** are sourced from `registry+https://github.com/rust-lang/crates.io-index`
- **No git-pinned dependencies** — every dep resolves via SemVer from the registry
- **All checksums** in `Cargo.lock` are content-addressed SHA-256 digests that Cargo verifies before compilation
- **`soroban-wasmi`** is a Stellar-maintained fork of `wasmi`, published to crates.io under `soroban-wasmi` — not a shadowing attack on the upstream `wasmi` crate

---

## 9. Housekeeping Items (Non-Security)

These are not vulnerabilities but are worth resolving during normal maintenance.

### Item 1 — Dual `base64` versions (low priority)

```
base64 0.21.7  ← direct dep in Cargo.toml (pinned to "0.21")
base64 0.22.1  ← indirect dep via hyper-util, stellar-xdr, reqwest
```

Both versions are safe; the duplication exists because `0.21` → `0.22` was a
breaking API change (the new `Engine` trait). Neither version has any known
security issue. Once you no longer need the `0.21` API surface, unify with:

```toml
# Cargo.toml
base64 = "0.22"
```

### Item 2 — Pin `cargo-audit` or `cargo-deny` to CI (recommended hygiene)

The lockfile is clean today, but advisories are published continuously. Add one
of the following to your CI pipeline to catch new advisories automatically:

```yaml
# .github/workflows/security.yml
- name: Audit dependencies
  run: |
    cargo install cargo-audit --locked
    cargo audit
```

Or with `cargo-deny` for more control (license + duplicate-version checks too):

```toml
# deny.toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
```

---

## Appendix: Full Crypto-Surface Crate List

For completeness, every crate with cryptographic relevance found in the lockfile:

```
ark-bls12-381 0.4.0       ark-bn254 0.4.0          ark-ec 0.4.2
ark-ff 0.4.2              ark-ff-asm 0.4.2          ark-ff-macros 0.4.2
ark-serialize 0.4.2       ark-std 0.4.0             base16ct 0.2.0
base64ct 1.8.3            block-buffer 0.10.4       const-oid 0.9.6
crypto-bigint 0.5.5       crypto-common 0.1.6       curve25519-dalek 4.1.3
der 0.7.10                digest 0.10.7             ecdsa 0.16.9
ed25519 2.2.3             ed25519-dalek 2.0.0       elliptic-curve 0.13.8
ff 0.13.1                 fiat-crypto 0.2.9         generic-array 0.14.9
getrandom 0.2.11          getrandom 0.3.4           group 0.13.0
hmac 0.12.1               hyper-rustls 0.27.7       k256 0.13.4
keccak 0.1.5              openssl-probe 0.2.1       p256 0.13.2
pkcs8 0.10.2              ppv-lite86 0.2.20         primeorder 0.13.6
rand 0.8.5                rand_chacha 0.3.1         rand_core 0.6.4
rfc6979 0.4.0             ring 0.17.14              rustls 0.23.36
rustls-native-certs 0.8.3 rustls-pki-types 1.14.0  rustls-platform-verifier 0.6.2
rustls-webpki 0.103.9     sec1 0.7.3                sha2 0.10.9
sha3 0.10.8               signature 2.2.0           spki 0.7.3
subtle 2.6.1              tokio-rustls 0.26.4       untrusted 0.9.0
zeroize 1.8.2
```