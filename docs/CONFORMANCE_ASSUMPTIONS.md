# Conformance assumptions and spec gaps — v0.3.0-alpha

The vectors in `tests/` need exact answers wherever the specification leaves a choice open. This file records each choice (**A-xx**) and each place where the spec as written allows something it probably shouldn't (**G-xx**). All of them are provisional. Each one should be written into the normative text (or replaced), and the vectors regenerated after any change.

Vectors that pin behaviour from a G-item carry a `spec_gap` field. Their expected values follow the spec **as written**, so fixing the spec will flip them. That is intended.

---

## Assumptions

### A-01 — Canonical encoding `PRC-LP-0`
§1 requires "length-prefixed canonical byte encodings" but names no format. §5 mentions Protobuf/FlatBuffers, but neither has a canonical form by default. Until a schema registry exists, the vectors use this tag-length-value encoding:

```
value := tag:u8 || len:u64 big-endian || payload[len]
0x00 null   len=0          0x10 int    len=8, int64 two's complement BE
0x01 false  len=0          0x11 f64    len=8, IEEE 754 bits BE (no normalisation)
0x02 true   len=0          0x20 string UTF-8
                           0x21 bytes  raw
0x30 list   concatenated encoded items
0x31 map    concatenated (string key, value) pairs; keys strictly ascending by UTF-8 bytes
```
- The decoder is strict. It rejects unsorted or duplicate keys, trailing bytes, wrong fixed lengths, invalid UTF-8, non-string keys and unknown tags (`golden_vectors.json → must_reject`).
- Strings are not Unicode-normalised: `"é"` (NFC) and `"é"` (NFD) encode differently. Callers must normalise before encoding if they need them to compare equal.
- Hashes, key ids and UUIDs inside payloads are lowercase hex / canonical text strings, not raw bytes.

### A-02 — One encoding layer
The spec defines `H(z) = SHA256(CanonicalEncode(z))`, but also defines `d`, `p` and `r` as `CanonicalEncode(…)`, and writes the null digests as `H(CanonicalEncode(label))`. Read literally, that encodes twice. The vectors treat `d`, `p` and `r` as the structured objects and encode exactly once:
`NULL_APPROVAL_DIGEST = SHA256(PRC-LP-0("PROVENANCE-RAZOR-NO-APPROVAL-V0.3.0-Alpha"))`.

### A-03 — Reason codes
- `reason_codes` (in `d`) and `reason_code` (in `r`) are a single unsigned 64-bit bitfield, encoded as an int.
- The bit assignments in `tests/reason_codes.json` are provisional.
- Verifiers report every failing conjunct, not just the first (A-18).

### A-04 — Exceptional threshold
§2.3 only says NaN/Inf in *C* forces `C = 0.0`. The vectors treat NaN/Inf in *T* the same way (lock, deny).

### A-05 — Safe State Lock denies
If a Safe State Lock fires, `AuthorizationCheck` returns FALSE even when the forced `C = 0.0 ≥ T` (for example `T = 0.0`). The lock must never produce an ALLOW.

### A-06 — No CORDIC vectors
The spec text defines no CORDIC operation, so none are generated. `KAHAN_SUM` is an **informative** harness operation for comparing runtimes. Only `AUTH_CHECK` records are normative. The file keeps the name given in §5.

### A-07 — `ScopePermits(scope, x, target)`
Case-sensitive glob (`*`, `?`) matched against `"<x.action>:<p.target>"`, e.g. `wire.release:acct-*`.

### A-08 — `A(F̄_k)` with several optional members
Each member's state gives a factor: `VALID` → 1.0, `DEGRADED` → κ, `CONTRADICTORY` → 0.0, `UNAVAILABLE_OR_STALE` → ignored. `A` is the **minimum** factor, or 1.0 if nothing contributes.

### A-09 — `CanonicalRepresentative`
The selection rule isn't defined, so each fixture names its representative explicitly as input.

### A-10 — Eligibility
A class is in `F_eligible` unless one of its members is `INVALID`. That invalidates the whole class and emits a `FAMILY_INVALIDATED` audit event.

### A-11 — Undefined aggregates (in the core lineage fixtures)
*The experimental scoring profile `jaccard-v0.1.0-alpha` supplies candidate definitions; see its own document. The core fixtures stay profile-independent.*
- `I(F̄_k | F̄_j)` isn't defined, so fixtures supply it as an input matrix. `I_k` is the minimum over the other eligible classes, or 1.0 for a singleton.
- `M(x,a)` and `C(x,a)` are only defined for an empty eligible set (both 0.0). Otherwise the fixtures mark them `UNDEFINED_BY_SPEC`.

### A-12 — Local CAS abort still produces a receipt
§4.1 writes the receipt *inside* the transaction, so an abort would also discard the receipt. But §4.3 defines `REJECTED`/`PRECONDITION` receipts. The vectors therefore:
- roll back the transaction, leaving the capability unconsumed and the state unchanged;
- write a `REJECTED` receipt in a separate transaction.

### A-13 — Distributed capabilities are never released
Once reserved at Prepare, a capability counts as consumed whatever the outcome (`REJECTED`, `ROLLED_BACK`, `UNRESOLVED`). This stops replays under the same Idempotency-Key. Retrying needs a new decision.

### A-14 — Timeout that reconciles to COMMITTED
`failure_phase = NONE`, and `reason_code` keeps `DISPATCH_TIMEOUT` so the history is recorded. A timeout that reconciles to not-applied is `ROLLED_BACK` / `DISPATCH`.

### A-15 — Time, identifiers, keys
- All timestamps are int64 microseconds since the Unix epoch, UTC. The `*_iso` fields in the vectors are for reading only.
- UUIDv7 follows RFC 9562. The 74 random bits are `SHA256("PRC-UUID7|" + label)`, so identifiers are deterministic.
- Test keys are Ed25519 with seed `SHA256("PRC-TEST-KEY|<domain>|<label>")`. Key id is `kid:<domain>:<first 16 hex of SHA256(pubkey)>`. **The seeds are public. These keys are for testing only.**

### A-16 — Signatures
`σ = Ed25519.Sign(sk, H(z))` over the raw 32-byte digest. Ed25519 is deterministic, so signatures are stable golden values.

### A-17 — Profile-driven parameters
The profile supplies:
- `ManualOnly` = `profile.manual_only_actions`;
- `Δτ_max(x, a, profile)` = `profile.max_eval_skew_us[x.action]`, falling back to `["*"]`;
- "reusable as classified" = `authority_class ∈ profile.reusable_authority_classes`.

### A-18 — No short-circuit
`DecisionBindingValid` evaluates every conjunct and sets every failing bit. The one exception is `CanonicalDecodeValid`: if decoding fails, only `DECODE_INVALID` is reported.

### A-19 — Key lookup and domain separation
- `Verify_{K_decision^pub}` uses the key named by `decision_key_id` in the trust registry.
- A valid signature from a key in another domain passes the signature conjunct, but `DecisionKeyAuthorized` rejects it (`auth_expiry_009`).
- For approvals, the named key must be an `approval`-domain key for the signature to count (`auth_expiry_031`).

---

## Spec gaps: status after 0.2.0-alpha

The normative text is `spec/PROVENANCE_RAZOR_SPEC.md` (0.3.0-alpha). Eleven of the twelve 0.1.0 gaps are now closed in the spec and pinned by vectors; G-12 is partly addressed.

| ID | Gap (0.1.0) | Status in 0.2.0 | Evidence |
|---|---|---|---|
| G-01 | approval target not bound to `d.target` / `CurrentTarget` | **closed** (§3.1) | `auth_expiry_036` now must-reject |
| G-02 | post-dated approvals accepted | **closed**: `p.τ_issued ≤ d.τ_eval ≤ τ_exec ≤ p.τ_expiry` | `auth_expiry_037` must-reject, `041` boundary |
| G-03 | approval not bound to actor / req_id / capability_id | **closed** (§3.1) | `auth_expiry_038`–`040` must-reject |
| G-04 | double encoding | **closed**: single layer, detached signatures (§1.2–1.3) | golden vectors |
| G-05 | M, C, T, I undefined | **closed by delegation** to a scoring profile (§2.1); reference `coverage-v0.2.1-alpha` | scoring vectors |
| G-06 | receipt inside an aborting transaction | **closed**: abort writes REJECTED receipt separately (§4.1) | cas `02`, `03` |
| G-07 | NaN/Inf in T; lock vs `0 ≥ T` | **closed**: E-1, lock always denies (§2.3) | numeric, `e0x` |
| G-08 | `reason_codes` shape | **closed**: uint64 bitfield (§3.3) | `tests/reason_codes.json` |
| G-09 | capability release after failure | **closed**: never released (§4.2) | cas `06`, `08`, `09` |
| G-10 | evaluator/executor clock disagreement; source of `τ_exec` | **closed in 0.3.0**: C-1 clock authorities with combined uncertainty U (§3.5) | `auth_clock_k01`–`k07` |
| G-11 | "SPECIFICATION FROZEN"; schemas claimed but absent | **closed**: status table rewritten; transport schemas added and marked provisional | `schema/` |
| G-12 | non-VALID representative | **partly**: a non-VALID representative gives no positive support (S-05); INVALID/TAMPERED invalidates the family. A normative sentence is still needed | scoring vectors |

### Open questions

| ID | Question | Status in 0.3.0 |
|---|---|---|
| Q-1 | **Naming authority.** Who maintains the atom registry and alias table, and how is alias equivalence proven? `x07` vs `x08` show this decides whether correlation is visible. | open; the registry is now committed by `trust_state_hash`, so it is at least bound and auditable |
| Q-2 | **Unverified contradictions** could suppress a family's support. | **closed**: A-1 (§2.5). An unattested contradiction contains (MANUAL_REQUIRED) and never changes M or C (`a02`, `a12`) |
| Q-3 | **Family membership** was trusted upstream. | **addressed**: M-1 (§2.6) signed family manifests; injection vectors `m01`–`m06` are neutral. What remains is Q-6 |
| Q-4 | **Attester collusion.** Independence is only `attester ≠ producer`. | open |
| Q-5 | **Calibration.** Ω, T_base, T_base_manual, β and Γ are policy choices without empirical validation. | open |
| Q-6 | **Membership authorities are now a trust root.** The manifest issuer decides what is in a family. Two consequences follow from the current rules. First, authenticated adverse evidence arriving outside a manifest is quarantined (`m04`), so the ingestion path must be able to add contradictions to families. Second, withholding a listed member excludes the whole family (`m13`). That is fail-safe for support, but it does not by itself raise containment. Who may issue manifests, how quickly contradictions can be appended, and whether withholding should also CONTAIN are unspecified. | new |
