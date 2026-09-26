# PRC Scoring Profile `coverage-v0.2.0-alpha`

```yaml
scoring-profile:
  id: coverage-v0.2.0-alpha
  status: experimental
  normative-role: reference candidate (replaceable); supersedes jaccard-v0.1.0-alpha's mass rule
  canonical-representative: structural-root-v1
  mass-function: material-dependency-coverage-v1
  unknown-lineage: single-sink-consequence-gated-v1
  confidence-function: exponential-saturation-v1
  threshold-function: consequence-exponential-v1
  exp-function: prc-exp-v1
  summation-order: dependency-atom-utf8-ascending
  dependency-source: self-declared-UNVERIFIED     # see P-1 and known exploit x01
```

- Reference: `reference/prc_coverage.py`
- Engine guard: `reference/prc_engine.py`
- Vectors: `tests/vectors/scoring_coverage_v0.2.0-alpha.json` (24 cases, 24 property witnesses)
- Randomised property tests: `tools/property_tests.py`
- Independent JavaScript implementation: `tools/xcheck.mjs`

The representative, state machine, confidence, threshold and `prc-exp-v1` are unchanged from `jaccard-v0.1.0-alpha`; see that document. The calibration (Ω = 1, T_base = 0.5, β = 0.2156, κ_degraded = 0.5, same Γ table) is also carried over.

## Mass

For each eligible family k with value `V_k = V(F*_k) · A(F̄_k)` and material atom set `D_k`:

$$w_k=\frac{V_k}{|D_k|},\qquad \operatorname{best}(d)=\max_{k:\,d\in D_k} w_k,\qquad M=\sum_{d\,\in\,\bigcup_k D_k}\operatorname{best}(d)$$

- The sum runs in ascending UTF-8 order of `d`, left to right.
- Ties keep the first family in canonical order as the atom's recorded owner. This affects only the trace, not M.

**Unknown lineage (single-sink-consequence-gated-v1).** A family with no material atoms is given `D_k = {UNKNOWN:*}` and `V_k · κ_eff`, where:
- `κ_eff = 0` if `T(x,a) ≥ unknown_gate_t` (0.92 in this profile);
- otherwise `κ_eff = κ_unknown` (0.5).

All unattributed families share the one sink atom. Together they contribute at most `max V_k · κ_eff`, however many there are.

## Properties

M is a weighted coverage function. Adding a family either leaves each `best(d)` unchanged, raises it, or adds a new atom with a non-negative credit. Round-to-nearest addition is monotone (`a ≤ a′ ⇒ fl(a+b) ≤ fl(a′+b)`), so by induction over the fixed-order sum the properties hold **bit for bit**, not just in exact arithmetic:

| Property | Statement | coverage-v0.2 violations | jaccard-v0.1 violations |
|---|---|---|---|
| P1 monotone | adding an eligible family never lowers M | 0 / 1500 | 287 / 1500 |
| P2 idempotent | a structural duplicate leaves M bit-identical | 0 / 1500 | 720 / 1500 |
| P3 order-free | permuting families, members or atom lists changes no output bit | 0 / 1500 | 0 / 1500 |
| P4 bridge-safe | a family drawn from several others' atoms never lowers M | 0 / 1500 | 463 / 1500 |
| P5 decision | none of the above turns ALLOW into DENY | 0 | 245 |

The counts come from `python tools/property_tests.py` (seed 20260925). The checker reruns 400 trials, and 24 deterministic witnesses are recomputed in both Python and JavaScript.

A family that is malformed, invalidated or has a non-VALID representative is excluded and cannot change anyone else's credit. `κ_eff` depends only on the action's threshold, never on the evidence, so adding evidence cannot switch the gate.

## Results

| Case | M | C | Decision | Notes |
|---|---|---|---|---|
| c03 three independent (wire) | 2.77 | 0.93734 | **ALLOW** | |
| c04 same three, shared feed | 1.314 | 0.73126 | **DENY** | the lineage flip is preserved |
| c05 two of three shared | 2.05 | 0.87127 | DENY | |
| c06 two independent | 1.87 | 0.84588 | DENY | |
| c07 + mirror of vendor A | 2.77 | 0.93734 | ALLOW | M bit-identical to c03 (F-2 fixed) |
| c08 + bridging item | 2.77 | 0.93734 | ALLOW | M bit-identical to c03 |
| c09 + unattributed item (wire, κ_eff = 0) | 1.314 | 0.73126 | DENY | M bit-identical to c04 (F-3 fixed) |
| c10a refund, one known family | 0.6 | 0.45119 | DENY | |
| c10b + one unattributed (κ_eff = 0.5) | 1.05 | 0.65006 | ALLOW | low-consequence policy lets unattributed evidence help, once |
| c11 + twenty unattributed | 1.05 | 0.65006 | ALLOW | M bit-identical to c10b: the single sink holds |
| c12 exact duplicate | 0.6 | 0.45119 | DENY | M bit-identical to c10a |
| c17 / c18 boundary | | C = T / T − 1 ulp | ALLOW / DENY | |
| e01–e04 NaN/Inf anywhere | 0 | 0 | DENY | stopped at `ENGINE_GUARD`; profile code never runs |
| **x01 atom padding** | 3.168 | 0.95790 | **ALLOW** | **known exploit, open (expected failure)** |

## Proposed normative rules

**E-1: Engine input guard.** Before dispatching to any scoring profile, the engine MUST check that every binary64 input is finite. That covers every `*_bits` profile parameter, every consequence Γ, and every evidence member's `value_bits`, including optional members. If any is NaN or ±Inf, the engine MUST return DENY with `SAFE_STATE_LOCK | NONFINITE_INPUT` without invoking the profile.

§2.3's rule that NaN/Inf forces C to 0.0 remains as a second line of defence for intermediate values. The guard is kept apart from profile validation deliberately: vectors e03 and e04 show that without it, a NaN parameter surfaces as a misleading "omega must be > 0" error instead of a clean fail-closed decision.

**N-1: Arithmetic.** Profiles MUST use binary64 with every intermediate rounded separately. Fused multiply-add, `-ffast-math`, reassociation and x87 extended precision are forbidden (`-ffp-contract=off`, strict FP modes). Transcendental functions MUST be profile-specified algorithms over basic operations (`prc-exp-v1`), never the platform library. JavaScript cannot express FMA portably, and FMA rounds `a·b+c` once instead of twice, so allowing it would split runtimes.

**P-1: Verified provenance.** This is the proposed rule that would close x01.
- Dependency atoms MUST NOT be taken from unauthenticated evidence bodies.
- An atom is admissible only if it is either:
  (a) carried in a provenance attestation signed by a key in a dedicated `K_provenance` domain (a fifth key domain under §1), bound to the evidence's canonical digest, and issued by an attester the profile authorises for that atom type; or
  (b) computed by the verifier itself from topology it observed.
- Anything else maps to `UNKNOWN:*`.
- Profiles SHOULD also bound atoms per type per family (for example one `SOURCE`). A signed attestation makes padding attributable, but not impossible.

Under P-1, x01's padded items would collapse to the unknown sink and contribute 0 on a wire. The vector records that as its security expectation: DENY, with M equal to c04. The checker treats the case as an expected failure, and fails the build if the exploit ever stops reproducing without the case being promoted.

## Still open

- **x01 / P-1:** needs the provenance attestation schema, the attester authorisation model and test vectors. It is the prerequisite for any lineage-based profile being sound.
- **Contradiction.** Coverage is monotone even for families with `CONTRADICTORY` members: contradiction zeroes only that family's own value, exactly as §2.2 states. Evidence that *refutes* the assertion therefore can't lower confidence built on other evidence. If refutation should act as a veto, it needs a separate channel (a defeater set checked before mass), not a negative mass term. That channel would break P1 by design.
- **Atom granularity** is still a modelling choice. Splitting one real dependency into several atoms changes shares (`V/|D|`). Verified provenance fixes who declares atoms, not how finely.
- **Calibration** is carried over and is still a policy choice, not a validated risk model.
