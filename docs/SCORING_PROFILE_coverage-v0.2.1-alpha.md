# PRC Scoring Profile `coverage-v0.2.1-alpha`

```yaml
scoring-profile:
  id: coverage-v0.2.1-alpha
  status: experimental
  normative-role: reference candidate; supersedes coverage-v0.2.0-alpha
  canonical-representative: structural-root-v1
  mass-function: material-dependency-coverage-v1      # unchanged from v0.2.0
  unknown-lineage: single-sink-consequence-gated-v1   # unchanged
  confidence-function: exponential-saturation-v1
  threshold-function: consequence-exponential-v1
  exp-function: prc-exp-v1
  summation-order: dependency-atom-utf8-ascending
  dependency-source: attested-P-1                     # was self-declared-UNVERIFIED
  defeater-policy: authenticated-contradiction-veto-v1 # new
```

- Reference: `reference/prc_provenance.py`, `reference/prc_coverage_v021.py`
- Vectors: `tests/vectors/scoring_coverage_v0.2.1-alpha.json` (32 cases, 18 witnesses)
- Normative text: `spec/PROVENANCE_RAZOR_SPEC.md` §2.4 (P-1) and §2.5 (D-1)

The coverage mass rule and the calibration are unchanged from v0.2.0. Only two things change: where the atoms come from, and how contradiction acts.

## Profile additions

| Field | Value in the calibrated profile | Purpose |
|---|---|---|
| `atom_registry.mode` | `closed` | only registered atoms are admissible (the naming authority) |
| `atom_registry.atoms` | sorted, unique list | canonical atom identities |
| `atom_registry.aliases` | e.g. `SOURCE:fcp-1 → SOURCE:feed-core-primary` | different names for one dependency resolve to one identity |
| `max_atoms_per_type` | API_ENDPOINT 1, CLOCK 1, COLLECTOR 2, DATABASE 2, NETWORK_AS 1, RUNTIME 2, SOURCE 2, TRUST_ROOT 1 | bounds padding even by an honest-but-careless attester |
| `attester_independence_required` | `true` | the attester must not be the evidence producer |

The trust state (key registry and revocations) is an input to evaluation, not part of the profile. Each provenance key is registered with its owner's `attester_id`, its authorised epochs, and the atom types it may vouch for.

## Results

| Case | Provenance outcome | Decision | Notes |
|---|---|---|---|
| c03 three independent (attested) | ADMITTED | **ALLOW** (C = 0.93734) | the lineage flip is preserved over attested lineage |
| c04 same three, shared feed (attested) | ADMITTED | **DENY** (C = 0.73126) | |
| c07 / c08 / c09 mirror, bridge, re-attested duplicate | ADMITTED | ALLOW | M bit-identical to c03 |
| c10b / c11 unattested at refund | UNATTESTED | ALLOW | contributes V·κ once; twenty contribute the same as one |
| **x01 self-declared padding** (the v0.2.0 exploit) | UNATTESTED | **DENY** | M bit-identical to c04; was ALLOW (C = 0.958) in v0.2.0 |
| x02 auditor-signed fabricated atoms | INADMISSIBLE: unregistered atom | DENY | M = c04 |
| x03 registered atoms over the cap | INADMISSIBLE: 3 COLLECTOR > 2 | DENY | M = c04 |
| x04 vendor attests its own evidence | INADMISSIBLE: self-attested | DENY | |
| x05 valid attestation copied onto other evidence | **TAMPERED**: digest mismatch | DENY | family invalidated, audited |
| x06 attestation signed with a decision key | **TAMPERED**: key domain | DENY | |
| x07 shared feed named by aliases | ADMITTED (resolved) | DENY | M = c05: correlation detected |
| x08 same input, registry without aliases | ADMITTED | **ALLOW** | pins the naming-authority risk (Q-1) |
| x09 / x10 / x11 / x12 expired, revoked, unknown key, type not authorised | INADMISSIBLE | DENY | |
| x13 attester_id forged | **TAMPERED** | DENY | |
| x14 score edited after attestation | **TAMPERED**: digest mismatch | DENY | the digest covers `value_bits` |
| d00 four independent | ADMITTED | ALLOW (C = 0.97452) | baseline |
| d01 unattested contradiction | UNATTESTED | ALLOW | zeroes only its family; audited as UNVERIFIED_CONTRADICTION |
| **d02 auditor-attested contradiction** | ADMITTED defeater | **DENY** | M and C bit-identical to d01: a categorical veto |
| d03 contradiction with a forged signature | TAMPERED | ALLOW | family invalidated; the other three still pass |

## Properties

`tools/property_tests.py` runs 500 trials over randomly generated attested evidence. The results:

| | Property | Violations |
|---|---|---|
| P1 | monotone positive mass | 0 |
| P2 | re-attested duplicate idempotent | 0 |
| P3 | order-free | 0 |
| P4 | bridge-safe | 0 |
| P5 | none of P1–P4 turns ALLOW into DENY | 0 |
| P6 | an admitted defeater always yields DENY | 0 |
| P7 | an unattested family is neutral on a wire | 0 |
| P8 | a lifted or forged attestation is neutral | 0 |

P5 now excludes defeaters by design: a veto is the one addition that may turn ALLOW into DENY.

## Open questions

These are summarised in `docs/CONFORMANCE_ASSUMPTIONS.md` as Q-1 to Q-5:

- Q-1 who governs the atom registry;
- Q-2 whether unattested contradictions should have any effect;
- Q-3 admissibility of family membership;
- Q-4 attester collusion;
- Q-5 calibration.
