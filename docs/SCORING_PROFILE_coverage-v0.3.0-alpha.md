# PRC Scoring Profile `coverage-v0.3.0-alpha`

```yaml
scoring-profile:
  id: coverage-v0.3.0-alpha
  status: experimental
  normative-role: reference candidate; supersedes coverage-v0.2.1-alpha
  canonical-representative: structural-root-v1
  mass-function: material-dependency-coverage-v1       # unchanged since v0.2.0
  unknown-lineage: single-sink-consequence-gated-v1    # unchanged
  confidence-function: exponential-saturation-v1
  threshold-function: consequence-exponential-v1       # also used for T_manual (t_base_manual)
  exp-function: prc-exp-v1
  summation-order: dependency-atom-utf8-ascending
  dependency-source: attested-P-1
  membership: signed-family-manifest-M-1               # new
  adverse-disposition: contain-defeat-lock-A-1         # new; replaces D-1
```

- Reference: `reference/prc_coverage_v030.py`, `reference/prc_membership.py`, `reference/prc_schema.py`
- Vectors: `tests/vectors/scoring_coverage_v0.3.0-alpha.json` (39 cases, 18 witnesses)
- Normative text: spec §2.5 (A-1), §2.6 (M-1), §2.7 (trust context)
- Trust context: `tools/trust_fixture.py`

The mass function and the calibration are unchanged. In this version the profile holds only arithmetic. The atom registry, aliases, caps, independence rule, conflict types and clock authorities moved to the committed trust state.

## What changed and what it closes

| Case | Result | What it shows |
|---|---|---|
| a00 four independent | ALLOW (C = 0.97452) | baseline |
| a01 + auditor-attested contradiction | **DENY** (DEFEAT) | M and C bit-identical to a00 |
| a02 + unattested contradiction | **MANUAL_REQUIRED** (CONTAIN) | M and C bit-identical to a00; automatic ALLOW prohibited |
| a03 + self-attested contradiction | MANUAL_REQUIRED | INADMISSIBLE contains exactly like UNATTESTED |
| a04 + listed contradiction with a forged attestation | **DENY** (LOCK) | Safe State Lock |
| a05 CONTAIN with C below T_manual | DENY | containment never lowers the bar |
| a06 / a07 same claim in two families / twenty times | one obligation | review obligations deduplicate |
| a08 / a09 wrong target / unknown conflict type | ALLOW | irrelevant contradictions are audited only |
| a10 root is itself an unattested contradiction | MANUAL_REQUIRED | no support from that family; containment |
| a11 DEFEAT and CONTAIN together | DENY (DEFEAT) | precedence |
| a12 three independent + unattested contradiction | MANUAL_REQUIRED, M = 2.77 | coverage-v0.2.1 zeroed this family (M = 1.85, DENY) |
| m01–m06 injected INVALID member, second root, unattested / attested / forged contradiction, same-id impostor | ALLOW, M bit-identical | injection into another source's family is neutral (quarantined) |
| m07–m15 no manifest, out of scope, unregistered key, wrong key domain, replayed, altered, withheld, expired, revoked | family excluded or invalidated | membership admissibility |
| x01 / x05 / x07 padding, lifted attestation, aliases | DENY | P-1 still holds under M-1 |
| b01 / b02 boundary | ALLOW / DENY | C = T and one ulp below |
| f01 / f02 malformed family or member | excluded, audited | V-1: structured, never an exception |

## Properties

`tools/property_tests.py` runs 200 trials for the v0.3.0 properties and 600 mutations for P11. The results:

| | Property | Violations |
|---|---|---|
| P1 | monotone positive mass | 0 |
| P2 | re-attested, re-manifested duplicate idempotent | 0 |
| P3 | order-free | 0 |
| P4 | bridge-safe | 0 |
| P5 | none of P1–P4 turns ALLOW into DENY | 0 |
| P6 | a listed, admitted, relevant contradiction always DENYs | 0 |
| P9 | an unlisted member of any adversarial kind changes nothing (M, C, disposition, decision) | 0 |
| P10 | a listed unattested relevant contradiction keeps M and C bit-identical, never yields ALLOW, and turns ALLOW into MANUAL_REQUIRED | 0 |
| P11 | totality under 600 random mutations: exceptions escaping the decision verifier; byte-flipped decisions accepted; scoring faults | 0; 0; 0 |

## Open questions

These are listed in `docs/CONFORMANCE_ASSUMPTIONS.md`:

- Q-1 naming authority;
- Q-4 attester collusion;
- Q-5 calibration;
- Q-6 membership authorities as a trust root: authenticated adverse evidence outside a manifest is quarantined (m04), and withholding excludes a family but does not raise containment (m13).
