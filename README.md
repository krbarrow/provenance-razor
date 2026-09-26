# Provenance Razor — specification and conformance suite (v0.3.0-alpha)

```
spec/PROVENANCE_RAZOR_SPEC.md normative text, 0.3.0-alpha (changelog in §6)
schema/protobuf/*.proto       TRANSPORT ONLY (v1alpha3; compiled + round-trip tested); never hashed or signed
schema/flatbuffers/*.fbs      TRANSPORT ONLY (v1alpha3; compiled with flatc + round-trip tested)
reference/prc_ref.py          Python reference model of the spec (pure, deterministic)
reference/prc_scoring.py      EXPERIMENTAL scoring profile jaccard-v0.1.0-alpha (superseded mass rule; kept as evidence)
reference/prc_coverage.py     scoring profile coverage-v0.2.0-alpha (superseded; atom-padding exploit reproduces by design)
reference/prc_provenance.py   P-1 provenance attestation + DependencyAdmissible
reference/prc_coverage_v021.py  scoring profile coverage-v0.2.1-alpha (superseded)
reference/prc_schema.py       CanonicalObjectValid (total) for d, p, r, attestations, manifests, evidence members
reference/prc_membership.py   M-1 family manifests: FamilyMembershipAdmissible
reference/prc_coverage_v030.py  EXPERIMENTAL scoring profile coverage-v0.3.0-alpha (A-1 containment + M-1)
reference/prc_engine.py       engine: non-finite guard (E-1), total boundary (V-1), profile dispatch
tools/generate_vectors.py     writes every artifact under tests/ (refuses if model ≠ declared intent)
tools/check_vectors.py        recomputes all expected values, checks MANIFEST, checks byte-identical regeneration
tools/scoring_cases.py        jaccard profile cases (imported by the generator)
tools/coverage_cases.py       coverage profile cases, engine-guard cases, property witnesses, known exploit
tools/coverage_v021_cases.py  v0.2.1 cases, exploit family x01–x14, defeaters d00–d03, witnesses
tools/coverage_v030_cases.py  v0.3.0 cases: disposition a00–a12, membership m01–m15, carry-overs, boundaries
tools/trust_fixture.py        the committed trust state and scoring profile used by 0.3.0 vectors
tools/property_tests.py       randomised property tests (P1–P6, P9–P10) and P11 totality fuzz
tools/transport_roundtrip.py  canonical -> Protobuf / FlatBuffers -> canonical -> PRC-LP-0 -> verify, + demos
tools/xcheck.mjs              independent JavaScript re-implementation; checks the same vectors
docs/CONFORMANCE_ASSUMPTIONS.md   every interpretive choice (A-xx) and spec gap (G-xx)
docs/SCORING_PROFILE_jaccard-v0.1.0-alpha.md   scoring definitions, calibration, findings F-1..F-5
docs/SCORING_PROFILE_coverage-v0.2.0-alpha.md  coverage mass, properties, proposed rules E-1 / N-1 / P-1
docs/SCORING_PROFILE_coverage-v0.2.1-alpha.md  P-1 / D-1 profile, exploit-family results
docs/SCORING_PROFILE_coverage-v0.3.0-alpha.md  A-1 containment, M-1 membership, properties
tests/
  MANIFEST.json               SHA-256 of every artifact
  reason_codes.json           provisional reason-code bit registry
  fixtures/golden_vectors.json            encoding primitives, must-reject bytes, signed d/p/r/profile
  fixtures/lineage_graphs/*.yaml          §2.1–2.2 consolidation cases
  fixtures/cas_reconciliation/*.yaml      §4.1–4.3 local CAS + distributed reconciliation, signed receipts
  vectors/auth_expiry_skew.json           §1.5, §3 DecisionBindingValid (71 cases: freshness, keys, schema, trust, containment, clocks)
  vectors/kahan_cordic_ieee754.bin/.json  §2.3 binary64 comparison + informative Kahan sums
  vectors/scoring_jaccard_v0.1.0-alpha.json   EXPERIMENTAL scoring profile: 26 cases + 32 prc-exp vectors
  vectors/scoring_coverage_v0.2.0-alpha.json  SUPERSEDED: 24 cases + 24 witnesses; x01 reproduces by design
  vectors/scoring_coverage_v0.2.1-alpha.json  SUPERSEDED: 32 cases + 18 witnesses
  vectors/scoring_coverage_v0.3.0-alpha.json  EXPERIMENTAL: 39 cases + 18 witnesses
```

Requirements: Python 3.9+ with `cryptography` and `PyYAML`. Optional: Node 18+ for the cross-check; `grpcio-tools` + `protobuf` and a `flatc` binary (on PATH or in `$FLATC`) for the transport round trips (each skipped when absent).

```bash
python tools/generate_vectors.py   # only when the model or the cases change
python tools/check_vectors.py      # includes 400 randomised property trials
python tools/property_tests.py     # full run: 1500 trials per property, coverage vs jaccard
node tools/xcheck.mjs
python tools/transport_roundtrip.py
```

The test keys are derived from public seeds (A-15). Never use them for anything except conformance testing.
