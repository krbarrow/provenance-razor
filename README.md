### The Provenance Razor (Philosophical Foundation)

The Provenance Razor is proposed as a foundational principle of justified reliance.

Unlike epistemologies that seek truth, probability, or belief justification, the Provenance Razor concerns the justification of reliance under uncertainty. It applies regardless of whether truth is known, unknowable, or ultimately nonexistent.

Its central claim is that reliance on an assertion requires provenance sufficient to support confidence proportional to the consequences of error.

The Razor is itself subject to this standard. Confidence in the Razor should rise or fall according to the provenance supporting its usefulness, explanatory power, and predictive success.

> **Assertion:** To rely on any assertion whose provenance does not support confidence proportional to the reasonably assessed consequences of its being wrong is a failure of reasoning.

> **Immediate Corollary:** This razor is itself an assertion and subject to its own scrutiny.

**Scope.** The razor is not a method for producing assertions. Bayesianism, evidentialism, pragmatism, skepticism and realism all produce assertions; the razor governs whether action or inaction based upon those assertions is justified. Whatever method generated an assertion, a separate analysis is required before relying upon it.

**Time of reliance.** The razor does not reward explanations for eventually being correct; it rewards them for being justified at the time reliance was requested. A justified reliance that turns out wrong is not a failure of the razor; an unjustified one that turns out right is a failure that went unpunished. New provenance opens a new moment of reliance; it does not revise the judgement of an earlier one.

**Temporal validity.** Provenance is not permanent. All provenance remains contingent upon the continued validity of the assertions it rests on, and may be revised or revoked by later information: it can be superseded by newer evidence, compromised when its own basis proves invalid, revoked by explicit withdrawal, or expire by design. Reliance justified yesterday may be unjustified today. An assertion can have excellent provenance and still deserve reduced reliance because it was formed before relevant evidence existed. What matters is whether evidence bearing on the assertion has appeared since, not age alone: a valid geometry proof from the 1950s loses nothing with time; a 1960s medical recommendation or 1950s physics may have been superseded; security guidance can go stale within years, valid when published and unsafe now. Newer contradicting evidence supersedes older knowledge only when it is itself backed by sufficient provenance. The specification implements this for its own objects: provenance attestations and family manifests are checked for revocation, authorised key epochs and expiry (§2.4, §2.6), the trust state binds the revocation sets in force (§2.7), and decision capabilities expire within a bounded window (§3.5).

**Cost of analysis.** Examining provenance is itself an action with consequences, and by the corollary it is subject to the razor. The total risk of relying after analysis of depth $d$ is

$$\text{Total Risk}(d) = P(\text{Error} \mid d) \times \text{Cost}(\text{Error}) + \text{Cost}(\text{Analysis}(d))$$

Analysis is warranted while a further step reduces the expected cost of error by more than the step costs. Low stakes therefore warrant little analysis, and a cheap heuristic can be the proportionate one. Testing is how provenance is acquired, so the same rule orders tests: in decreasing ratio of the probability that a test settles the question to its cost.

**Evidence standard.** The Provenance Razor is supported only insofar as it successfully reproduces the useful conclusions of existing heuristics, predicts their failure conditions, and identifies domains where they remain superior. The cases so far are in [docs/RELATED_PRINCIPLES.md](docs/RELATED_PRINCIPLES.md).

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
docs/RELATED_PRINCIPLES.md        the razor tested against Hanlon, Occam, extraordinary claims, Hitchens, crowds
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

Requirements: Python 3.11+ with `cryptography` and `PyYAML`. Optional: Node 18+ for the cross-check; `grpcio-tools` + `protobuf` and a `flatc` binary (on PATH or in `$FLATC`) for the transport round trips (each skipped when absent).

```bash
python tools/generate_vectors.py   # only when the model or the cases change
python tools/check_vectors.py      # includes 400 randomised property trials
python tools/property_tests.py     # full run: 1500 trials per property, coverage vs jaccard
node tools/xcheck.mjs
python tools/transport_roundtrip.py
```

The test keys are derived from public seeds (A-15). Never use them for anything except conformance testing.
