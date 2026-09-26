---
title: Provenance Razor Control Specification
version: 0.3.0-alpha
supersedes: 0.2.0-alpha
status: alpha
confidence-classification: provisional
artifact-class: research-specification
license: MIT
owner: Kevin R. Barrow

evidence-basis:
  - mathematical-formalization
  - executable-semantics
  - conformance-vectors
  - cross-runtime-verification
  - randomized-property-and-totality-testing

maturity:
  control-architecture: stable-draft
  canonical-encoding: provisional        # PRC-LP-0
  transport-schemas: provisional         # Protobuf and FlatBuffers, both compiled and round-trip tested
  scoring-profile: experimental          # coverage-v0.3.0-alpha
  reference-runtime: python
  conformance-vectors: generated-provisional
  cross-runtime-verification: python-and-javascript
  dag-decomposition: pending
  independent-verification: pending

version-policy:
  major: incompatible normative change
  minor: normative extension
  patch: clarification or correction
  pre-1.0: incompatible normative changes increment the minor version (SemVer 2.0.0 item 4)
---

## Provenance Razor Control Specification
#### v0.3.0 Alpha

The Provenance Razor Control Specification is an evolving research and engineering framework for deterministic, lineage-aware execution control. Everything in this document is provisional. Version status reflects the quantity and quality of supporting evidence, and nothing here is frozen.

Consistent with the Provenance Razor itself, the specification treats its own assertions as hypotheses. Its objective is not certainty. It is a deterministic framework for judging whether an assertion has enough evidence, verified provenance, verified membership, observation and reconciliation to justify confidence proportional to the consequences of error. Each result carries only the authority its provenance warrants.

**Changes** are summarised in §6. Every normative change is backed by conformance vectors in `tests/`.

---

### 1. Key Domains, Canonical Encoding, Signatures and Validity

#### 1.1 Key domains

$$\text{Domain}(K) \in \{ K_{\text{profile}}, K_{\text{approval}}, K_{\text{decision}}, K_{\text{receipt}}, K_{\text{provenance}}, K_{\text{membership}} \}$$

1. $K_{\text{profile}}$ signs control profiles, scoring profiles and trust-state objects.
2. $K_{\text{approval}}$ signs manual approvals ($p$).
3. $K_{\text{decision}}$ signs decision capabilities ($d$).
4. $K_{\text{receipt}}$ signs receipts ($r$).
5. $K_{\text{provenance}}$ signs provenance attestations ($\pi$, §2.4).
6. $K_{\text{membership}}$ signs family manifests ($\mu$, §2.6). New in 0.3.0.

**Domain-scoped resolution.** $\text{Verify}_{K_{\text{dom}}}$ means three separate steps:
1. resolve the key identifier *only* among keys registered in domain `dom`;
2. verify the signature;
3. check epoch and policy authorisation.

A key registered in another domain is treated as not found. The same rule applies to every object type.

#### 1.2 Canonical encoding and hashing

$$\mathcal{H}(z) \equiv \text{SHA256}\left( \text{PRC-LP-0}(z) \right)$$

- $z$ is the structured canonical object, encoded exactly once.
- PRC-LP-0 is the canonical, length-prefixed tag-length-value encoding (A-01). Decoders MUST reject every non-canonical byte string.
- Integers are int64, and every integer this specification defines is non-negative. Reason-code masks therefore use bits 0–62; **bit 63 is reserved.**
- Timestamps are int64 microseconds since the Unix epoch, UTC.

#### 1.3 Detached signatures

$$\sigma_z = \text{Sign}_{K_{\text{domain}(z)}}\left( \mathcal{H}(z) \right)$$

A signature is never a field of the object it signs.

#### 1.4 Transport encodings

Protobuf and FlatBuffers (`schema/`) are transport and storage formats only. Their bytes MUST NOT be hashed, signed or compared. A verifier MUST:

1. parse the transport message;
2. reject unknown fields;
3. validate presence, lengths and enumerations;
4. convert to the canonical object;
5. apply §1.5;
6. compute $\mathcal{H}$ over PRC-LP-0;
7. verify the detached signature.

#### 1.5 Canonical object validity and total verification

**CanonicalObjectValid(z, schema)** runs after decoding and before any signature or semantic predicate. It requires:

- exactly the schema's fields, with none missing and none extra;
- every field of its declared type, with a boolean never accepted as an integer;
- non-negative integers within int64;
- a supported `schema_ver`;
- 32-byte lowercase-hex digests;
- canonical lowercase UUIDv7 identifiers;
- key identifiers of the form `kid:<domain>:<16 hex>`;
- enumeration values from the defined set.

Schemas are defined for $d$, $p$, $r$, $\pi$ and $\mu$. Evidence members have an open schema: `evidence_id`, `parent_id`, `producer`, `value_bits` (16 hex digits) and optional `state` are required to be well formed, and claim fields may be added.

**V-1 (total verification).** For every input $z$:

$$\text{Verify}(z) \in \{\text{ALLOW}, \text{MANUAL\_REQUIRED}, \text{DENY}\}$$

Verify MUST NOT raise or terminate abnormally. A malformed object yields a structured rejection: `DECODE_INVALID`, `OBJECT_SCHEMA_INVALID` or `APPROVAL_SCHEMA_INVALID`. Structurally invalid families or members are excluded and audited. Any residual internal fault is converted at the verifier boundary into DENY with `SAFE_STATE_LOCK | VERIFIER_FAULT`.

---

### 2. Evidence, Provenance, Membership and Deterministic Math

#### 2.1 Equivalence classes and the scoring profile

Evidence is partitioned into lineage families $\bar{F}_1, \dots, \bar{F}_m$. The members of a family are exactly those admitted by §2.6.

- $F_k^*$ is the family's unique structural root among its admitted members.
- A family with zero or several roots, a cycle, or a duplicate identifier is malformed. It is excluded and audited.
- The family value is:

$$V(\bar{F}_k) = V(F_k^*) \cdot A(\bar{F}_k), \qquad V(F_k^*) \in [0,1]$$

$M(x,a)$, $C(x,a)$, $T(x,a)$ and $T_{\text{manual}}(x,a)$ are defined by the active **scoring profile**. The scoring profile is bound by $d.\text{scoring\_profile\_hash}$ (§2.7). A scoring profile MUST:
- be deterministic;
- obey §2.3;
- take dependency atoms only from §2.4 and family members only from §2.6.

Positive mass SHOULD be monotone. The reference candidate is `coverage-v0.3.0-alpha`.

$$F_{\text{eligible}}(x,a) = \emptyset \implies M(x,a) = 0.0 \implies C(x,a) = 0.0$$

#### 2.2 Optional member states

$$\text{State}(F_i) \in \{\text{VALID}, \text{UNAVAILABLE\_OR\_STALE}, \text{DEGRADED}, \text{CONTRADICTORY}, \text{INVALID}\}$$

* **UNAVAILABLE_OR_STALE:** no positive support. $A$ is unaffected.
* **DEGRADED:** $A(\bar{F}_k) = \kappa_{\text{degraded}}$.
* **CONTRADICTORY:** no positive support, and **no effect on $A$.** Its effect on authorization is governed only by §2.5.
* **INVALID:** the family is invalidated and a security audit event is emitted.

$A(\bar{F}_k)$ is the minimum factor over contributing members, or 1.0 if none contribute. A TAMPERED provenance attestation (§2.4) makes its member INVALID.

#### 2.3 Numerical comparison

$$\text{AuthorizationCheck}(C, T) \iff (C(x,a) \ge T(x,a)) = \text{TRUE}$$

- **E-1:** every binary64 input MUST be finite before any profile logic runs. Otherwise the result is DENY with Safe State Lock.
- **N-1:** binary64 with every intermediate rounded separately; no fused multiply-add, reassociation or extended precision. Transcendental functions MUST be profile-specified algorithms, such as `prc-exp-v1`.
- No epsilon tolerances. `-0.0` normalises to `+0.0`. Subnormals are preserved. A NaN or ±Inf forces $C = 0.0$ and **State 2 (Safe State Lock)**, which always denies.

#### 2.4 Verified provenance (P-1)

Self-declared dependencies MUST NOT be used. An atom `TYPE:id` is admissible only if it arrives in a provenance attestation that satisfies CanonicalObjectValid and:

$$\text{DependencyAdmissible}(\pi, e) \iff \begin{cases} \text{Verify}_{K_{\text{provenance}}}(\mathcal{H}(\pi), \sigma_\pi) \land \pi.\text{domain} = \text{"PROVENANCE-RAZOR-PROVENANCE-V0.3.0-Alpha"} \\ \land\; \pi.\text{attester\_id} = \text{Owner}(\pi.\text{provenance\_key\_id}) \land \pi.\text{evidence\_digest} = \mathcal{H}(\text{EvidenceCore}(e)) \\ \land\; \text{EpochAuthorized} \land \neg\text{Revoked}(\pi) \land \pi.\tau_{\text{issued}} \le \tau_{\text{eval}} \le \pi.\tau_{\text{expiry}} \land \pi.\text{attester\_id} \ne e.\text{producer} \\ \land\; \forall t: \text{AttesterAuthorized}(\text{type}(t)) \land \text{Registered}(\text{Resolve}(t)) \land \forall \theta: |\text{atoms of type } \theta| \le \text{Cap}(\theta) \end{cases}$$

- The atom registry, the alias table, the caps and the independence rule belong to the **trust state** (§2.7).
- Outcomes:
  - **ADMITTED:** the resolved atoms are used.
  - **UNATTESTED** or **INADMISSIBLE:** the lineage is unknown.
  - **TAMPERED:** the member is INVALID.

#### 2.5 Adverse disposition (A-1)

A contradicting member is **relevant** only if it meets both conditions:
- its `conflict_type` is recognised by the trust state;
- its `contradicts` field equals the request's $\langle$action, assertion, target, evidence_snapshot_id$\rangle$.

Irrelevant contradictions are audited and have no effect. For each relevant contradicting member $e$ admitted by §2.6:

$$\text{ContradictionDisposition}(e)= \begin{cases} \text{DEFEAT}, & \text{Provenance}(e)=\text{ADMITTED}\\ \text{CONTAIN}, & \text{Provenance}(e)\in\{\text{UNATTESTED},\text{INADMISSIBLE}\}\\ \text{LOCK}, & \text{Provenance}(e)=\text{TAMPERED} \end{cases}$$

$$\text{AdverseDisposition}(x,a) = \max_{\prec}\{\text{ContradictionDisposition}(e)\} \cup \{\text{CLEAR}\}, \qquad \text{CLEAR} \prec \text{CONTAIN} \prec \text{DEFEAT} \prec \text{LOCK}$$

A numeric Safe State Lock also yields LOCK. Contradictions never change $A$, $V$, $M$, $C$ or $T$. They affect only which authorization modes are eligible:

$$\text{AutomatedAllow}(x,a) \iff C \ge T \land \text{AdverseDisposition} = \text{CLEAR}$$

$$\text{ManualAllow}(x,a) \iff C \ge T_{\text{manual}} \land \text{AdverseDisposition} \in \{\text{CLEAR}, \text{CONTAIN}\} \land \text{ExternalApprovalValid}(p, d)$$

| Disposition | Outcome |
|---|---|
| LOCK | DENY, with Safe State Lock |
| DEFEAT | DENY. An ordinary manual approval cannot override it; any future override needs a separately named, higher-authority exception object. |
| CONTAIN | MANUAL_REQUIRED if $C \ge T_{\text{manual}}$, otherwise DENY |
| CLEAR | ALLOW if $C \ge T$, otherwise DENY |

**Containment obligations.**
- Relevant adverse claims collapse under the canonical contradiction digest $\mathcal{H}(\langle\text{conflict\_type}, \text{contradicts}, \text{claim}\rangle)$. Repeated submissions of the same claim create one obligation.
- Each occurrence is audited with its ingress channel.
- `containment_digest` is $\mathcal{H}$ of the sorted CONTAIN digests, or NULL_CONTAINMENT_DIGEST when the disposition is CLEAR.

$$\text{NULL\_CONTAINMENT\_DIGEST} = \mathcal{H}\left(\text{"PROVENANCE-RAZOR-NO-CONTAINMENT-V0.3.0-Alpha"}\right)$$

#### 2.6 Family membership (M-1)

Membership is asserted by a **family manifest** $\mu$ signed in $K_{\text{membership}}$ by a membership authority, typically the ingestion gateway. It contains:
- domain, schema_ver, manifest_id, membership_key_id, membership_trust_epoch;
- authority_id and family_id;
- ingress_channel;
- members, each as $\langle$evidence_id, $\mathcal{H}(\text{EvidenceCore}(e))$, parent_id$\rangle$, sorted and unique;
- $\tau_{\text{issued}}$ and $\tau_{\text{expiry}}$.

Evaluating a family's manifest gives one of three outcomes:

- **TAMPERED** — the family is invalidated and a security event emitted. Causes:
  - a malformed envelope or payload, or a wrong domain string;
  - a key from another domain, or a bad signature;
  - an authority_id that is not the key's owner, or a family_id that doesn't match (a replayed manifest);
  - a non-canonical member list;
  - a listed member altered after the manifest was issued.
- **UNVERIFIED** — the family is excluded from support, and its contradictions have no effect. Causes:
  - no manifest, or a manifest signed by a key that isn't registered;
  - an unauthorised epoch, a revoked manifest, or a manifest that isn't fresh;
  - the authority's `membership_scopes` don't cover the family_id;
  - a listed member withheld from the submission.
- **VERIFIED** — members are classified individually:
  - **LISTED:** the digest and parent match the manifest.
  - **QUARANTINED:** the member is not listed, or it reuses a listed evidence_id without matching the manifest. It is excluded entirely and audited only: it can neither invalidate, attenuate, contain nor defeat the family it names.

Structurally invalid members (§1.5) are quarantined before membership is evaluated.

#### 2.7 Trust context and binding

Each rule is committed by exactly one object:

| Object | Commits | Bound as |
|---|---|---|
| Control profile | ManualOnly, $\Delta\tau_{\max}$, reusable authority classes | `control_profile_hash` |
| Scoring profile | Ω, $T_{\text{base}}$, $T_{\text{base,manual}}$, β, κ values, gate, Γ, material types, component ids | `scoring_profile_hash` |
| Trust state | key registry for all six domains (owners, epochs, authority classes, authorised atom types, membership scopes), revocations of attestations and manifests, atom registry and aliases, per-type caps, attester independence, conflict types, clock authorities | `trust_state_hash` |

The verifier MUST confirm all three:
- $d.\text{trust\_state\_hash} = \mathcal{H}(\text{TrustState}_{\text{active}})$;
- $d.\text{scoring\_profile\_hash} = \mathcal{H}(\text{ScoringProfile}_{\text{active}})$;
- $d.\text{control\_profile\_hash} = \mathcal{H}(\text{ControlProfile}_{\text{active}})$.

Two evaluators that use different registries, alias authorities, revocation sets or attester authorisations therefore produce different decision bindings.

---

### 3. Canonical Objects and Bidirectional Binding

#### 3.1 External manual approval ($p$)

$p$ carries:
- domain `"PROVENANCE-RAZOR-APPROVAL-V0.3.0-Alpha"`, schema_ver, approval_id, approval_key_id, approval_trust_epoch;
- authority_class and authority_scope;
- $x$, $a$, target, actor, req_id, capability_id, state_ver;
- control_profile_hash, scoring_profile_hash, trust_state_hash;
- adverse_disposition, containment_digest;
- $\tau_{\text{issued}}$, $\tau_{\text{expiry}}$, and decision = ALLOW.

$$\text{ExternalApprovalValid}(x,a,d,p,\sigma_p) \iff \begin{cases} \text{CanonicalObjectValid}(p, \text{approval}) \land \text{Verify}_{K_{\text{approval}}}(\mathcal{H}(p), \sigma_p) \land \text{domain ok} \\ \land\; \text{ApprovalKeyAuthorized} \land \text{ScopePermits}(p.\text{authority\_scope}, x, p.\text{target}) \\ \land\; p.x = x \land p.a = a \land p.\text{state\_ver} = \text{CurrentStateVersion} \land p.\text{control\_profile\_hash} = \text{Active} \\ \land\; p.\text{scoring\_profile\_hash} = d.\text{scoring\_profile\_hash} \land p.\text{trust\_state\_hash} = d.\text{trust\_state\_hash} \\ \land\; p.\text{target} = d.\text{target} = \text{CurrentTarget} \land p.\text{actor} = d.\text{actor} \land p.\text{req\_id} = d.\text{req\_id} \land p.\text{capability\_id} = d.\text{capability\_id} \\ \land\; p.\text{adverse\_disposition} = d.\text{adverse\_disposition} \land p.\text{containment\_digest} = d.\text{containment\_digest} \\ \land\; p.\tau_{\text{issued}} \le d.\tau_{\text{eval}} \land \tau_{\text{exec}} + U \le p.\tau_{\text{expiry}} \land \text{ApprovalUnconsumedOrReusableAsClassified}(p) \end{cases}$$

The approver acknowledges exactly the adverse claims the decision carries. An approval of a clean request cannot be reused once containment appears, and an approval of one set of claims cannot cover another.

#### 3.2 Null digests

$$\text{NULL\_APPROVAL\_DIGEST} = \mathcal{H}\left( \text{"PROVENANCE-RAZOR-NO-APPROVAL-V0.3.0-Alpha"} \right)$$

#### 3.3 Decision capability ($d$)

$d$ carries:
- domain `"PROVENANCE-RAZOR-DECISION-V0.3.0-Alpha"`, schema_ver, profile_version, lineage_schema_version;
- capability_id, req_id, evidence_snapshot_id, actor, auth_mode ∈ {AUTOMATED, MANUAL};
- $x$, $a$, target, state_ver;
- **control_profile_hash, scoring_profile_hash, trust_state_hash**, evidence_hash, lineage_hash, approval_hash;
- **adverse_disposition ∈ {CLEAR, CONTAIN}, containment_digest**;
- decision_key_id, decision_trust_epoch, **eval_clock_id**;
- $\tau_{\text{eval}}$, $\tau_{\text{expiry}}$, decision = ALLOW, and reason_codes (a non-negative bitfield).

A decision is never issued for DEFEAT or LOCK.

#### 3.4 Bidirectional authorization mode validation

$$\text{AuthorizationModeValid} \iff \begin{cases} d.\text{auth\_mode} = \text{AUTOMATED} \land x \notin \text{ManualOnly} \land d.\text{adverse\_disposition} = \text{CLEAR} \land d.\text{approval\_hash} = \text{NULL\_APPROVAL\_DIGEST} \\ \lor\; d.\text{auth\_mode} = \text{MANUAL} \land (x \in \text{ManualOnly} \lor d.\text{adverse\_disposition} = \text{CONTAIN}) \land d.\text{approval\_hash} = \mathcal{H}(p) \land \text{ExternalApprovalValid} \end{cases}$$

Consistency: $d.\text{adverse\_disposition} = \text{CLEAR} \iff d.\text{containment\_digest} = \text{NULL\_CONTAINMENT\_DIGEST}$.

#### 3.5 Decision verification predicate and clock authority (C-1)

The evaluator's clock is $d.\text{eval\_clock\_id}$. The executor's clock is $\langle\text{clock\_id}, \tau_{\text{exec}}, u_{\text{exec}}\rangle$. Both MUST be registered clock authorities in the trust state, and $u_{\text{exec}}$ MUST NOT exceed the executor authority's maximum; otherwise the result is `CLOCK_UNTRUSTED`. Every time comparison uses the combined worst-case uncertainty:

$$U = u_{\text{eval}}^{\max} + u_{\text{exec}}$$

$$\text{DecisionBindingValid} \iff \begin{cases} \text{CanonicalDecodeValid}(d) \land \text{CanonicalObjectValid}(d, \text{decision}) \land \text{Verify}_{K_{\text{decision}}}(\mathcal{H}(d), \sigma_d) \land \text{domain ok} \\ \land\; d.x = x \land d.a = a \land d.\text{target} = \text{CurrentTarget} \land d.\text{state\_ver} = \text{CurrentStateVersion} \\ \land\; d.\text{control\_profile\_hash}, d.\text{scoring\_profile\_hash}, d.\text{trust\_state\_hash} \text{ match the active objects (§2.7)} \\ \land\; d.\text{evidence\_hash} = \mathcal{H}(F_{\text{eligible}}) \land d.\text{lineage\_hash} = \mathcal{H}(D_{x,a}) \\ \land\; d.\text{adverse\_disposition}, d.\text{containment\_digest} \text{ match the current evaluation} \land d.\text{decision} = \text{ALLOW} \\ \land\; \text{ClocksTrusted} \land d.\tau_{\text{eval}} + U \le \tau_{\text{exec}} \land \tau_{\text{exec}} + U \le d.\tau_{\text{expiry}} \land (\tau_{\text{exec}} - d.\tau_{\text{eval}}) + U \le \Delta\tau_{\max} \\ \land\; \text{DecisionKeyAuthorized} \land \text{CapabilityAvailable} \land \text{AuthorizationModeValid} \end{cases}$$

Verifiers report every failing reason bit. On a decoding or schema failure, only that single bit is reported.

---

### 4. Transaction Boundaries, State Preconditions and Signed Receipts

#### 4.1 Local targets (compare-and-swap)

The transaction proceeds in this order:

1. BEGIN, then lock the target.
2. Verify CapabilityAvailable.
3. Verify CurrentStateVersion = $d$.state_ver.
4. MarkCapabilityConsumed.
5. ApplyMutation.
6. AdvanceStateVersion.
7. WriteReceipt.
8. COMMIT.

If a verification fails, the transaction rolls back and a REJECTED/PRECONDITION receipt is written in a separate transaction.

#### 4.2 Distributed targets

This section is unchanged from 0.2.0. The target enforces the state precondition. Outcomes are COMMITTED, REJECTED (PRECONDITION, TARGET or PREPARE), ROLLED_BACK (DISPATCH) or UNRESOLVED (RECONCILIATION, with reconciliation_required). A reserved capability is never released.

#### 4.3 Execution receipt ($r$)

$r$ carries:
- domain `"PROVENANCE-RAZOR-RECEIPT-V0.3.0-Alpha"`, schema_ver, receipt_id;
- capability_id, req_id, decision_digest = $\mathcal{H}(d)$, $x$, target, **control_profile_hash**;
- expected_state_ver = $d$.state_ver, observed_pre_state_ver, observed_post_state_ver (null if unknown);
- execution_status, failure_phase, reason_code, reconciliation_required;
- pre_state_digest, post_state_digest ($\mathcal{H}(\text{State}_{\text{post}})$ if known, else NULL_STATE_DIGEST);
- $\tau_{\text{dispatch}}$, $\tau_{\text{finalized}}$, receipt_key_id, receipt_trust_epoch.

The scoring profile and trust state are committed through `decision_digest`.

$$\text{NULL\_STATE\_DIGEST} = \mathcal{H}\left( \text{"PROVENANCE-RAZOR-NO-STATE-V0.3.0-Alpha"} \right)$$

---

### 5. Conformance Status

| Deliverable | Status | Location / harness |
|---|---|---|
| Normative control specification | **ALPHA**; control architecture **STABLE DRAFT** | this document |
| Canonical encoding PRC-LP-0 | **PROVISIONAL** | A-01 |
| Transport schemas | **PROVISIONAL**: Protobuf and FlatBuffers compiled, round-trip tested, strict | `schema/`, `tools/transport_roundtrip.py` |
| Scoring profile `coverage-v0.3.0-alpha` | **EXPERIMENTAL** | `tests/vectors/scoring_coverage_v0.3.0-alpha.json` |
| Superseded profiles | `jaccard-v0.1.0-alpha`, `coverage-v0.2.0-alpha` (exploit reproduces by design), `coverage-v0.2.1-alpha` | `tests/vectors/` |
| Golden, numerical, lineage, authorization, transaction vectors | **GENERATED, PROVISIONAL** | `tests/` |
| Randomised property and totality tests | P1–P6, P9–P11 hold | `tools/property_tests.py` |
| Cross-runtime conformance | **PYTHON + JAVASCRIPT**; Go / Rust / C++ pending | `tools/check_vectors.py`, `tools/xcheck.mjs` |
| Independent external verification | **PENDING** | — |

**Exploit statement.** For `coverage-v0.3.0-alpha` there is no known open exploit **under the declared assumptions**:
- the trust state (key owners, authorisations, revocations);
- the atom registry and alias authority;
- the family-membership authorities;
- the clock authorities;
- the calibration.

Each of these is an assumption, not a result. The open questions are listed in `docs/CONFORMANCE_ASSUMPTIONS.md` (Q-1 to Q-6).

---

### 6. Changes

#### 6.1 From 0.2.0-alpha to 0.3.0-alpha

| Change | Section | Closes |
|---|---|---|
| CanonicalObjectValid for $d$, $p$, $r$, $\pi$, $\mu$ and evidence members; V-1 total verification | 1.5 | validly signed malformed decisions were accepted or raised exceptions |
| Domain-scoped key resolution for every object type | 1.1 | asymmetric cross-domain diagnostics |
| Reason masks non-negative; bit 63 reserved | 1.2, 3.3 | signed/unsigned mismatch |
| Contradictions no longer change $A$; A-1 disposition CLEAR / CONTAIN / DEFEAT / LOCK; MANUAL_REQUIRED outcome | 2.2, 2.5 | Q-2 (unverified contradictions suppressing support) |
| Containment obligations deduplicated; approval must acknowledge `containment_digest` | 2.5, 3.1 | review spam; stale approvals |
| $K_{\text{membership}}$ and signed family manifests; quarantine of unlisted members | 1.1, 2.6 | Q-3 (injection into another source's family) |
| Trust state as a committed object; `control_profile_hash`, `scoring_profile_hash`, `trust_state_hash` on $d$ and $p$ | 2.7, 3 | scoring profile and registry were not bound |
| C-1 clock authorities and combined uncertainty $U$ | 3.5 | G-10 |
| Receipt `profile_hash` renamed `control_profile_hash` | 4.3 | naming ambiguity |
| FlatBuffers compiled and round-trip tested | 1.4 | transport completeness |
| Exploit statement qualified by its assumptions | 5 | overclaim |
| Domain strings move to `V0.3.0-Alpha` | all | cross-version replay |

#### 6.2 From 0.1.0-alpha to 0.2.0-alpha (summary)

- `K_provenance` and P-1 verified provenance.
- D-1 authenticated defeaters.
- Approvals bound to target, actor, req_id and capability_id (G-01 to G-03).
- Expected vs observed receipt state.
- Single encoding layer and detached signatures (G-04).
- E-1 and N-1.
- Scoring delegated to profiles (G-05).
- Transport schemas.
- The "SPECIFICATION FROZEN" status removed.
