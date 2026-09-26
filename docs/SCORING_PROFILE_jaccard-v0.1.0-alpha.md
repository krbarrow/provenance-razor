# PRC Scoring Profile `jaccard-v0.1.0-alpha`

> **Superseded for mass computation by `coverage-v0.2.0-alpha`** (docs/SCORING_PROFILE_coverage-v0.2.0-alpha.md), which fixes F-2 and F-3. This profile and its vectors are kept frozen as the evidence that motivated the change.

```yaml
scoring-profile:
  id: jaccard-v0.1.0-alpha
  status: experimental
  normative-role: reference candidate (replaceable)
  canonical-representative: structural-root-v1
  independence-function: material-dependency-jaccard-v1
  mass-function: quality-weighted-independent-mass-v1
  confidence-function: exponential-saturation-v1
  threshold-function: consequence-exponential-v1
  exp-function: prc-exp-v1
  summation-order: representative-evidence-id-utf8-ascending
```

The control architecture should require *a* deterministic scoring profile, identified by id and by fingerprint `H(profile)`. This is the first candidate. Its job is to produce evidence about the model. It is not settled, and nothing here belongs in the frozen core yet.

- Reference: `reference/prc_scoring.py` (pure functions; no signing, CAS or receipts)
- Vectors: `tests/vectors/scoring_jaccard_v0.1.0-alpha.json` (26 scoring cases + 32 `prc-exp-v1` vectors)
- Independent JavaScript implementation: the "scoring" block in `tools/xcheck.mjs`

## Success criterion — met

> With identical apparent confirmations and identical authorization context, changing only the evidence-lineage graph produces a reproducible ALLOW → DENY transition at a consequence-calibrated boundary.

| Case | Lineage | I per family | M | C | T (wire, Γ = 8.5) | Decision |
|---|---|---|---|---|---|---|
| `07_three_independent_pass` | disjoint material dependencies | 1, 1, 1 | 2.77 | 0.93734 | 0.92000 | **ALLOW** |
| `08_three_correlated_fail` | all three share one upstream feed | ⅓, ⅓, ⅓ | 0.92333 | 0.60281 | 0.92000 | **DENY** |
| `08b_two_of_three_correlated` | vendors A and B share the feed | ⅓, ⅓, 1 | 1.53667 | 0.78490 | 0.92000 | DENY |
| `08c_two_independent_insufficient` | two disjoint confirmations | 1, 1 | 1.87 | 0.84588 | 0.92000 | DENY |

The generator and both checkers verify that cases 07 and 08 are **byte-identical once dependency atoms are removed**: same evidence ids, scores, attestations, request and profile. They produce the same bits in Python and in the independent JavaScript implementation.

## Definitions

All arithmetic is binary64, uses only `+ − × ÷` (correctly rounded) and exact power-of-two scaling, and has no FMA contraction.

**Representative (structural-root-v1).** A family must have exactly one *root*: a member whose `parent_id` is null or points outside the family. Every other member must reach the root through in-family parents without a cycle. `F*_k` is that root. Digest order is never used for selection. Zero roots, two or more roots, a cycle, a duplicate id or an unknown atom type make the class **MALFORMED** (S-02).

**Dependency atoms.** Typed strings `TYPE:value`, where `TYPE` is one of `SOURCE, DATABASE, COLLECTOR, RUNTIME, CLOCK, NETWORK_AS, TRUST_ROOT, API_ENDPOINT`. Atoms form a set, so duplicates and order are irrelevant. The compiled profile nominates which types are **material**; only those count. Here the material types are `SOURCE, DATABASE, COLLECTOR, RUNTIME, API_ENDPOINT`. `D_k` is the representative's set of material atoms.

**Independence (material-dependency-jaccard-v1).**

$$I(\bar F_k\mid\bar F_j)=\begin{cases}\kappa_{\text{unknown}} & D_k=\varnothing \lor D_j=\varnothing\\[2pt] 1-\dfrac{|D_k\cap D_j|}{|D_k\cup D_j|} & \text{otherwise}\end{cases}\qquad I_k=\begin{cases}1 & m=1\\ \min_{j\ne k} I(\bar F_k\mid\bar F_j) & m>1\end{cases}$$

The quotient is an int÷int correctly rounded division. The empty-union case is covered by the first branch.

**Class value.** `V(F̄_k) = V(F*_k) · A(F̄_k)`, using the §2.2 state rules (A-08). `V(F*)` must be finite and in [0, 1]; a finite value outside that range makes the class MALFORMED (S-08).

**Mass (quality-weighted-independent-mass-v1).** `M = Σ V(F̄_k) · I_k`, summed left to right with families in ascending UTF-8 order of representative `evidence_id` (S-06). Fixing the order is what makes the result permutation-invariant bit for bit.

**Confidence (exponential-saturation-v1).** `C = 1 − prc_exp(−(M / Ω))`. If M is NaN or ±Inf, C is NaN, which triggers the §2.3 Safe State Lock. Without this guard, `+Inf` would give `exp(−Inf) = 0` and therefore `C = 1` (case `11b`).

**Threshold (consequence-exponential-v1).** `T = 1 − (1 − T_base) · prc_exp(−(Γ(x) · β))`, with `T_base ∈ [0.5, 1)` and `Γ ∈ [0.1, 10]`. An action with no consequence class gets `T = NaN`, which faults closed (`CONSEQUENCE_CLASS_UNDEFINED`).

**Check.** This is the existing §2.3 `AuthorizationCheck(C, T)`.

**prc-exp-v1.**
1. `k = floor(x·INV_LN2 + 0.5)`
2. `r = (x − k·LN2_HI) − k·LN2_LO` (Cody–Waite reduction; `LN2_HI` has 21 trailing zero bits, so `k·LN2_HI` is exact)
3. Horner evaluation of the degree-13 Taylor polynomial with coefficients `1/n!`
4. Multiply by an exact `2^k` built from its bit pattern, in two steps outside [−1022, 1023]
5. Special cases: `x > 709 → +Inf`, `x < −745 → 0`, `NaN → NaN`

It is within 1 ulp of glibc `exp` across 197k samples. It is not correctly rounded, but it gives the same bits on every conforming runtime. All constants are published as bit patterns in the vector file.

### Calibrated parameters

| Parameter | Value |
|---|---|
| Ω | 1.0 |
| T_base | 0.5 |
| β | 0.2156 |
| κ_unknown | 0.0 |
| κ_degraded | 0.5 |
| Γ(ledger.annotate) | 0.1 |
| Γ(payment.refund) | 0.5 |
| Γ(wire.release) | 8.5 |

Resulting thresholds: T(annotate) = 0.5107, T(refund) = 0.5511, T(wire) = 0.9200.

At Γ = 8.5, confidence from *n* independent families each scoring 0.9:

| n | C | Wire decision |
|---|---|---|
| 1 | 0.593 | DENY |
| 2 | 0.835 | DENY |
| 3 | 0.933 | ALLOW |
| 4–6 | ≥ 0.973 | ALLOW |

So this profile's policy is that a $9.9M wire needs three independent confirmations. That was chosen deliberately (S-09). Your worked example's Ω = 2 would have required about six independent confirmations; with Ω = 2 even three fully independent ones reach only 0.750.

C is a calibrated *score*, not a probability. Nothing yet shows that these numbers correspond to real risk. That calibration is the open research question.

## Findings — where the model needs work

**F-1: Platform `exp` breaks bit-exact authorization.**

- V8's `Math.exp` and glibc's `exp` disagree by 1 ulp on about 10% of inputs in [−40, 0] (19,543 of 200,000 sampled).
- Evaluated with platform `exp` on the same inputs, case `10_boundary_one_ulp_below` is **ALLOW in Python/glibc and DENY in Node/V8**.

§2.3 demands bit-exact comparison without tolerance, so any profile that uses transcendental functions must specify the algorithm. This is what `prc-exp-v1` does. The finding belongs in the normative core as a rule: *scoring profiles must use only basic IEEE operations or profile-specified algorithms.*

**F-2: Mass is non-monotone in evidence** (case `17`).

Adding a fourth confirmation that mirrors vendor A's lineage zeroes both A's and the mirror's I_k under the min rule. M drops from 2.77 to 1.82, and the decision flips from ALLOW to DENY. A redundant confirmation should add roughly nothing; it should not subtract. The min-pairwise `I_k` comes from §2.1 itself. Candidate fixes:
- cluster families by lineage and give each cluster one unit of mass; or
- discount sequentially in canonical order, so only later duplicates are reduced.

**F-3: Unknown lineage poisons the whole set** (case `06`).

With κ_unknown = 0, a single family with no declared material dependencies makes `I_k = 0` for *every* family. That is a denial-of-service lever: anyone who can inject one unattributed evidence item can block an action. It follows from F-2's min rule combined with a conservative κ. Excluding unknown-lineage families from the pairwise reduction, and capping their own contribution, would avoid it.

**F-4: The choice of material types decides outcomes** (case `18`).

Declaring `NETWORK_AS` material makes three vendors behind one CDN look like shared provenance. I drops to 6/7, C to 0.9069, and the decision flips to DENY. Which types are material must be a justified, reviewed profile choice.

**F-5: A single family always gets I = 1** (§2.1 singleton identity), even when its lineage is unknown. It is harmless at high Γ, since one family can't pass there, but worth stating.

## Assumptions (S-xx)

- **S-01** Families (equivalence classes) are supplied as input. How raw evidence is partitioned into classes is out of scope for this profile.
- **S-02** A malformed class is excluded and audited (`LINEAGE_CLASS_MALFORMED`) rather than denying the whole evaluation. Exclusion can only lower C, so it is safe, and it stops one malformed item from blocking everything. Your security policy may prefer global deny; that is a profile switch.
- **S-03** D_k is the *representative's* material atoms, following the formula. Derivatives' atoms are ignored for independence.
- **S-04** κ_unknown applies when either set is empty. There is no division by an empty union.
- **S-05** A representative whose state is not VALID gives no positive support. `INVALID` invalidates the family (G-12).
- **S-06** The canonical summation order is representative `evidence_id`, ascending by UTF-8 bytes. Min is order-independent anyway.
- **S-07** No platform transcendental functions (F-1).
- **S-08** Quality scores are in [0, 1]. NaN and ±Inf fault closed; other out-of-range values make the class malformed.
- **S-09** The calibration above is a policy choice made to demonstrate the lineage flip, not a validated risk model.

## On the comparison with OPA and Cedar

OPA and Cedar are general-purpose policy engines. An application can feed either one a lineage graph, or a precomputed score, and enforce the same decision. So the distinction isn't that they *can't* do this. What the Provenance Razor adds is a **normative, deterministic preprocessing and execution-control model**. It specifies how to derive action-specific confidence from evidence lineage, compares it with a consequence-calibrated threshold, and binds the result (via `evidence_hash`, `lineage_hash` and the profile fingerprint) into a consumable execution capability.

The value lies in the specification being exact, reproducible across runtimes and auditable. The findings above show those properties aren't automatic, which is exactly why they need specifying.

## Suggested status block for the spec

```
[CONTROL ARCHITECTURE STABLE]    subject to G-01..G-03 (approval target/time/actor binding) being closed
[SCORING PROFILE EXPERIMENTAL]   jaccard-v0.1.0-alpha — F-2 and F-3 open
```
