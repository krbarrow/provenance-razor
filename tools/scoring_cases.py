"""
Scoring-profile vectors for `jaccard-v0.1.0-alpha` (EXPERIMENTAL).

Imported by tools/generate_vectors.py. Every case declares its intended decision (and,
where it matters, key intermediates); build() aborts if the reference evaluator disagrees.
"""
from __future__ import annotations

import copy
import math
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reference"))
import prc_ref as R          # noqa: E402
import prc_scoring as P      # noqa: E402

hx = P.hx


def bits(x: float) -> str:
    return hx(x)


# ---------------------------------------------------------------------------
# Calibrated profile
# ---------------------------------------------------------------------------
# Calibration target (S-09): at Γ(wire.release) = 8.5 the threshold is ≈ 0.92, and
#   three independent families scoring 0.95 / 0.90 / 0.92  -> C ≈ 0.937  ALLOW
#   the same three sharing one upstream feed (I = 1/3)      -> C ≈ 0.603  DENY
#   two independent families                                -> C ≈ 0.846  DENY
# Ω = 1.0 and T_base = 0.5; β chosen so that (1 - T_base)·exp(-8.5β) ≈ 0.08.
PROFILE = {
    "id": P.PROFILE_ID,
    "status": "experimental",
    **P.COMPONENTS,
    "material_dependency_types": ["API_ENDPOINT", "COLLECTOR", "DATABASE", "RUNTIME", "SOURCE"],
    "omega_bits": bits(1.0),
    "t_base_bits": bits(0.5),
    "beta_bits": bits(0.2156),
    "kappa_unknown_bits": bits(0.0),
    "kappa_degraded_bits": bits(0.5),
    "consequence_gamma_bits": {
        "ledger.annotate": bits(0.1),
        "payment.refund": bits(0.5),
        "wire.release": bits(8.5),
    },
}
PROFILE_NET_MATERIAL = dict(PROFILE, material_dependency_types=sorted(PROFILE["material_dependency_types"] + ["NETWORK_AS"]))

WIRE = {"action": "wire.release", "assertion": "beneficiary-verified", "target": "acct-9921",
        "amount_minor": 990000000, "currency": "USD"}
REFUND = {"action": "payment.refund", "assertion": "refund-eligible", "target": "acct-000123"}
ANNOTATE = {"action": "ledger.annotate", "assertion": "memo-accurate", "target": "acct-000123"}

SHARED_FEED = ["SOURCE:feed-core-primary", "DATABASE:aggregator-master", "COLLECTOR:aggregator-17",
               "RUNTIME:aggregator-rt"]
COMMON_NONMATERIAL = ["NETWORK_AS:13335", "TRUST_ROOT:ca-42", "CLOCK:ntp-cluster-2"]


def ev(eid, value, deps, parent=None, state=None, **extra):
    e = {"evidence_id": eid, "parent_id": parent, "value_bits": bits(value) if isinstance(value, float) else value,
         "dependencies": list(deps)}
    if state:
        e["state"] = state
    e.update(extra)
    return e


def fam(fid, *members):
    return {"family_id": fid, "members": list(members)}


def three_confirmations(correlated: bool, vendor_b_webhook_shared=None):
    """Identical apparent confirmations; only dependency atoms differ between the two variants."""
    if correlated:
        da = SHARED_FEED + ["API_ENDPOINT:vendor-a/verify-v2"]
        db = SHARED_FEED + ["API_ENDPOINT:vendor-b/confirm"]
        dw = SHARED_FEED + ["API_ENDPOINT:internal/webhook-beneficiary"]
    else:
        da = ["SOURCE:vendor-a-registry", "DATABASE:vendor-a-db", "API_ENDPOINT:vendor-a/verify-v2"]
        db = ["SOURCE:vendor-b-bureau", "DATABASE:vendor-b-db", "API_ENDPOINT:vendor-b/confirm"]
        dw = ["SOURCE:internal-kyc", "DATABASE:beneficiary-master", "API_ENDPOINT:internal/webhook-beneficiary"]
    if vendor_b_webhook_shared == "partial":  # only vendors A and B echo the shared feed
        da = SHARED_FEED + ["API_ENDPOINT:vendor-a/verify-v2"]
        db = SHARED_FEED + ["API_ENDPOINT:vendor-b/confirm"]
        dw = ["SOURCE:internal-kyc", "DATABASE:beneficiary-master", "API_ENDPOINT:internal/webhook-beneficiary"]
    return [
        fam("F-vendor-a", ev("ev-vendor-a", 0.95, da + COMMON_NONMATERIAL, attestation="sig:vendor-a:88192")),
        fam("F-vendor-b", ev("ev-vendor-b", 0.90, db + COMMON_NONMATERIAL, attestation="sig:vendor-b:55120")),
        fam("F-webhook", ev("ev-internal-webhook", 0.92, dw + COMMON_NONMATERIAL, attestation="sig:internal:30017")),
    ]


def strip_lineage(families):
    out = copy.deepcopy(families)
    for f_ in out:
        for m in f_["members"]:
            m["dependencies"] = []
    return R.encode(out)


# ---------------------------------------------------------------------------
# Boundary search: find representative values whose C lands exactly on / one ulp below T
# ---------------------------------------------------------------------------

def _single(v_bits_hex, action_req):
    return P.evaluate(action_req, [fam("F-solo", ev("ev-solo", v_bits_hex, ["SOURCE:solo-registry"]))], PROFILE)


def boundary_values(action_req):
    tr = _single(bits(0.5), action_req)
    T = P.f(tr["T_bits"])
    lo, hi = 0.0, 1.0  # C is monotone non-decreasing in V; bisect on the bit pattern
    lob, hib = R.bits_of(lo), R.bits_of(hi)
    while hib - lob > 1:
        mid = (lob + hib) // 2
        C = P.f(_single(f"{mid:016x}", action_req)["C_bits"])
        if C >= T:
            hib = mid
        else:
            lob = mid
    eq = hib
    if P.f(_single(f"{eq:016x}", action_req)["C_bits"]) != T:
        raise SystemExit("boundary search: no V gives C == T exactly")
    below = eq
    target_below = struct.unpack(">d", struct.pack(">Q", R.bits_of(T) - 1))[0]
    while P.f(_single(f"{below:016x}", action_req)["C_bits"]) > target_below:
        below -= 1
    if P.f(_single(f"{below:016x}", action_req)["C_bits"]) != target_below:
        raise SystemExit("boundary search: no V gives C == T - 1ulp exactly")
    return f"{eq:016x}", f"{below:016x}", T


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def cases():
    C = []

    def add(cid, title, request, families, expect_decision, profile=PROFILE, checks=None, finding=None,
            note=None, refs=("2.1", "2.2", "2.3")):
        C.append(dict(id=cid, title=title, request=request, families=families, profile=profile,
                      expect=expect_decision, checks=checks or {}, finding=finding, note=note, refs=list(refs)))

    # 1-6: operator semantics
    add("01_no_eligible_evidence", "No eligible evidence: M = 0, C = 0", WIRE, [], "DENY",
        checks={"M": 0.0, "C": 0.0, "reasons": ["THRESHOLD_NOT_MET", "NO_ELIGIBLE_EVIDENCE"]})
    add("02_single_family", "One family takes the singleton identity I = 1.0 (low-consequence action)", ANNOTATE,
        [fam("F1", ev("ev-1", 0.8, ["SOURCE:registry-1", "DATABASE:db-1"]))], "ALLOW", checks={"I": {"F1": 1.0}})
    add("03_identical_dependencies", "Two families with identical material dependencies: I = 0", REFUND,
        [fam("F1", ev("ev-1", 0.9, ["SOURCE:s", "DATABASE:d"])),
         fam("F2", ev("ev-2", 0.9, ["DATABASE:d", "SOURCE:s", "CLOCK:c-1"]))], "DENY",
        checks={"I": {"F1": 0.0, "F2": 0.0}, "M": 0.0},
        note="CLOCK is not a material type in this profile, so the extra atom on ev-2 is ignored.")
    add("04_disjoint_dependencies", "Two families with disjoint material dependencies: I = 1", REFUND,
        [fam("F1", ev("ev-1", 0.6, ["SOURCE:s1", "DATABASE:d1"])),
         fam("F2", ev("ev-2", 0.5, ["SOURCE:s2", "DATABASE:d2"]))], "ALLOW", checks={"I": {"F1": 1.0, "F2": 1.0}})
    add("05a_partial_overlap_half", "Partial overlap |∩|/|∪| = 2/4: I = 0.5", REFUND,
        [fam("F1", ev("ev-1", 0.9, ["SOURCE:a", "DATABASE:b", "COLLECTOR:c"])),
         fam("F2", ev("ev-2", 0.9, ["DATABASE:b", "COLLECTOR:c", "RUNTIME:d"]))], "ALLOW",
        checks={"I": {"F1": 0.5, "F2": 0.5}})
    add("05b_partial_overlap_third", "Partial overlap 1/3: I = 1 - 1/3 exactly as binary64", REFUND,
        [fam("F1", ev("ev-1", 0.9, ["SOURCE:a", "DATABASE:b"])),
         fam("F2", ev("ev-2", 0.9, ["DATABASE:b", "RUNTIME:c"]))], "ALLOW",
        checks={"I": {"F1": 1.0 - 1 / 3, "F2": 1.0 - 1 / 3}})
    add("06_unknown_lineage_fallback", "Empty material dependency set uses κ_unknown = 0.0 (unknown ≠ independent)",
        REFUND,
        [fam("F1", ev("ev-1", 0.6, ["SOURCE:s1"])), fam("F2", ev("ev-2", 0.6, ["SOURCE:s2"])),
         fam("F3", ev("ev-3", 0.6, ["NETWORK_AS:13335"]))], "DENY",
        checks={"I": {"F1": 0.0, "F2": 0.0, "F3": 0.0}, "M": 0.0},
        finding="With min-pairwise I_k, one family of unknown lineage zeroes I_k for every other family. "
                "Two independent confirmations become worth nothing because a third, unrelated item was added.")

    # 7-8: the headline pair
    add("07_three_independent_pass", "Wire: three independent high-quality confirmations", WIRE,
        three_confirmations(False), "ALLOW", checks={"I": {"F-vendor-a": 1.0, "F-vendor-b": 1.0, "F-webhook": 1.0}},
        note="Non-material atoms (NETWORK_AS, TRUST_ROOT, CLOCK) are shared by all three and ignored.")
    add("08_three_correlated_fail", "Wire: the same confirmations, all echoing one upstream feed", WIRE,
        three_confirmations(True), "DENY",
        checks={"I": {"F-vendor-a": 1.0 - 4 / 6, "F-vendor-b": 1.0 - 4 / 6, "F-webhook": 1.0 - 4 / 6},
                "reasons": ["THRESHOLD_NOT_MET"]})
    add("08b_two_of_three_correlated", "Wire: vendors A and B share the feed, the webhook is independent", WIRE,
        three_confirmations(False, "partial"), "DENY")
    add("08c_two_independent_insufficient", "Wire: only two independent confirmations", WIRE,
        [f_ for f_ in three_confirmations(False) if f_["family_id"] != "F-vendor-b"], "DENY",
        note="Calibration evidence: at Γ = 8.5 this profile needs three independent confirmations.")

    # 9-11: numeric boundaries
    eq_bits, below_bits, T_refund = boundary_values(REFUND)
    add("09_boundary_c_equals_t", "C == T exactly (bit-for-bit) must ALLOW", REFUND,
        [fam("F-solo", ev("ev-solo", eq_bits, ["SOURCE:solo-registry"]))], "ALLOW", checks={"C_equals_T": True},
        note="Representative value found by bisection over bit patterns; see `summary`.")
    add("10_boundary_one_ulp_below", "C one binary64 ulp below T must DENY", REFUND,
        [fam("F-solo", ev("ev-solo", below_bits, ["SOURCE:solo-registry"]))], "DENY",
        checks={"C_ulps_below_T": 1})
    add("11a_nan_value_faults_closed", "NaN representative value -> Safe State Lock", ANNOTATE,
        [fam("F1", ev("ev-1", "7ff8000000000000", ["SOURCE:s1"])), fam("F2", ev("ev-2", 0.9, ["SOURCE:s2"]))], "DENY",
        checks={"lock": True, "C": 0.0})
    add("11b_inf_value_faults_closed", "+Inf representative value -> Safe State Lock (not 'infinitely confident')",
        ANNOTATE, [fam("F1", ev("ev-1", "7ff0000000000000", ["SOURCE:s1"]))], "DENY", checks={"lock": True, "C": 0.0},
        note="Without an explicit guard, exp(-Inf) = 0 would give C = 1.0 and ALLOW.")
    add("11c_undefined_consequence_class", "Action with no consequence class -> T undefined -> fault closed",
        {"action": "treasury.sweep", "assertion": "x"}, three_confirmations(False), "DENY",
        checks={"lock": True, "reasons": ["SAFE_STATE_LOCK", "CONSEQUENCE_CLASS_UNDEFINED"]})

    # 12-14: invariances (the generator proves each against its base case)
    base12 = three_confirmations(True) + [fam("F-memo", ev("ev-memo-root", 0.7, ["SOURCE:memo"]),
                                               ev("ev-memo-derived", 0.7, ["SOURCE:memo", "RUNTIME:m"],
                                                  parent="ev-memo-root", state="DEGRADED"))]
    perm = copy.deepcopy(base12)
    random.Random(12).shuffle(perm)
    for f_ in perm:
        f_["members"].reverse()
        for m in f_["members"]:
            m["dependencies"].reverse()
    add("12_permutation_invariance", "Shuffled families, members and dependency lists: identical output bits", WIRE,
        perm, "DENY", checks={"same_trace_as": base12})
    dup = copy.deepcopy(C[3]["families"])  # case 04
    for f_ in dup:
        for m in f_["members"]:
            m["dependencies"] = m["dependencies"] + m["dependencies"][:1]
    add("13_duplicate_atoms", "Duplicate dependency atoms do not change Jaccard (or digests)", REFUND, dup, "ALLOW",
        checks={"same_trace_as": C[3]["families"]})
    root = ev("ev-root", 0.9, ["SOURCE:reg"])
    variants = []
    for nonce in range(1000):
        d = ev("ev-derived", 0.9, ["SOURCE:reg", "COLLECTOR:c"], parent="ev-root", state="VALID", revision=nonce)
        variants.append((P.canonical_digest(d) > P.canonical_digest(root), d))
    hi_d = next(d for gt, d in variants if gt)
    lo_d = next(d for gt, d in variants if not gt)
    add("14a_digest_not_selection_hi", "Derivative with a digest above the root's does not become representative",
        ANNOTATE, [fam("F1", copy.deepcopy(root), hi_d)], "ALLOW", checks={"representative": {"F1": "ev-root"}})
    add("14b_digest_not_selection_lo", "Same family, derivative digest below the root's: same representative", ANNOTATE,
        [fam("F1", copy.deepcopy(root), lo_d)], "ALLOW", checks={"representative": {"F1": "ev-root"},
                                                                  "same_decision_values_as": "14a_digest_not_selection_hi"})

    # structure & findings
    add("15_malformed_two_roots", "Two parentless roots in one class -> class malformed, excluded, audited", ANNOTATE,
        [fam("F1", ev("ev-a", 0.9, ["SOURCE:a"]), ev("ev-b", 0.9, ["SOURCE:b"])),
         fam("F2", ev("ev-c", 0.8, ["SOURCE:c"]))], "ALLOW",
        checks={"reasons": ["LINEAGE_CLASS_MALFORMED"], "eligible": ["F2"]},
        note="Exclusion (not global deny) is chosen so a malformed class can lower C but cannot block on its own (S-02).")
    add("16_malformed_cycle", "Parent-link cycle inside a class -> malformed", ANNOTATE,
        [fam("F1", ev("ev-r", 0.9, ["SOURCE:r"]), ev("ev-x", 0.9, ["SOURCE:r"], parent="ev-y"),
             ev("ev-y", 0.9, ["SOURCE:r"], parent="ev-x"))], "DENY",
        checks={"reasons": ["THRESHOLD_NOT_MET", "NO_ELIGIBLE_EVIDENCE", "LINEAGE_CLASS_MALFORMED"]})
    add("17_non_monotonic_mass", "Adding a fourth confirmation (a mirror of vendor A) flips ALLOW to DENY", WIRE,
        three_confirmations(False) + [fam("F-vendor-a-mirror", ev("ev-vendor-a-mirror", 0.90,
                                          ["SOURCE:vendor-a-registry", "DATABASE:vendor-a-db",
                                           "API_ENDPOINT:vendor-a/verify-v2"]))], "DENY",
        checks={"I": {"F-vendor-a": 0.0, "F-vendor-a-mirror": 0.0}},
        finding="Min-pairwise I_k makes M non-monotone: a redundant confirmation zeroes the independence of the "
                "family it duplicates, so M drops from 2.77 to 1.82. Redundant evidence should add ~0, not subtract.")
    add("18_material_type_sensitivity", "Case 07 with NETWORK_AS declared material: the shared AS flips the decision",
        WIRE, three_confirmations(False), "DENY", profile=PROFILE_NET_MATERIAL,
        checks={"I": {"F-vendor-a": 1.0 - 1 / 7}},
        finding="Which dependency types are material is decisive. Nominating NETWORK_AS makes a shared CDN "
                "look like shared provenance; that choice needs justification, not a default.")
    add("19_degraded_member", "Case 07 with a DEGRADED derivative in vendor A's family (κ = 0.5)", WIRE,
        [fam("F-vendor-a", *(three_confirmations(False)[0]["members"] +
                             [ev("ev-vendor-a-cache", 0.95, ["SOURCE:vendor-a-registry", "RUNTIME:cdn-edge"],
                                 parent="ev-vendor-a", state="DEGRADED")]))] + three_confirmations(False)[1:],
        "DENY")
    add("20_value_out_of_range", "Representative value 1.2 is outside [0, 1] -> class malformed", ANNOTATE,
        [fam("F1", ev("ev-1", 1.2, ["SOURCE:a"])), fam("F2", ev("ev-2", 0.8, ["SOURCE:b"]))], "ALLOW",
        checks={"reasons": ["LINEAGE_CLASS_MALFORMED"], "eligible": ["F2"]})
    return C


# ---------------------------------------------------------------------------
# prc-exp-v1 primitive vectors
# ---------------------------------------------------------------------------
EXP_INPUTS = [0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 1e-300, -1e-300, math.log(2), -math.log(2),
              -0.3695, -0.18475, -2.77, -1.8326, -0.1078, -0.02156,
              -27.046689406673504,  # a value where V8 Math.exp and glibc exp disagree by 1 ulp
              -40.0, -100.0, -700.0, -708.5, -709.0, -744.0, -745.0, -745.1, -1000.0,
              700.0, 709.0, 709.5, math.inf, -math.inf, math.nan]


# Published libm exp() bits for EXP_INPUTS, informative only (the normative value is prc_exp). Frozen from the
# committed 0.3.0-alpha vectors so regeneration doesn't depend on the host's libm (glibc 2.41, for one, returns
# ...f576 for -27.046689406673504). check_vectors.py reports where the host's libm differs.
PUBLISHED_LIBM_EXP_BITS = {
    "0000000000000000": "3ff0000000000000",  # 0.0
    "8000000000000000": "3ff0000000000000",  # -0.0
    "3ff0000000000000": "4005bf0a8b145769",  # 1.0
    "bff0000000000000": "3fd78b56362cef38",  # -1.0
    "3fe0000000000000": "3ffa61298e1e069c",  # 0.5
    "bfe0000000000000": "3fe368b2fc6f960a",  # -0.5
    "01a56e1fc2f8f359": "3ff0000000000000",  # 1e-300
    "81a56e1fc2f8f359": "3ff0000000000000",  # -1e-300
    "3fe62e42fefa39ef": "4000000000000000",  # 0.6931471805599453
    "bfe62e42fefa39ef": "3fe0000000000000",  # -0.6931471805599453
    "bfd7a5e353f7ced9": "3fe61d5359fc72ec",  # -0.3695
    "bfc7a5e353f7ced9": "3fea9a1bcdb65856",  # -0.18475
    "c00628f5c28f5c29": "3fb00a9dfd11c093",  # -2.77
    "bffd525460aa64c3": "3fc47ac866bb3ff3",  # -1.8326
    "bfbb98c7e28240b8": "3fecbad60a0005bb",  # -0.1078
    "bf9613d31b9b66f9": "3fef514555085f8f",  # -0.02156
    "c03b0bf3d642bb7b": "3d7f8e852733f577",  # -27.046689406673504
    "c044000000000000": "3c539792499b1a24",  # -40.0
    "c059000000000000": "36ea8c1f14e2af5d",  # -100.0
    "c085e00000000000": "00d14f2b0fb9307f",  # -700.0
    "c086240000000000": "000e6cf6d08897ac",  # -708.5
    "c086280000000000": "0008bfe55de02338",  # -709.0
    "c087400000000000": "0000000000000002",  # -744.0
    "c087480000000000": "0000000000000001",  # -745.0
    "c08748cccccccccd": "0000000000000001",  # -745.1
    "c08f400000000000": "0000000000000000",  # -1000.0
    "4085e00000000000": "7f0d945df4f8ec8e",  # 700.0
    "4086280000000000": "7fdd422d2be5dc9b",  # 709.0
    "40862c0000000000": "7fe81e9b4b52d0c9",  # 709.5
    "7ff0000000000000": "7ff0000000000000",  # inf
    "fff0000000000000": "0000000000000000",  # -inf
    "7ff8000000000000": "7ff8000000000000",  # nan
}


def exp_vectors():
    out = []
    for x in EXP_INPUTS:
        y = P.prc_exp(x)
        out.append({"input_bits": hx(x), "input_repr": repr(x), "expected_bits": hx(y), "expected_repr": repr(y),
                    "libm_exp_bits_informative": PUBLISHED_LIBM_EXP_BITS[hx(x)]})
    return out


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _num(b):
    return P.f(b)


def build():
    all_cases = cases()
    by_id = {}
    out = []
    for c in all_cases:
        tr = P.evaluate(c["request"], c["families"], c["profile"])
        if tr["decision"] != c["expect"]:
            raise SystemExit(f"scoring {c['id']}: evaluator says {tr['decision']} ({tr['reason_codes']}), "
                             f"case declares {c['expect']}")
        ck = c["checks"]
        fams = tr["families"]
        if "M" in ck and _num(tr["M_bits"]) != ck["M"]:
            raise SystemExit(f"scoring {c['id']}: M = {_num(tr['M_bits'])}")
        if "C" in ck and _num(tr["C_bits"]) != ck["C"]:
            raise SystemExit(f"scoring {c['id']}: C = {_num(tr['C_bits'])}")
        for k, v in ck.get("I", {}).items():
            if _num(fams[k]["I_bits"]) != v:
                raise SystemExit(f"scoring {c['id']}: I[{k}] = {_num(fams[k]['I_bits'])} != {v}")
        if "reasons" in ck and sorted(tr["reason_codes"]) != sorted(ck["reasons"]):
            raise SystemExit(f"scoring {c['id']}: reasons {tr['reason_codes']}")
        if "lock" in ck and tr["safe_state_lock"] != ck["lock"]:
            raise SystemExit(f"scoring {c['id']}: lock")
        if "eligible" in ck and tr["eligible_families"] != ck["eligible"]:
            raise SystemExit(f"scoring {c['id']}: eligible {tr['eligible_families']}")
        for k, v in ck.get("representative", {}).items():
            if fams[k]["representative"] != v:
                raise SystemExit(f"scoring {c['id']}: representative")
        if ck.get("C_equals_T") and tr["C_bits"] != tr["T_bits"]:
            raise SystemExit(f"scoring {c['id']}: C != T")
        if "C_ulps_below_T" in ck and int(tr["T_bits"], 16) - int(tr["C_bits"], 16) != ck["C_ulps_below_T"]:
            raise SystemExit(f"scoring {c['id']}: ulp distance")
        if "same_trace_as" in ck:
            base = P.evaluate(c["request"], ck["same_trace_as"], c["profile"])
            if R.encode(base) != R.encode(tr):
                raise SystemExit(f"scoring {c['id']}: trace differs from its base case")
        if "same_decision_values_as" in ck:
            o = by_id[ck["same_decision_values_as"]]
            if (o["M_bits"], o["C_bits"], o["T_bits"], o["decision"]) != (tr["M_bits"], tr["C_bits"], tr["T_bits"], tr["decision"]):
                raise SystemExit(f"scoring {c['id']}: values differ from {ck['same_decision_values_as']}")
        by_id[c["id"]] = tr
        v = {
            "id": c["id"], "title": c["title"], "spec_refs": c["refs"],
            "profile": "calibrated" if c["profile"] is PROFILE else "calibrated+NETWORK_AS-material",
            "input": {"request": c["request"], "families": c["families"]},
            "expected_trace": tr,
            "summary": {
                "decision": tr["decision"],
                "M": repr(_num(tr["M_bits"])), "C": repr(_num(tr["C_bits"])), "T": repr(_num(tr["T_bits"])),
                "I": {k: repr(_num(x["I_bits"])) for k, x in fams.items() if "I_bits" in x},
            },
        }
        if c["note"]:
            v["note"] = c["note"]
        if c["finding"]:
            v["finding"] = c["finding"]
        out.append(v)

    # The headline claim: same apparent confirmations, only lineage differs, decision flips.
    a, b = cases()[7], cases()[8]
    assert a["id"].startswith("07") and b["id"].startswith("08")
    if strip_lineage(a["families"]) != strip_lineage(b["families"]) or a["request"] != b["request"]:
        raise SystemExit("headline pair differs in something other than dependency atoms")
    headline = {
        "claim": "With identical apparent confirmations and identical authorization context, changing only the "
                 "evidence-lineage graph produces a reproducible ALLOW -> DENY transition at a consequence-"
                 "calibrated boundary.",
        "allow_case": "07_three_independent_pass", "deny_case": "08_three_correlated_fail",
        "inputs_identical_except_dependencies": True,
        "stripped_inputs_sha256": R.H_bytes(strip_lineage(a["families"])),
        "allow": out[7]["summary"], "deny": out[8]["summary"],
    }

    # Informative calibration table (not normative).
    calib = {"T_by_action": {}, "C_for_n_independent_families_at_0.9": {}}
    for act in PROFILE["consequence_gamma_bits"]:
        tr = P.evaluate({"action": act}, [], PROFILE)
        calib["T_by_action"][act] = repr(_num(tr["T_bits"]))
    for n in range(1, 7):
        fs = [fam(f"F{i}", ev(f"ev-{i}", 0.9, [f"SOURCE:s{i}"])) for i in range(n)]
        tr = P.evaluate(WIRE, fs, PROFILE)
        calib["C_for_n_independent_families_at_0.9"][str(n)] = f"{repr(_num(tr['C_bits']))} -> {tr['decision']} (wire)"

    return {
        "vector_set": "scoring-profile",
        "scoring_profile": P.PROFILE_ID,
        "status": "EXPERIMENTAL — reference candidate, replaceable; not part of the frozen control architecture",
        "spec_version": R.SPEC_VERSION,
        "assumptions": "docs/SCORING_PROFILE_jaccard-v0.1.0-alpha.md",
        "profiles": {
            "calibrated": {"declaration": PROFILE, "fingerprint": R.H(PROFILE)},
            "calibrated+NETWORK_AS-material": {"declaration": PROFILE_NET_MATERIAL, "fingerprint": R.H(PROFILE_NET_MATERIAL)},
        },
        "prc_exp_v1": {
            "algorithm": "k = floor(x*INV_LN2 + 0.5); r = (x - k*LN2_HI) - k*LN2_LO; p = Horner(c13..c0, r); "
                         "return p * 2^k (two-step scaling outside [-1022, 1023]); "
                         "x > 709 -> +Inf, x < -745 -> 0, NaN -> NaN. No FMA contraction.",
            "constants_bits": {"INV_LN2": hx(P.EXP_INV_LN2), "LN2_HI": hx(P.EXP_LN2_HI), "LN2_LO": hx(P.EXP_LN2_LO),
                               "C0..C13": P.EXP_COEFF_BITS},
            "vectors": exp_vectors(),
        },
        "headline": headline,
        "calibration_informative": calib,
        "cases": out,
    }
