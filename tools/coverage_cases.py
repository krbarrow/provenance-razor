"""
Vectors for scoring profile `coverage-v0.2.0-alpha` (EXPERIMENTAL) and the engine guard (E-1).

Imported by tools/generate_vectors.py. Each case declares its intended decision and the
invariant it demonstrates; build() aborts if the reference engine disagrees.
Randomised property witnesses use a SHA-256 counter PRNG so they regenerate byte-for-byte.
"""
from __future__ import annotations

import copy
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reference"))
import prc_ref as R            # noqa: E402
import prc_scoring as S        # noqa: E402
import prc_coverage as COV     # noqa: E402
import prc_engine as ENG       # noqa: E402
import scoring_cases as J      # noqa: E402  (shared evidence builders; jaccard vectors stay untouched)

bits, ev, fam = J.bits, J.ev, J.fam
WIRE, REFUND, ANNOTATE = J.WIRE, J.REFUND, J.ANNOTATE

PROFILE = {
    "id": COV.PROFILE_ID,
    "status": "experimental",
    **COV.COMPONENTS,
    "material_dependency_types": J.PROFILE["material_dependency_types"],
    "omega_bits": bits(1.0),
    "t_base_bits": bits(0.5),
    "beta_bits": bits(0.2156),
    "kappa_unknown_bits": bits(0.5),
    "kappa_degraded_bits": bits(0.5),
    "unknown_gate_t_bits": bits(0.92),
    "consequence_gamma_bits": J.PROFILE["consequence_gamma_bits"],
}


class DRng:
    """Deterministic PRNG: SHA-256 over (seed, counter). Independent of the Python version."""

    def __init__(self, seed: str):
        self.seed, self.n = seed, 0

    def u64(self) -> int:
        self.n += 1
        return int.from_bytes(hashlib.sha256(f"{self.seed}|{self.n}".encode()).digest()[:8], "big")

    def below(self, k: int) -> int:
        return self.u64() % k

    def unit(self) -> float:  # multiple of 2^-10 in [0, 1] — exact, readable values
        return self.below(1025) / 1024.0

    def pick(self, seq):
        return seq[self.below(len(seq))]


ATOM_POOL = [f"{t}:{v}" for t in ("SOURCE", "DATABASE", "COLLECTOR", "RUNTIME", "API_ENDPOINT")
             for v in ("p", "q", "r")] + ["NETWORK_AS:13335", "TRUST_ROOT:ca-42"]


def random_family(rng: DRng, fid: str) -> dict:
    n = rng.below(5)  # 0 atoms -> unknown lineage
    deps = sorted({rng.pick(ATOM_POOL) for _ in range(n)})
    members = [ev(f"ev-{fid}", rng.unit(), deps)]
    if rng.below(3) == 0:
        members.append(ev(f"ev-{fid}-d", rng.unit(), deps[:1], parent=f"ev-{fid}",
                          state=rng.pick(["VALID", "DEGRADED", "UNAVAILABLE_OR_STALE"])))
    return fam(fid, *members)


def rename_family(f_: dict, new_fid: str) -> dict:
    """Exact structural duplicate under fresh ids (parent links remapped)."""
    ids = {m["evidence_id"]: f"{m['evidence_id']}@{new_fid}" for m in f_["members"]}
    members = []
    for m in f_["members"]:
        n = copy.deepcopy(m)
        n["evidence_id"] = ids[m["evidence_id"]]
        if n.get("parent_id") in ids:
            n["parent_id"] = ids[n["parent_id"]]
        members.append(n)
    return {"family_id": new_fid, "members": members}


def M_of(tr) -> float:
    return S.f(tr["M_bits"])


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def cases():
    C = []

    def add(cid, title, request, families, expect, checks=None, note=None, profile=PROFILE, **extra):
        C.append(dict(id=cid, title=title, request=request, families=families, expect=expect,
                      checks=checks or {}, note=note, profile=profile, **extra))

    ind, cor, part = J.three_confirmations(False), J.three_confirmations(True), J.three_confirmations(False, "partial")
    add("c01_no_eligible_evidence", "No eligible evidence: M = 0, C = 0", WIRE, [], "DENY", {"M": 0.0})
    add("c02_single_family", "One family, low-consequence action", ANNOTATE,
        [fam("F1", ev("ev-1", 0.8, ["SOURCE:registry-1", "DATABASE:db-1"]))], "ALLOW", {"M": 0.8})
    add("c03_three_independent_pass", "Wire: three independent confirmations", WIRE, ind, "ALLOW")
    add("c04_three_correlated_fail", "Wire: the same confirmations sharing one upstream feed", WIRE, cor, "DENY")
    add("c05_two_of_three_correlated", "Wire: vendors A and B share the feed", WIRE, part, "DENY")
    add("c06_two_independent_insufficient", "Wire: only two independent confirmations", WIRE,
        [x for x in ind if x["family_id"] != "F-vendor-b"], "DENY")
    mirror = ind + [fam("F-vendor-a-mirror", ev("ev-vendor-a-mirror", 0.90,
                                                  ["SOURCE:vendor-a-registry", "DATABASE:vendor-a-db",
                                                   "API_ENDPOINT:vendor-a/verify-v2"]))]
    add("c07_mirror_added_neutral", "Fix for F-2: a mirror of vendor A adds nothing and cannot flip ALLOW",
        WIRE, mirror, "ALLOW", {"same_M_as": "c03_three_independent_pass"})
    bridge = ind + [fam("F-bridge", ev("ev-bridge", 0.10, ["SOURCE:vendor-a-registry", "SOURCE:vendor-b-bureau",
                                                            "SOURCE:internal-kyc"]))]
    add("c08_bridge_added_neutral", "A bridging item touching all three sources cannot merge or dilute them",
        WIRE, bridge, "ALLOW", {"same_M_as": "c03_three_independent_pass"})
    add("c09_unknown_at_high_consequence", "Fix for F-3: unattributed item on a wire (T ≥ gate, κ = 0) is neutral",
        WIRE, cor + [fam("F-unattributed", ev("ev-unattributed", 1.0, ["NETWORK_AS:13335"]))], "DENY",
        {"same_M_as": "c04_three_correlated_fail", "kappa_effective": 0.0})
    base10 = [fam("F1", ev("ev-1", 0.6, ["SOURCE:s1"]))]
    add("c10a_refund_known_only", "Refund: one attributed family alone", REFUND, base10, "DENY", {"M": 0.6})
    add("c10b_unknown_at_low_consequence", "Refund (T < gate): unattributed item contributes V·κ once", REFUND,
        base10 + [fam("F-u1", ev("ev-u1", 0.9, []))], "ALLOW", {"M": 0.6 + 0.45, "kappa_effective": 0.5})
    spam = base10 + [fam(f"F-u{i}", ev(f"ev-u{i}", 0.9, [])) for i in range(1, 21)]
    add("c11_unknown_spam_single_sink", "Twenty unattributed items share one UNKNOWN sink: same M as one", REFUND,
        spam, "ALLOW", {"same_M_as": "c10b_unknown_at_low_consequence"})
    dup = base10 + [fam("F1-dup", ev("ev-1-dup", 0.6, ["SOURCE:s1"]))]
    add("c12_duplicate_idempotent", "Exact duplicate (same atoms, same value) leaves M bit-identical", REFUND,
        dup, "DENY", {"same_M_as": "c10a_refund_known_only"})
    base13 = cor + [fam("F-memo", ev("ev-memo-root", 0.7, ["SOURCE:memo"]),
                        ev("ev-memo-derived", 0.7, ["SOURCE:memo", "RUNTIME:m"], parent="ev-memo-root", state="DEGRADED"))]
    perm = copy.deepcopy(base13)
    rng = DRng("c13")
    for i in range(len(perm) - 1, 0, -1):
        j = rng.below(i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    for f_ in perm:
        f_["members"].reverse()
        for m in f_["members"]:
            m["dependencies"].reverse()
    add("c13_permutation_invariance", "Shuffled families, members and atom lists: identical output bits", WIRE, perm,
        "DENY", {"same_trace_as": base13})
    add("c14_degraded_member", "DEGRADED optional member halves vendor A's value", WIRE,
        [fam("F-vendor-a", *(ind[0]["members"] + [ev("ev-vendor-a-cache", 0.95, ["SOURCE:vendor-a-registry"],
                                                     parent="ev-vendor-a", state="DEGRADED")]))] + ind[1:], "DENY")
    add("c15_malformed_class_excluded", "Two roots in one class: excluded and audited, others still count", ANNOTATE,
        [fam("F1", ev("ev-a", 0.9, ["SOURCE:a"]), ev("ev-b", 0.9, ["SOURCE:b"])),
         fam("F2", ev("ev-c", 0.8, ["SOURCE:c"]))], "ALLOW", {"reasons": ["LINEAGE_CLASS_MALFORMED"]})
    add("c16_undefined_consequence", "Action without a consequence class faults closed", {"action": "treasury.sweep"},
        ind, "DENY", {"reasons": ["SAFE_STATE_LOCK", "CONSEQUENCE_CLASS_UNDEFINED"]})
    eqb, belowb = boundary_values()
    add("c17_boundary_c_equals_t", "C == T exactly must ALLOW", REFUND,
        [fam("F-solo", ev("ev-solo", eqb, ["SOURCE:solo"]))], "ALLOW", {"C_equals_T": True})
    add("c18_boundary_one_ulp_below", "C one ulp below T must DENY", REFUND,
        [fam("F-solo", ev("ev-solo", belowb, ["SOURCE:solo"]))], "DENY", {"C_ulps_below_T": 1})

    # engine guard (E-1): profile code is never reached
    add("e01_nan_representative", "Engine guard: NaN representative value", ANNOTATE,
        [fam("F1", ev("ev-1", "7ff8000000000000", ["SOURCE:a"]))], "DENY", {"stage": "ENGINE_GUARD"})
    add("e02_inf_optional_member", "Engine guard: +Inf on an optional (non-representative) member", ANNOTATE,
        [fam("F1", ev("ev-1", 0.9, ["SOURCE:a"]), ev("ev-1d", "7ff0000000000000", ["SOURCE:a"], parent="ev-1"))],
        "DENY", {"stage": "ENGINE_GUARD"})
    add("e03_nan_profile_parameter", "Engine guard: NaN in a profile parameter (Ω)", ANNOTATE, ind, "DENY",
        {"stage": "ENGINE_GUARD"}, profile=dict(PROFILE, omega_bits="7ff8000000000000"))
    add("e04_neg_inf_gamma", "Engine guard: −Inf consequence Γ", WIRE, ind, "DENY", {"stage": "ENGINE_GUARD"},
        profile=dict(PROFILE, consequence_gamma_bits=dict(PROFILE["consequence_gamma_bits"],
                                                          **{"wire.release": "fff0000000000000"})))

    # KNOWN OPEN EXPLOIT: self-declared lineage padding
    pad = [fam(f"F-pad-{i}", ev(f"ev-pad-{i}", 0.95, J.SHARED_FEED + ["API_ENDPOINT:vendor-a/verify-v2"] +
                                [f"COLLECTOR:fabricated-{i}-{k:03d}" for k in range(200)])) for i in (1, 2)]
    add("x01_atom_padding_exploit", "Two self-declared duplicates padded with fabricated atoms flip DENY to ALLOW",
        WIRE, cor + pad, "ALLOW",
        known_exploit={"security_expectation": {"decision": "DENY", "same_M_as": "c04_three_correlated_fail"},
                       "open_until": "verified-provenance boundary (proposed rule P-1) is specified and implemented",
                       "why": "Each padded item re-declares vendor A's lineage and adds 200 unique fabricated "
                              "COLLECTOR atoms, collecting ~V of mass it did not earn."})
    return C


def boundary_values():
    def one(vb):
        return ENG.evaluate(REFUND, [fam("F-solo", ev("ev-solo", vb, ["SOURCE:solo"]))], PROFILE)
    T = S.f(one(bits(0.5))["T_bits"])
    lob, hib = R.bits_of(0.0), R.bits_of(1.0)
    while hib - lob > 1:
        mid = (lob + hib) // 2
        if S.f(one(f"{mid:016x}")["C_bits"]) >= T:
            hib = mid
        else:
            lob = mid
    if S.f(one(f"{hib:016x}")["C_bits"]) != T:
        raise SystemExit("coverage boundary: no V gives C == T")
    target = struct.unpack(">d", struct.pack(">Q", R.bits_of(T) - 1))[0]
    b = hib
    while S.f(one(f"{b:016x}")["C_bits"]) > target:
        b -= 1
    if S.f(one(f"{b:016x}")["C_bits"]) != target:
        raise SystemExit("coverage boundary: no V gives C == T - 1ulp")
    return f"{hib:016x}", f"{b:016x}"


# ---------------------------------------------------------------------------
# Property witnesses (deterministic random pairs, re-checked by the JS cross-check)
# ---------------------------------------------------------------------------

def witnesses(n=24):
    rng = DRng("coverage-witness")
    out = []
    kinds = ["monotone", "idempotent", "bridge"]
    for i in range(n):
        kind = kinds[i % 3]
        base = [random_family(rng, f"W{i}-{k}") for k in range(1 + rng.below(5))]
        req = rng.pick([WIRE, REFUND, ANNOTATE])
        if kind == "monotone":
            added = random_family(rng, f"W{i}-new")
        elif kind == "idempotent":
            added = rename_family(rng.pick(base), f"W{i}-dup")
        else:
            atoms = sorted({a for fb in base for a in fb["members"][0]["dependencies"]})
            pick = sorted({rng.pick(atoms) for _ in range(3)}) if atoms else []
            added = fam(f"W{i}-bridge", ev(f"ev-W{i}-bridge", rng.unit(), pick))
        t0 = ENG.evaluate(req, base, PROFILE)
        t1 = ENG.evaluate(req, base + [added], PROFILE)
        m0, m1 = M_of(t0), M_of(t1)
        ok = m1 >= m0 if kind != "idempotent" else t1["M_bits"] == t0["M_bits"]
        # duplicates of an unknown-lineage family or of a degraded one may still add nothing; the check holds
        if not ok:
            raise SystemExit(f"property witness {i} ({kind}) violated: {m0} -> {m1}")
        out.append({"kind": kind, "request": req, "base": base, "added": added,
                    "M_base_bits": t0["M_bits"], "M_after_bits": t1["M_bits"],
                    "decision_base": t0["decision"], "decision_after": t1["decision"]})
    return out


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build():
    out, by_id = [], {}
    xfail = []
    for c in cases():
        tr = ENG.evaluate(c["request"], c["families"], c["profile"])
        if tr["decision"] != c["expect"]:
            raise SystemExit(f"coverage {c['id']}: engine says {tr['decision']} {tr['reason_codes']}, declared {c['expect']}")
        ck = c["checks"]
        if "M" in ck and S.f(tr["M_bits"]) != ck["M"]:
            raise SystemExit(f"coverage {c['id']}: M = {S.f(tr['M_bits'])} != {ck['M']}")
        if "same_M_as" in ck and tr["M_bits"] != by_id[ck["same_M_as"]]["M_bits"]:
            raise SystemExit(f"coverage {c['id']}: M differs from {ck['same_M_as']}")
        if "same_trace_as" in ck and R.encode(ENG.evaluate(c["request"], ck["same_trace_as"], c["profile"])) != R.encode(tr):
            raise SystemExit(f"coverage {c['id']}: trace differs from its base")
        if "kappa_effective" in ck and S.f(tr["kappa_unknown_effective_bits"]) != ck["kappa_effective"]:
            raise SystemExit(f"coverage {c['id']}: kappa")
        if "reasons" in ck and sorted(tr["reason_codes"]) != sorted(ck["reasons"]):
            raise SystemExit(f"coverage {c['id']}: reasons {tr['reason_codes']}")
        if "stage" in ck and tr["stage"] != ck["stage"]:
            raise SystemExit(f"coverage {c['id']}: stage {tr['stage']}")
        if ck.get("C_equals_T") and tr["C_bits"] != tr["T_bits"]:
            raise SystemExit(f"coverage {c['id']}: C != T")
        if "C_ulps_below_T" in ck and int(tr["T_bits"], 16) - int(tr["C_bits"], 16) != ck["C_ulps_below_T"]:
            raise SystemExit(f"coverage {c['id']}: ulp")
        by_id[c["id"]] = tr
        v = {"id": c["id"], "title": c["title"],
             "profile": "calibrated" if c["profile"] is PROFILE else "variant",
             "input": {"request": c["request"], "families": c["families"]},
             "expected_trace": tr,
             "summary": {"decision": tr["decision"], "stage": tr["stage"],
                         "M": repr(S.f(tr["M_bits"])), "C": repr(S.f(tr["C_bits"])),
                         "T": repr(S.f(tr["T_bits"])) if tr["T_bits"] else None}}
        if c["profile"] is not PROFILE:
            v["profile_declaration"] = c["profile"]
        if c.get("note"):
            v["note"] = c["note"]
        if c.get("known_exploit"):
            ke = c["known_exploit"]
            sec = ke["security_expectation"]
            meets = tr["decision"] == sec["decision"] and tr["M_bits"] == by_id[sec["same_M_as"]]["M_bits"]
            if meets:
                raise SystemExit(f"{c['id']}: exploit no longer reproduces — promote it to a normal case")
            v["known_exploit"] = dict(ke, status="REPRODUCES in this superseded profile; closed in coverage-v0.2.1-alpha (x01_self_declared_padding)")
            xfail.append(c["id"])
        out.append(v)

    return {
        "vector_set": "scoring-profile",
        "scoring_profile": COV.PROFILE_ID,
        "status": "SUPERSEDED by coverage-v0.2.1-alpha (kept frozen as evidence; x01 reproduces here by design)",
        "spec_version": R.SPEC_VERSION,
        "assumptions": "docs/SCORING_PROFILE_coverage-v0.2.0-alpha.md",
        "engine": "reference/prc_engine.py — non-finite guard (E-1) runs before profile dispatch",
        "profiles": {"calibrated": {"declaration": PROFILE, "fingerprint": R.H(PROFILE)}},
        "known_exploits_open": xfail,
        "property_witnesses": witnesses(),
        "cases": out,
    }
