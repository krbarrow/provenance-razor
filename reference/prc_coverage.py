"""
prc_coverage — PRC Scoring Profile `coverage-v0.2.0-alpha`

    Status:          EXPERIMENTAL
    Normative role:  reference candidate (replaceable); supersedes jaccard-v0.1.0-alpha's mass rule

Mass is set-union coverage over material dependency atoms instead of a pairwise
independence penalty:

    w_k        = V(F̄_k) / |D_k|                         per-atom share of family k
    best(d)    = max_{k : d ∈ D_k} w_k                   each atom credited once, at its best share
    M          = Σ_{d ∈ ∪ D_k} best(d)                   summed in ascending UTF-8 order of d

A family with no material atoms is mapped to the single synthetic sink `UNKNOWN:*`, with
its value multiplied by κ_unknown, and κ_unknown is forced to 0 when T(x,a) ≥ unknown_gate_t.

Properties (proved in docs/SCORING_PROFILE_coverage-v0.2.0-alpha.md, tested in
tools/property_tests.py and witnessed in the vectors):
    monotone      adding an eligible family never lowers M (bitwise, under round-to-nearest)
    idempotent    adding a family whose atoms and value duplicate an existing one leaves M unchanged
    bridge-safe   a family overlapping several others can only add its own best shares
    order-free    permuting families, members or atom lists leaves every output bit unchanged

KNOWN OPEN EXPLOIT: dependencies are self-declared (`dependency_source: self-declared-UNVERIFIED`).
A claimant can pad its own atom list with fabricated atoms and collect up to V of mass per
item. The vectors carry this as an expected-failure case until the verified-provenance
boundary is specified.

The same arithmetic rules as prc_scoring apply: binary64, + − × ÷ only, no FMA contraction,
exp from prc-exp-v1.
"""
from __future__ import annotations

import math
from typing import List

import prc_ref as R
import prc_scoring as S

PROFILE_ID = "coverage-v0.2.0-alpha"
UNKNOWN_ATOM = "UNKNOWN:*"
COMPONENTS = {
    "canonical_representative": "structural-root-v1",
    "mass_function": "material-dependency-coverage-v1",
    "unknown_lineage": "single-sink-consequence-gated-v1",
    "confidence_function": "exponential-saturation-v1",
    "threshold_function": "consequence-exponential-v1",
    "exp_function": "prc-exp-v1",
    "summation_order": "dependency-atom-utf8-ascending",
    "dependency_source": "self-declared-UNVERIFIED",
}
f, hx, prc_exp = S.f, S.hx, S.prc_exp


def compile_profile(p: dict) -> dict:
    if p.get("id") != PROFILE_ID:
        raise S.ProfileError("unsupported scoring profile id")
    for k, v in COMPONENTS.items():
        if p.get(k) != v:
            raise S.ProfileError(f"component mismatch: {k}")
    c = {"fingerprint": R.H(p)}
    for name in ("omega", "t_base", "beta", "kappa_unknown", "kappa_degraded", "unknown_gate_t"):
        c[name] = f(p[name + "_bits"])
    if not c["omega"] > 0.0:
        raise S.ProfileError("omega must be > 0")
    if not 0.5 <= c["t_base"] < 1.0:
        raise S.ProfileError("t_base must be in [0.5, 1.0)")
    if not c["beta"] >= 0.0:
        raise S.ProfileError("beta must be >= 0")
    for name in ("kappa_unknown", "kappa_degraded", "unknown_gate_t"):
        if not 0.0 <= c[name] <= 1.0:
            raise S.ProfileError(f"{name} must be in [0, 1]")
    mats = p["material_dependency_types"]
    if sorted(set(mats)) != sorted(mats) or any(t not in S.DEPENDENCY_TYPES for t in mats):
        raise S.ProfileError("material_dependency_types must be distinct known types")
    c["material"] = frozenset(mats)
    c["gamma"] = {}
    for action, gbits in p["consequence_gamma_bits"].items():
        g = f(gbits)
        if not 0.1 <= g <= 10.0:
            raise S.ProfileError(f"gamma for {action} outside [0.1, 10.0]")
        c["gamma"][action] = g
    return c


def _utf8(s: str) -> bytes:
    return s.encode("utf-8")


def evaluate(request: dict, families: List[dict], profile_decl: dict) -> dict:
    prof = compile_profile(profile_decl)
    reason, audit, fam_out, eligible = 0, [], {}, []

    action = request["action"]
    if action in prof["gamma"]:
        g = prof["gamma"][action]
        T = 1.0 - (1.0 - prof["t_base"]) * prc_exp(-(g * prof["beta"]))
    else:
        g, T = None, math.nan
        reason |= R.RC["CONSEQUENCE_CLASS_UNDEFINED"]
    # consequence gate: at or above the gate, unattributed evidence carries no weight
    kappa_u = 0.0 if (T == T and T >= prof["unknown_gate_t"]) else prof["kappa_unknown"]

    for fam in sorted(families, key=lambda x: _utf8(x["family_id"])):
        fid = fam["family_id"]
        root, depth, err = S.canonical_representative(fam)
        atoms_ok = all(S.dependency_atoms(m) is not None for m in fam["members"])
        if err or not atoms_ok:
            why = err or "malformed or unknown-typed dependency atom"
            fam_out[fid] = {"eligible": False, "status": "MALFORMED", "error": why}
            audit.append({"event": "LINEAGE_CLASS_MALFORMED", "family": fid, "detail": why})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        optional = [m for m in fam["members"] if m["evidence_id"] != root["evidence_id"]]
        states = [m.get("state", "VALID") for m in optional]
        root_state = root.get("state", "VALID")
        if "INVALID" in states or root_state == "INVALID":
            fam_out[fid] = {"eligible": False, "status": "INVALIDATED", "representative": root["evidence_id"]}
            audit.append({"event": "FAMILY_INVALIDATED", "family": fid})
            reason |= R.RC["FAMILY_INVALIDATED"]
            continue
        if root_state != "VALID":
            fam_out[fid] = {"eligible": False, "status": "REPRESENTATIVE_" + root_state,
                            "representative": root["evidence_id"]}
            continue
        V_rep = f(root["value_bits"])  # finiteness already enforced by the engine guard
        if not 0.0 <= V_rep <= 1.0:
            fam_out[fid] = {"eligible": False, "status": "MALFORMED", "error": "value outside [0, 1]"}
            audit.append({"event": "LINEAGE_CLASS_MALFORMED", "family": fid, "detail": "value outside [0, 1]"})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        factors = [prof["kappa_degraded"] if s == "DEGRADED" else S.STATE_FACTOR[s]
                   for s in states if s != "UNAVAILABLE_OR_STALE"]
        A = min(factors) if factors else 1.0
        V = V_rep * A
        mat = S.material_atoms(S.dependency_atoms(root), prof)
        unknown = not mat
        if unknown:
            V = V * kappa_u
            mat = frozenset([UNKNOWN_ATOM])
        w = V / len(mat)
        fam_out[fid] = {
            "eligible": True, "status": "ELIGIBLE",
            "representative": root["evidence_id"],
            "representative_digest": S.canonical_digest(root),
            "lineage_depth": dict(sorted(depth.items())),
            "A_bits": hx(A), "V_bits": hx(V), "unknown_lineage": unknown,
            "atoms": sorted(mat, key=_utf8), "per_atom_share_bits": hx(w),
        }
        eligible.append((fid, mat, w))

    best = {}
    owner = {}
    for fid, mat, w in eligible:  # families already in canonical order; ties keep the first owner
        for d in mat:
            if d not in best or w > best[d]:
                best[d], owner[d] = w, fid
    M = 0.0
    for d in sorted(best, key=_utf8):
        M = M + best[d]
    credited = {fid: 0 for fid, _, _ in eligible}
    for d in best:
        credited[owner[d]] += 1
    for fid in credited:
        fam_out[fid]["atoms_credited"] = credited[fid]

    C = 1.0 - prc_exp(-(M / prof["omega"]))
    if not eligible:
        reason |= R.RC["NO_ELIGIBLE_EVIDENCE"]
        M, C = 0.0, 0.0
    chk = R.authorization_check(R.bits_of(C), R.bits_of(T))
    if chk["safe_state_lock"]:
        reason |= R.RC["SAFE_STATE_LOCK"]
    elif not chk["result"]:
        reason |= R.RC["THRESHOLD_NOT_MET"]
    allow = chk["result"] and not reason & R.RC["CONSEQUENCE_CLASS_UNDEFINED"]
    return {
        "stage": "PROFILE",
        "scoring_profile": PROFILE_ID,
        "profile_fingerprint": prof["fingerprint"],
        "action": action,
        "families": fam_out,
        "eligible_families": [e[0] for e in eligible],
        "atom_credit_bits": {d: hx(best[d]) for d in sorted(best, key=_utf8)},
        "atom_owner": {d: owner[d] for d in sorted(owner, key=_utf8)},
        "kappa_unknown_effective_bits": hx(kappa_u),
        "gamma_bits": hx(g) if g is not None else None,
        "M_bits": hx(M),
        "C_bits": f"{chk['c_effective_bits']:016x}",
        "T_bits": hx(T),
        "safe_state_lock": chk["safe_state_lock"],
        "decision": "ALLOW" if allow else "DENY",
        "reason_bitfield": reason,
        "reason_codes": R.reason_names(reason),
        "audit_events": audit,
    }
