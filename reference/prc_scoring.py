"""
prc_scoring — PRC Scoring Profile `jaccard-v0.1.0-alpha`

    Status:          EXPERIMENTAL
    Normative role:  reference candidate (replaceable)

The control architecture requires *a* deterministic scoring profile. This module is the
first concrete candidate. It exists to generate evidence about the model, not to settle it.

Pure functions only: no signing, no CAS, no receipts, no clock, no randomness.
Every float is IEEE 754 binary64 and every operation is +, -, *, / (correctly rounded)
or an exact power-of-two scaling, so results are bit-reproducible across runtimes
provided the runtime does not contract a*b+c into an FMA. Transcendental functions
come from `prc_exp` below, never from the platform libm (see S-07).

Component ids (recorded in the profile and in every trace):
    canonical-representative : structural-root-v1
    independence-function    : material-dependency-jaccard-v1
    mass-function            : quality-weighted-independent-mass-v1
    confidence-function      : exponential-saturation-v1
    threshold-function       : consequence-exponential-v1
    exp-function             : prc-exp-v1
"""
from __future__ import annotations

import math
import re
import struct
from typing import Dict, List, Optional, Tuple

import prc_ref as R

PROFILE_ID = "jaccard-v0.1.0-alpha"
COMPONENTS = {
    "canonical_representative": "structural-root-v1",
    "independence_function": "material-dependency-jaccard-v1",
    "mass_function": "quality-weighted-independent-mass-v1",
    "confidence_function": "exponential-saturation-v1",
    "threshold_function": "consequence-exponential-v1",
    "exp_function": "prc-exp-v1",
    "summation_order": "representative-evidence-id-utf8-ascending",
}

DEPENDENCY_TYPES = (
    "SOURCE", "DATABASE", "COLLECTOR", "RUNTIME", "CLOCK", "NETWORK_AS", "TRUST_ROOT", "API_ENDPOINT",
)
ATOM_RE = re.compile(r"^([A-Z_]+):(\S+)$")


class ProfileError(ValueError):
    pass


# ---------------------------------------------------------------------------
# binary64 helpers (bits in, bits out — no decimal round trips)
# ---------------------------------------------------------------------------

def f(bits_hex: str) -> float:
    return struct.unpack(">d", bytes.fromhex(bits_hex))[0]


def hx(x: float) -> str:
    return struct.pack(">d", x).hex()


def _finite(x: float) -> bool:
    return not (math.isnan(x) or math.isinf(x))


# ---------------------------------------------------------------------------
# prc-exp-v1 : deterministic exp using only basic IEEE operations  (S-07)
# ---------------------------------------------------------------------------
# Cody–Waite reduction x = k*ln2 + r, |r| <= ln2/2, then Horner evaluation of the
# degree-13 Taylor polynomial, then exact scaling by 2^k. Accuracy is ~1 ulp; it is not
# correctly rounded, but it is *the same* on every conforming runtime.
EXP_INV_LN2 = f("3ff71547652b82fe")
EXP_LN2_HI = f("3fe62e42fee00000")   # low 21 bits of the significand are zero -> k*LN2_HI is exact
EXP_LN2_LO = f("3dea39ef35793c76")
EXP_COEFF = [1.0 / math.factorial(n) for n in range(14)]   # c0..c13, each a correctly rounded quotient
EXP_COEFF_BITS = [hx(c) for c in EXP_COEFF]


def _pow2(k: int) -> float:
    """Exact 2^k built from its bit pattern, -1074 <= k <= 1023."""
    if k >= -1022:
        return struct.unpack(">d", struct.pack(">Q", (k + 1023) << 52))[0]
    return struct.unpack(">d", struct.pack(">Q", 1 << (k + 1074)))[0]


def prc_exp(x: float) -> float:
    if math.isnan(x):
        return x
    if x > 709.0:
        return math.inf
    if x < -745.0:
        return 0.0
    k = math.floor(x * EXP_INV_LN2 + 0.5)
    r = (x - k * EXP_LN2_HI) - k * EXP_LN2_LO
    p = EXP_COEFF[13]
    for n in range(12, -1, -1):
        p = p * r + EXP_COEFF[n]
    if k < -1022:  # two-step scaling so the only rounding happens in the final multiply
        return (p * _pow2(-1022)) * _pow2(k + 1022)
    if k > 1023:
        return (p * _pow2(1023)) * _pow2(k - 1023)
    return p * _pow2(k)


# ---------------------------------------------------------------------------
# Profile compilation
# ---------------------------------------------------------------------------

def compile_profile(p: dict) -> dict:
    """Validate a scoring profile and return a compiled copy with floats decoded.
    The profile's fingerprint is H(profile) over its declared (hex-bits) form."""
    if p.get("id") != PROFILE_ID:
        raise ProfileError("unsupported scoring profile id")
    for k, v in COMPONENTS.items():
        if p.get(k) != v:
            raise ProfileError(f"component mismatch: {k}")
    c = {"fingerprint": R.H(p)}
    for name in ("omega", "t_base", "beta", "kappa_unknown", "kappa_degraded"):
        v = f(p[name + "_bits"])
        if not _finite(v):
            raise ProfileError(f"{name} not finite")
        c[name] = v
    if not c["omega"] > 0.0:
        raise ProfileError("omega must be > 0")
    if not 0.5 <= c["t_base"] < 1.0:
        raise ProfileError("t_base must be in [0.5, 1.0)")
    if not c["beta"] >= 0.0:
        raise ProfileError("beta must be >= 0")
    for name in ("kappa_unknown", "kappa_degraded"):
        if not 0.0 <= c[name] <= 1.0:
            raise ProfileError(f"{name} must be in [0, 1]")
    mats = p["material_dependency_types"]
    if sorted(set(mats)) != sorted(mats) or any(t not in DEPENDENCY_TYPES for t in mats):
        raise ProfileError("material_dependency_types must be distinct known types")
    c["material"] = frozenset(mats)
    c["gamma"] = {}
    for action, gbits in p["consequence_gamma_bits"].items():
        g = f(gbits)
        if not (_finite(g) and 0.1 <= g <= 10.0):
            raise ProfileError(f"gamma for {action} outside [0.1, 10.0]")
        c["gamma"][action] = g
    return c


# ---------------------------------------------------------------------------
# Evidence normalisation and structural representative (S-01, S-02)
# ---------------------------------------------------------------------------

def dependency_atoms(evidence: dict) -> Optional[frozenset]:
    """All declared atoms (any type) as a set, or None if any atom is malformed/unknown-typed."""
    out = set()
    for a in evidence.get("dependencies", []):
        m = ATOM_RE.match(a)
        if not m or m.group(1) not in DEPENDENCY_TYPES:
            return None
        out.add(a)
    return frozenset(out)


def material_atoms(atoms: frozenset, profile: dict) -> frozenset:
    return frozenset(a for a in atoms if a.split(":", 1)[0] in profile["material"])


def normalise_evidence(e: dict) -> dict:
    """Canonical form used for hashing: dependencies sorted and de-duplicated."""
    n = dict(e)
    n["dependencies"] = sorted(set(e.get("dependencies", [])), key=lambda s: s.encode("utf-8"))
    return n


def canonical_digest(e: dict) -> str:
    return R.H(normalise_evidence(e))


def canonical_representative(family: dict) -> Tuple[Optional[dict], Dict[str, int], Optional[str]]:
    """structural-root-v1: exactly one member whose parent is absent or outside the family,
    every other member must reach it through in-family parents without cycles.
    Returns (root, depth-by-id, error). Digest order is never used for selection."""
    members = family["members"]
    ids = [m["evidence_id"] for m in members]
    if len(set(ids)) != len(ids):
        return None, {}, "duplicate evidence_id in family"
    by_id = {m["evidence_id"]: m for m in members}
    roots = [m for m in members if m.get("parent_id") is None or m.get("parent_id") not in by_id]
    if len(roots) != 1:
        return None, {}, f"expected exactly one root, found {len(roots)}"
    root = roots[0]
    depth: Dict[str, int] = {}
    for m in members:
        seen, cur, d = set(), m, 0
        while cur["evidence_id"] != root["evidence_id"]:
            if cur["evidence_id"] in seen:
                return None, {}, "cycle in parent links"
            seen.add(cur["evidence_id"])
            cur = by_id[cur["parent_id"]]
            d += 1
        depth[m["evidence_id"]] = d
    return root, depth, None


# ---------------------------------------------------------------------------
# Independence (S-03, S-04)
# ---------------------------------------------------------------------------

def pairwise_independence(dk: frozenset, dj: frozenset, profile: dict) -> Tuple[float, bool]:
    """material-dependency-jaccard-v1. Returns (I, unknown_fallback_used)."""
    if not dk or not dj:
        return profile["kappa_unknown"], True
    inter = len(dk & dj)
    union = len(dk | dj)
    return 1.0 - inter / union, False   # int/int -> correctly rounded binary64


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
STATE_FACTOR = {"VALID": 1.0, "CONTRADICTORY": 0.0}


def evaluate(request: dict, families: List[dict], profile_decl: dict) -> dict:
    """evaluate(request, evidence families, profile) -> DecisionTrace (plain dict, bits as hex)."""
    prof = compile_profile(profile_decl)
    reason = 0
    audit = []
    fam_out = {}
    eligible = []  # (rep_id, family_id, V, material atoms)

    for fam in sorted(families, key=lambda x: x["family_id"].encode("utf-8")):
        fid = fam["family_id"]
        root, depth, err = canonical_representative(fam)
        atoms_ok = all(dependency_atoms(m) is not None for m in fam["members"])
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
            fam_out[fid] = {"eligible": False, "status": "INVALIDATED",
                            "representative": root["evidence_id"]}
            audit.append({"event": "FAMILY_INVALIDATED", "family": fid})
            reason |= R.RC["FAMILY_INVALIDATED"]
            continue
        if root_state != "VALID":  # S-05: a non-VALID representative gives no positive support
            fam_out[fid] = {"eligible": False, "status": "REPRESENTATIVE_" + root_state,
                            "representative": root["evidence_id"]}
            continue
        factors = [prof["kappa_degraded"] if s == "DEGRADED" else STATE_FACTOR[s]
                   for s in states if s != "UNAVAILABLE_OR_STALE"]
        A = min(factors) if factors else 1.0
        V_rep = f(root["value_bits"])
        if _finite(V_rep) and not 0.0 <= V_rep <= 1.0:  # S-08: quality scores live in [0, 1]
            fam_out[fid] = {"eligible": False, "status": "MALFORMED", "error": "value outside [0, 1]"}
            audit.append({"event": "LINEAGE_CLASS_MALFORMED", "family": fid, "detail": "value outside [0, 1]"})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        V = V_rep * A  # NaN/Inf propagate into M and are caught below (fault closed)
        mat = material_atoms(dependency_atoms(root), prof)
        fam_out[fid] = {
            "eligible": True, "status": "ELIGIBLE",
            "representative": root["evidence_id"],
            "representative_digest": canonical_digest(root),
            "lineage_depth": dict(sorted(depth.items())),
            "A_bits": hx(A), "V_bits": hx(V),
            "material_atoms": sorted(mat, key=lambda s: s.encode("utf-8")),
        }
        eligible.append((root["evidence_id"], fid, V, mat))

    eligible.sort(key=lambda t: t[0].encode("utf-8"))  # canonical summation order (S-06)
    pair_out, unknown_used = {}, False
    I_k = {}
    if len(eligible) == 1:
        I_k[eligible[0][1]] = 1.0
    for _, fk, _, dk in eligible:
        if len(eligible) == 1:
            break
        vals = []
        for _, fj, _, dj in eligible:
            if fj == fk:
                continue
            i, unk = pairwise_independence(dk, dj, prof)
            unknown_used |= unk
            pair_out[f"{fk}|{fj}"] = hx(i)
            vals.append(i)
        I_k[fk] = min(vals)

    M = 0.0
    for _, fid, V, _ in eligible:
        M = M + V * I_k[fid]
        fam_out[fid]["I_bits"] = hx(I_k[fid])
        fam_out[fid]["contribution_bits"] = hx(V * I_k[fid])

    if _finite(M):
        C = 1.0 - prc_exp(-(M / prof["omega"]))
    else:  # §2.3: a float exception anywhere in the pipeline must not become "very confident"
        C = math.nan
    action = request["action"]
    if action in prof["gamma"]:
        g = prof["gamma"][action]
        T = 1.0 - (1.0 - prof["t_base"]) * prc_exp(-(g * prof["beta"]))
    else:  # fault closed: an action without a consequence class can never be authorised
        g, T = None, math.nan
        reason |= R.RC["CONSEQUENCE_CLASS_UNDEFINED"]

    if not eligible:
        reason |= R.RC["NO_ELIGIBLE_EVIDENCE"]
        M, C = 0.0, 0.0
    chk = R.authorization_check(R.bits_of(C), R.bits_of(T))
    if chk["safe_state_lock"]:
        reason |= R.RC["SAFE_STATE_LOCK"]
    elif not chk["result"]:
        reason |= R.RC["THRESHOLD_NOT_MET"]
    # Invalidated/malformed families are audited and excluded; they can only lower C, never block alone.
    allow = chk["result"] and not reason & R.RC["CONSEQUENCE_CLASS_UNDEFINED"]
    return {
        "scoring_profile": PROFILE_ID,
        "profile_fingerprint": prof["fingerprint"],
        "action": action,
        "families": fam_out,
        "eligible_families": [t[1] for t in eligible],
        "pairwise_independence_bits": dict(sorted(pair_out.items())),
        "unknown_lineage_fallback_used": unknown_used,
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
