"""
prc_coverage_v021 — PRC Scoring Profile `coverage-v0.2.1-alpha`

    Status:          EXPERIMENTAL
    Normative role:  reference candidate; supersedes coverage-v0.2.0-alpha

Identical mass rule to coverage-v0.2.0-alpha (material-dependency-coverage-v1 with the
single consequence-gated UNKNOWN:* sink). What changes is where atoms come from and how
contradiction is handled:

  P-1  D_k comes only from the representative's *admitted* provenance attestation
       (prc_provenance.admissibility), resolved through the profile's alias table against
       its closed atom registry and bounded by per-type caps. Self-declared
       `dependencies` are ignored. Unattested / inadmissible -> UNKNOWN:*.
       TAMPERED on any member -> the family is INVALID (§2.2), audited, PROVENANCE_TAMPERED.

  D-1  Defeater channel (authenticated-contradiction-veto-v1):
         D⁻(x,a) = { optional members in state CONTRADICTORY whose attestation is ADMITTED }
         Decision = ALLOW  requires  D⁻ = ∅   (categorical; never a negative mass term)
       An *unverified* contradiction keeps the §2.2 behaviour (A = 0 for its own family) and
       is audited as UNVERIFIED_CONTRADICTION.

Positive mass stays monotone (P1–P4). The decision is monotone for every addition except an
admitted defeater, which by design always yields DENY (P6).
"""
from __future__ import annotations

import math
from typing import List, Optional

import prc_ref as R
import prc_scoring as S
import prc_coverage as COV
import prc_provenance as PV

PROFILE_ID = "coverage-v0.2.1-alpha"
UNKNOWN_ATOM = COV.UNKNOWN_ATOM
COMPONENTS = {
    "canonical_representative": "structural-root-v1",
    "mass_function": "material-dependency-coverage-v1",
    "unknown_lineage": "single-sink-consequence-gated-v1",
    "confidence_function": "exponential-saturation-v1",
    "threshold_function": "consequence-exponential-v1",
    "exp_function": "prc-exp-v1",
    "summation_order": "dependency-atom-utf8-ascending",
    "dependency_source": "attested-P-1",
    "defeater_policy": "authenticated-contradiction-veto-v1",
}
f, hx, prc_exp = S.f, S.hx, S.prc_exp


def compile_profile(p: dict) -> dict:
    if p.get("id") != PROFILE_ID:
        raise S.ProfileError("unsupported scoring profile id")
    for k, v in COMPONENTS.items():
        if p.get(k) != v:
            raise S.ProfileError(f"component mismatch: {k}")
    base = dict(p, id=COV.PROFILE_ID, **COV.COMPONENTS)  # reuse numeric validation
    c = COV.compile_profile({k: base[k] for k in base if k in COV.COMPONENTS or k.endswith("_bits")
                             or k in ("id", "material_dependency_types", "consequence_gamma_bits")})
    c["fingerprint"] = R.H(p)
    reg = p["atom_registry"]
    if reg.get("mode") != "closed":
        raise S.ProfileError("coverage-v0.2.1 requires a closed atom registry")
    atoms = reg["atoms"]
    if atoms != sorted(set(atoms), key=lambda s: s.encode("utf-8")):
        raise S.ProfileError("atom registry must be sorted and unique")
    for a in atoms:
        m = S.ATOM_RE.match(a)
        if not m or m.group(1) not in S.DEPENDENCY_TYPES:
            raise S.ProfileError(f"bad registry atom {a}")
    c["registered_atoms"] = frozenset(atoms)
    c["aliases"] = dict(reg.get("aliases", {}))
    for src, dst in c["aliases"].items():
        if dst not in c["registered_atoms"] or src.split(":", 1)[0] != dst.split(":", 1)[0]:
            raise S.ProfileError(f"alias {src} -> {dst} must target a registered atom of the same type")
    c["max_atoms_per_type"] = {k: int(v) for k, v in p["max_atoms_per_type"].items()}
    c["attester_independence_required"] = bool(p["attester_independence_required"])
    return c


def _utf8(s: str) -> bytes:
    return s.encode("utf-8")


def evaluate(request: dict, families: List[dict], profile_decl: dict, trust: Optional[dict] = None) -> dict:
    prof = compile_profile(profile_decl)
    trust = trust or {"registry": {}, "revoked_attestation_ids": []}
    tau_eval = request["tau_eval"]
    reason, audit, fam_out, eligible, defeaters = 0, [], {}, [], []

    action = request["action"]
    if action in prof["gamma"]:
        g = prof["gamma"][action]
        T = 1.0 - (1.0 - prof["t_base"]) * prc_exp(-(g * prof["beta"]))
    else:
        g, T = None, math.nan
        reason |= R.RC["CONSEQUENCE_CLASS_UNDEFINED"]
    kappa_u = 0.0 if (T == T and T >= prof["unknown_gate_t"]) else prof["kappa_unknown"]

    for fam in sorted(families, key=lambda x: _utf8(x["family_id"])):
        fid = fam["family_id"]
        root, depth, err = S.canonical_representative(fam)
        if err:
            fam_out[fid] = {"eligible": False, "status": "MALFORMED", "error": err}
            audit.append({"event": "LINEAGE_CLASS_MALFORMED", "family": fid, "detail": err})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        # provenance for every member (tamper anywhere invalidates the family)
        prov = {}
        for m in sorted(fam["members"], key=lambda x: _utf8(x["evidence_id"])):
            prov[m["evidence_id"]] = PV.admissibility(m, trust, prof, tau_eval)
        tampered = [(eid, d) for eid, (o, d, _) in prov.items() if o == "TAMPERED"]
        optional = [m for m in fam["members"] if m["evidence_id"] != root["evidence_id"]]
        states = [m.get("state", "VALID") for m in optional]
        root_state = root.get("state", "VALID")
        prov_out = {eid: {"outcome": o, "detail": d} for eid, (o, d, _) in prov.items()}
        if tampered:
            fam_out[fid] = {"eligible": False, "status": "INVALIDATED", "cause": "PROVENANCE_TAMPERED",
                            "representative": root["evidence_id"], "provenance": prov_out}
            audit.append({"event": "PROVENANCE_TAMPERED", "family": fid,
                          "members": [{"evidence_id": e, "detail": d} for e, d in tampered]})
            reason |= R.RC["PROVENANCE_TAMPERED"] | R.RC["FAMILY_INVALIDATED"]
            continue
        if "INVALID" in states or root_state == "INVALID":
            fam_out[fid] = {"eligible": False, "status": "INVALIDATED", "representative": root["evidence_id"],
                            "provenance": prov_out}
            audit.append({"event": "FAMILY_INVALIDATED", "family": fid})
            reason |= R.RC["FAMILY_INVALIDATED"]
            continue
        # defeater channel: authenticated contradictions veto, unverified ones only zero the family
        for m in sorted(optional, key=lambda x: _utf8(x["evidence_id"])):
            if m.get("state") == "CONTRADICTORY":
                if prov[m["evidence_id"]][0] == "ADMITTED":
                    defeaters.append({"family": fid, "evidence_id": m["evidence_id"],
                                      "attestation_id": m["provenance"]["payload"]["attestation_id"]})
                else:
                    audit.append({"event": "UNVERIFIED_CONTRADICTION", "family": fid, "evidence_id": m["evidence_id"]})
        if root_state != "VALID":
            fam_out[fid] = {"eligible": False, "status": "REPRESENTATIVE_" + root_state,
                            "representative": root["evidence_id"], "provenance": prov_out}
            continue
        V_rep = f(root["value_bits"])
        if not 0.0 <= V_rep <= 1.0:
            fam_out[fid] = {"eligible": False, "status": "MALFORMED", "error": "value outside [0, 1]"}
            audit.append({"event": "LINEAGE_CLASS_MALFORMED", "family": fid, "detail": "value outside [0, 1]"})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        factors = [prof["kappa_degraded"] if s == "DEGRADED" else S.STATE_FACTOR[s]
                   for s in states if s != "UNAVAILABLE_OR_STALE"]
        A = min(factors) if factors else 1.0
        V = V_rep * A
        outcome, _, atoms = prov[root["evidence_id"]]
        mat = frozenset(a for a in atoms if a.split(":", 1)[0] in prof["material"]) if outcome == "ADMITTED" else frozenset()
        unknown = not mat
        if unknown:
            V = V * kappa_u
            mat = frozenset([UNKNOWN_ATOM])
        w = V / len(mat)
        fam_out[fid] = {
            "eligible": True, "status": "ELIGIBLE",
            "representative": root["evidence_id"],
            "representative_digest": PV.evidence_digest(root),
            "lineage_depth": dict(sorted(depth.items())),
            "provenance": prov_out,
            "A_bits": hx(A), "V_bits": hx(V), "unknown_lineage": unknown,
            "atoms": sorted(mat, key=_utf8), "per_atom_share_bits": hx(w),
        }
        eligible.append((fid, mat, w))

    best, owner = {}, {}
    for fid, mat, w in eligible:
        for d in mat:
            if d not in best or w > best[d]:
                best[d], owner[d] = w, fid
    M = 0.0
    for d in sorted(best, key=_utf8):
        M = M + best[d]
    C = 1.0 - prc_exp(-(M / prof["omega"]))
    if not eligible:
        reason |= R.RC["NO_ELIGIBLE_EVIDENCE"]
        M, C = 0.0, 0.0
    chk = R.authorization_check(R.bits_of(C), R.bits_of(T))
    if chk["safe_state_lock"]:
        reason |= R.RC["SAFE_STATE_LOCK"]
    elif not chk["result"]:
        reason |= R.RC["THRESHOLD_NOT_MET"]
    if defeaters:
        reason |= R.RC["DEFEATER_PRESENT"]
    allow = chk["result"] and not defeaters and not reason & R.RC["CONSEQUENCE_CLASS_UNDEFINED"]
    return {
        "stage": "PROFILE",
        "scoring_profile": PROFILE_ID,
        "profile_fingerprint": prof["fingerprint"],
        "action": action,
        "tau_eval": tau_eval,
        "families": fam_out,
        "eligible_families": [e[0] for e in eligible],
        "atom_credit_bits": {d: hx(best[d]) for d in sorted(best, key=_utf8)},
        "atom_owner": {d: owner[d] for d in sorted(owner, key=_utf8)},
        "defeaters": defeaters,
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
