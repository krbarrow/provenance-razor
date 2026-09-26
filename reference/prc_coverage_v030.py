"""
prc_coverage_v030 — PRC Scoring Profile `coverage-v0.3.0-alpha`

    Status:          EXPERIMENTAL
    Normative role:  reference candidate; supersedes coverage-v0.2.1-alpha

Positive mass is unchanged (material-dependency-coverage-v1 with the consequence-gated
UNKNOWN:* sink). What changes:

  M-1  FamilyMembershipAdmissible (prc_membership): only members listed in an admissible,
       signed family manifest take part. Anything else is QUARANTINED — audit only.
  A-1  AdverseDisposition ∈ {CLEAR, CONTAIN, DEFEAT, LOCK}, precedence LOCK > DEFEAT > CONTAIN > CLEAR.
       For each *relevant* contradicting member (recognised conflict_type, bound to this
       request's action, assertion, target and evidence snapshot):
           provenance ADMITTED                 -> DEFEAT
           provenance UNATTESTED | INADMISSIBLE -> CONTAIN
           provenance TAMPERED                  -> LOCK
       Contradictions NEVER change A, V, M, C or T (0.2.x set A = 0; that is removed).
  Outcome:
       LOCK    -> DENY (Safe State Lock)
       DEFEAT  -> DENY (authenticated defeater; not overridable by ordinary approval)
       CONTAIN -> MANUAL_REQUIRED if C >= T_manual, else DENY; automatic ALLOW prohibited
       CLEAR   -> ALLOW if C >= T, else DENY
  The trust state (key registry, revocations, atom registry and aliases, per-type caps,
  attester independence, conflict types, clock authorities) is an input bound by hash; the
  scoring profile holds only the arithmetic.
"""
from __future__ import annotations

import math
from typing import List

import prc_ref as R
import prc_scoring as S
import prc_provenance as PV
import prc_membership as PM

PROFILE_ID = "coverage-v0.3.0-alpha"
UNKNOWN_ATOM = "UNKNOWN:*"
COMPONENTS = {
    "canonical_representative": "structural-root-v1",
    "mass_function": "material-dependency-coverage-v1",
    "unknown_lineage": "single-sink-consequence-gated-v1",
    "confidence_function": "exponential-saturation-v1",
    "threshold_function": "consequence-exponential-v1",
    "exp_function": "prc-exp-v1",
    "summation_order": "dependency-atom-utf8-ascending",
    "dependency_source": "attested-P-1",
    "membership": "signed-family-manifest-M-1",
    "adverse_disposition": "contain-defeat-lock-A-1",
}
PRECEDENCE = {"CLEAR": 0, "CONTAIN": 1, "DEFEAT": 2, "LOCK": 3}
f, hx, prc_exp = S.f, S.hx, S.prc_exp


def _utf8(s):
    return s.encode("utf-8")


def compile_profile(p: dict) -> dict:
    if p.get("id") != PROFILE_ID:
        raise S.ProfileError("unsupported scoring profile id")
    for k, v in COMPONENTS.items():
        if p.get(k) != v:
            raise S.ProfileError(f"component mismatch: {k}")
    c = {"fingerprint": R.H(p)}
    for name in ("omega", "t_base", "t_base_manual", "beta", "kappa_unknown", "kappa_degraded", "unknown_gate_t"):
        c[name] = f(p[name + "_bits"])
    if not c["omega"] > 0.0 or not 0.5 <= c["t_base"] < 1.0 or not 0.5 <= c["t_base_manual"] < 1.0 or not c["beta"] >= 0.0:
        raise S.ProfileError("parameter out of range")
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


def trust_policy(ts: dict) -> dict:
    reg = ts["atom_registry"]
    return {"aliases": dict(reg.get("aliases", {})), "registered_atoms": frozenset(reg["atoms"]),
            "max_atoms_per_type": dict(ts["max_atoms_per_type"]),
            "attester_independence_required": bool(ts["attester_independence_required"])}


def contradiction_digest(m: dict) -> str:
    return R.H({"conflict_type": m.get("conflict_type"), "contradicts": m.get("contradicts"), "claim": m.get("claim")})


def evaluate(request: dict, families: List[dict], profile_decl: dict, trust: dict) -> dict:
    prof = compile_profile(profile_decl)
    pol = trust_policy(trust)
    tau_eval = request["tau_eval"]
    binding = {"action": request["action"], "assertion": request.get("assertion"),
               "target": request.get("target"), "evidence_snapshot_id": request.get("evidence_snapshot_id")}
    reason, audit, fam_out, eligible = 0, [], {}, []
    obligations = {}   # contradiction digest -> record
    disposition = "CLEAR"

    def raise_disp(level):
        nonlocal disposition
        if PRECEDENCE[level] > PRECEDENCE[disposition]:
            disposition = level

    action = request["action"]
    if action in prof["gamma"]:
        g = prof["gamma"][action]
        T = 1.0 - (1.0 - prof["t_base"]) * prc_exp(-(g * prof["beta"]))
        T_manual = 1.0 - (1.0 - prof["t_base_manual"]) * prc_exp(-(g * prof["beta"]))
    else:
        g, T, T_manual = None, math.nan, math.nan
        reason |= R.RC["CONSEQUENCE_CLASS_UNDEFINED"]
    kappa_u = 0.0 if (T == T and T >= prof["unknown_gate_t"]) else prof["kappa_unknown"]

    import prc_schema as SC
    well_formed = []
    for i, fam in enumerate(families):
        if not (isinstance(fam, dict) and isinstance(fam.get("family_id"), str) and fam["family_id"]
                and isinstance(fam.get("members"), list)):
            audit.append({"event": "FAMILY_MALFORMED", "index": i})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        well_formed.append(fam)
    for fam in sorted(well_formed, key=lambda x: _utf8(x["family_id"])):
        fid = fam["family_id"]
        # structurally invalid members never reach membership: they are quarantined like unlisted ones
        bad_members = [m for m in fam["members"] if SC.member_errors(m)]
        for _ in bad_members:
            audit.append({"event": "MEMBER_QUARANTINED", "family": fid, "evidence_id": None, "detail": "malformed member"})
        fam = dict(fam, members=[m for m in fam["members"] if not SC.member_errors(m)])
        m_out, m_detail, members, quarantined, ingress = PM.family_membership(fam, trust, tau_eval)
        for eid, why in quarantined:
            audit.append({"event": "MEMBER_QUARANTINED", "family": fid, "evidence_id": eid, "detail": why})
        if m_out == "UNVERIFIED":
            fam_out[fid] = {"eligible": False, "status": "MEMBERSHIP_UNVERIFIED", "detail": m_detail}
            audit.append({"event": "MEMBERSHIP_UNVERIFIED", "family": fid, "detail": m_detail})
            reason |= R.RC["MEMBERSHIP_UNVERIFIED"]
            continue
        if m_out == "TAMPERED":
            fam_out[fid] = {"eligible": False, "status": "INVALIDATED", "cause": "MEMBERSHIP_TAMPERED", "detail": m_detail}
            audit.append({"event": "MEMBERSHIP_TAMPERED", "family": fid, "detail": m_detail})
            reason |= R.RC["MEMBERSHIP_TAMPERED"] | R.RC["FAMILY_INVALIDATED"]
            continue
        sub = {"family_id": fid, "members": members}
        root, depth, err = S.canonical_representative(sub)
        if err:
            fam_out[fid] = {"eligible": False, "status": "MALFORMED", "error": err}
            audit.append({"event": "LINEAGE_CLASS_MALFORMED", "family": fid, "detail": err})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        prov = {m["evidence_id"]: PV.admissibility(m, trust, pol, tau_eval)
                for m in sorted(members, key=lambda x: _utf8(x["evidence_id"]))}
        prov_out = {eid: {"outcome": o, "detail": d} for eid, (o, d, _) in prov.items()}

        # adverse evidence (A-1): classified before, and independently of, positive support
        for m in sorted(members, key=lambda x: _utf8(x["evidence_id"])):
            if m.get("state") != "CONTRADICTORY":
                continue
            outcome = prov[m["evidence_id"]][0]
            if outcome == "TAMPERED":
                raise_disp("LOCK")
                audit.append({"event": "TAMPERED_CONTRADICTION", "family": fid, "evidence_id": m["evidence_id"]})
                continue
            relevant = m.get("conflict_type") in trust.get("conflict_types", []) and m.get("contradicts") == binding
            if not relevant:
                audit.append({"event": "IRRELEVANT_CONTRADICTION", "family": fid, "evidence_id": m["evidence_id"]})
                continue
            level = "DEFEAT" if outcome == "ADMITTED" else "CONTAIN"
            raise_disp(level)
            dg = contradiction_digest(m)
            rec = obligations.setdefault(dg, {"digest": dg, "disposition": level, "conflict_type": m["conflict_type"],
                                              "occurrences": []})
            if PRECEDENCE[level] > PRECEDENCE[rec["disposition"]]:
                rec["disposition"] = level
            rec["occurrences"].append({"family": fid, "evidence_id": m["evidence_id"], "ingress_channel": ingress,
                                       "provenance": outcome})

        tampered = [(eid, d) for eid, (o, d, _) in prov.items() if o == "TAMPERED"]
        if tampered:
            fam_out[fid] = {"eligible": False, "status": "INVALIDATED", "cause": "PROVENANCE_TAMPERED",
                            "representative": root["evidence_id"], "provenance": prov_out}
            audit.append({"event": "PROVENANCE_TAMPERED", "family": fid,
                          "members": [{"evidence_id": e, "detail": d} for e, d in tampered]})
            reason |= R.RC["PROVENANCE_TAMPERED"] | R.RC["FAMILY_INVALIDATED"]
            continue
        optional = [m for m in members if m["evidence_id"] != root["evidence_id"]]
        states = [m.get("state", "VALID") for m in optional]
        root_state = root.get("state", "VALID")
        if "INVALID" in states or root_state == "INVALID":
            fam_out[fid] = {"eligible": False, "status": "INVALIDATED", "representative": root["evidence_id"],
                            "provenance": prov_out}
            audit.append({"event": "FAMILY_INVALIDATED", "family": fid})
            reason |= R.RC["FAMILY_INVALIDATED"]
            continue
        if root_state != "VALID":  # includes a contradicting root: no admissible positive support
            fam_out[fid] = {"eligible": False, "status": "REPRESENTATIVE_" + root_state,
                            "representative": root["evidence_id"], "provenance": prov_out}
            continue
        V_rep = f(root["value_bits"])
        if not 0.0 <= V_rep <= 1.0:
            fam_out[fid] = {"eligible": False, "status": "MALFORMED", "error": "value outside [0, 1]"}
            audit.append({"event": "LINEAGE_CLASS_MALFORMED", "family": fid, "detail": "value outside [0, 1]"})
            reason |= R.RC["LINEAGE_CLASS_MALFORMED"]
            continue
        # contradicting members are excluded from support and do not alter A
        factors = [prof["kappa_degraded"] if s == "DEGRADED" else 1.0
                   for s in states if s not in ("UNAVAILABLE_OR_STALE", "CONTRADICTORY")]
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
            "eligible": True, "status": "ELIGIBLE", "representative": root["evidence_id"],
            "representative_digest": PV.evidence_digest(root), "lineage_depth": dict(sorted(depth.items())),
            "provenance": prov_out, "ingress_channel": ingress,
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
    chk_m = R.authorization_check(R.bits_of(C), R.bits_of(T_manual))
    if chk["safe_state_lock"]:
        raise_disp("LOCK")

    if disposition == "LOCK":
        decision = "DENY"
        reason |= R.RC["SAFE_STATE_LOCK"]
    elif disposition == "DEFEAT":
        decision = "DENY"
        reason |= R.RC["DEFEATER_PRESENT"]
    elif disposition == "CONTAIN":
        reason |= R.RC["ADVERSE_CONTAINMENT"]
        decision = "MANUAL_REQUIRED" if chk_m["result"] else "DENY"
        if not chk_m["result"]:
            reason |= R.RC["THRESHOLD_NOT_MET"]
    else:
        decision = "ALLOW" if chk["result"] else "DENY"
        if not chk["result"]:
            reason |= R.RC["THRESHOLD_NOT_MET"]
    if reason & R.RC["CONSEQUENCE_CLASS_UNDEFINED"]:
        decision = "DENY"
    obl = [obligations[k] for k in sorted(obligations)]
    containment = [o["digest"] for o in obl if o["disposition"] == "CONTAIN"]
    return {
        "stage": "PROFILE",
        "scoring_profile": PROFILE_ID,
        "profile_fingerprint": prof["fingerprint"],
        "trust_state_hash": R.H(trust),
        "action": action,
        "tau_eval": tau_eval,
        "families": fam_out,
        "eligible_families": [e[0] for e in eligible],
        "atom_credit_bits": {d: hx(best[d]) for d in sorted(best, key=_utf8)},
        "atom_owner": {d: owner[d] for d in sorted(owner, key=_utf8)},
        "adverse_disposition": disposition,
        "adverse_obligations": obl,
        "containment_digest": R.H(containment) if containment else R.NULL_CONTAINMENT_DIGEST,
        "kappa_unknown_effective_bits": hx(kappa_u),
        "gamma_bits": hx(g) if g is not None else None,
        "M_bits": hx(M),
        "C_bits": f"{chk['c_effective_bits']:016x}",
        "T_bits": hx(T),
        "T_manual_bits": hx(T_manual),
        "safe_state_lock": disposition == "LOCK",
        "decision": decision,
        "reason_bitfield": reason,
        "reason_codes": R.reason_names(reason),
        "audit_events": audit,
    }
