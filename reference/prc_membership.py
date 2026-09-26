"""
prc_membership — M-1 FamilyMembershipAdmissible (spec 0.3.0-alpha §2.6)

Family membership is asserted by a *family manifest* signed by a membership authority
(K_membership domain) — typically the ingestion gateway that received the evidence:

    domain                  "PROVENANCE-RAZOR-MEMBERSHIP-V0.3.0-Alpha"
    schema_ver, manifest_id (UUIDv7), membership_key_id, membership_trust_epoch
    authority_id            the key's registered owner
    family_id               the family this manifest governs
    ingress_channel         where the evidence entered (recorded on containment events)
    members                 [{evidence_id, evidence_digest = H(EvidenceCore(e)), parent_id}]
                            sorted by evidence_id (UTF-8), unique
    tau_issued, tau_expiry

Envelope on the family:  family["manifest"] = {"payload": ..., "signature": hex}

Family-level outcome:
    VERIFIED     manifest admissible; members are classified individually
    UNVERIFIED   no manifest / unknown key / epoch / revoked / stale / scope does not cover
                 family_id / listed member missing from the submission
                 -> family excluded from support; its contradictions are quarantined
    TAMPERED     malformed envelope or payload, wrong domain string, key from another domain,
                 bad signature, authority_id not the key's owner, manifest for another family
                 -> family INVALID, security event

Member-level outcome (only when VERIFIED):
    LISTED       evidence_digest and parent_id match the manifest
    QUARANTINED  not listed: excluded from the family entirely, audit only — it can neither
                 invalidate, attenuate, contain nor defeat the family it names
    ALTERED      listed but digest/parent differ -> family INVALID (MEMBERSHIP_TAMPERED)
"""
from __future__ import annotations

import fnmatch
from typing import Dict, Tuple

import prc_ref as R
import prc_schema as SC
import prc_provenance as PV


def make_manifest(family: dict, key: R.TestKey, authority_id: str, *, epoch: str, tau_issued: int,
                  tau_expiry: int, unix_ms: int, ingress_channel: str = "gateway:primary",
                  members=None, family_id: str = None, domain: str = R.DOMAIN_MEMBERSHIP, label: str = None) -> dict:
    if members is None:
        members = [{"evidence_id": m["evidence_id"], "evidence_digest": PV.evidence_digest(m),
                    "parent_id": m.get("parent_id")} for m in family["members"]]
    members = sorted(members, key=lambda m: m["evidence_id"].encode("utf-8"))
    payload = {
        "domain": domain,
        "schema_ver": R.SPEC_VERSION,
        "manifest_id": R.uuid7(unix_ms, "manifest|" + (label or family["family_id"] + "|" + R.H(members)[:12])),
        "membership_key_id": key.key_id,
        "membership_trust_epoch": epoch,
        "authority_id": authority_id,
        "family_id": family_id or family["family_id"],
        "ingress_channel": ingress_channel,
        "members": members,
        "tau_issued": tau_issued,
        "tau_expiry": tau_expiry,
    }
    return {"payload": payload, "signature": key.sign_digest(R.H(payload))}


def family_membership(family: dict, trust: dict, tau_eval: int):
    """Returns (family_outcome, detail, admitted_members, quarantined[(evidence_id, why)], ingress_channel).
    Never raises for malformed families or manifests."""
    env = family.get("manifest")
    if env is None:
        return "UNVERIFIED", "no family manifest", [], [], ""
    if SC.envelope_errors(env) or SC.validate(env.get("payload"), "manifest"):
        return "TAMPERED", "malformed manifest", [], [], ""
    p = env["payload"]
    if p["domain"] != R.DOMAIN_MEMBERSHIP:
        return "TAMPERED", "wrong domain string", [], [], ""
    reg = trust["key_registry"]
    entry = reg.get(p["membership_key_id"])
    if entry is None:
        return "UNVERIFIED", "unknown membership key", [], [], ""
    if entry.get("domain") != "membership":
        return "TAMPERED", f"signed with a {entry.get('domain')}-domain key", [], [], ""
    if not R.ed25519_verify(entry["public_key"], R.H(p), env["signature"]):
        return "TAMPERED", "signature invalid", [], [], ""
    if p["authority_id"] != entry.get("owner"):
        return "TAMPERED", "authority_id is not the key's registered owner", [], [], ""
    if p["family_id"] != family["family_id"]:
        return "TAMPERED", "manifest governs a different family (replayed)", [], [], ""
    ids = [m["evidence_id"] for m in p["members"]]
    if ids != sorted(set(ids), key=lambda s: s.encode("utf-8")):
        return "TAMPERED", "manifest members not canonical (sorted, unique)", [], [], ""
    if p["membership_trust_epoch"] not in entry["epochs"]:
        return "UNVERIFIED", "membership epoch not authorised", [], [], ""
    if p["manifest_id"] in trust.get("revoked_manifest_ids", []):
        return "UNVERIFIED", "manifest revoked", [], [], ""
    if not p["tau_issued"] <= tau_eval <= p["tau_expiry"]:
        return "UNVERIFIED", "manifest not fresh at tau_eval", [], [], ""
    if not any(fnmatch.fnmatchcase(family["family_id"], pat) for pat in entry.get("membership_scopes", [])):
        return "UNVERIFIED", "membership authority's scope does not cover this family", [], [], ""
    listed = {m["evidence_id"]: m for m in p["members"]}
    admitted, quarantined, altered = [], [], []
    by_id = {}
    for m in family["members"]:
        eid = m.get("evidence_id") if isinstance(m, dict) else None
        by_id.setdefault(eid if isinstance(eid, str) else None, []).append(m)
    for eid in sorted((k for k in by_id if k is not None), key=lambda s: s.encode("utf-8")):
        cands = by_id[eid]
        if eid not in listed:
            quarantined += [(eid, "not listed in the family manifest")] * len(cands)
            continue
        want = listed[eid]
        match = [m for m in cands if PV.evidence_digest(m) == want["evidence_digest"]
                 and m.get("parent_id") == want["parent_id"]]
        if match:
            admitted.append(match[0])
            # same-id impostors are quarantined, so an injected duplicate cannot trigger tampering
            quarantined += [(eid, "duplicate evidence_id not matching the manifest")] * (len(cands) - 1)
        else:
            altered.append(eid)
    quarantined += [(None, "member without evidence_id")] * len(by_id.get(None, []))
    missing = [eid for eid in listed if eid not in by_id]
    if altered:
        return "TAMPERED", f"listed member(s) altered after the manifest was issued: {', '.join(altered)}", \
            admitted, quarantined, p["ingress_channel"]
    if missing:
        return "UNVERIFIED", f"listed member(s) withheld: {', '.join(missing)}", [], quarantined, p["ingress_channel"]
    return "VERIFIED", "ok", admitted, quarantined, p["ingress_channel"]
