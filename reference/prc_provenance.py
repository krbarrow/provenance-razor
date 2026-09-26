"""
prc_provenance — P-1 verified provenance (proposed normative, spec 0.2.0-alpha §2.4).

A dependency atom is admissible only when it arrives in a provenance attestation that
passes DependencyAdmissible. Self-declared `dependencies` on evidence are never read.

Attestation payload (canonical PRC-LP-0 map, signed detached):

    domain                  "PROVENANCE-RAZOR-PROVENANCE-V0.2.0-Alpha"
    schema_ver              spec version
    attestation_id          UUIDv7
    provenance_key_id       KeyID in the K_provenance domain
    provenance_trust_epoch  EpochID
    attester_id             identity the key is registered to
    evidence_digest         H(EvidenceCore(e))  — the member without `provenance`/`dependencies`
    dependencies            ascending (UTF-8), duplicate-free list of "TYPE:id"
    tau_issued, tau_expiry  int64 µs UTC

Envelope carried on the evidence member:  {"payload": <attestation>, "signature": hex}
with signature = Ed25519(sk, H(payload)). The signature is never inside the signed bytes.

Outcomes of admissibility:

    ADMITTED      atoms usable (after alias resolution)
    UNATTESTED    no envelope                                  -> UNKNOWN:* sink
    INADMISSIBLE  well-formed but not acceptable (unknown attester, stale, revoked,
                  self-attested, unauthorised type, unregistered atom, cap exceeded,
                  non-canonical list)                          -> UNKNOWN:* sink
    TAMPERED      evidence of forgery or mis-binding (bad signature, digest mismatch,
                  wrong domain string, key from another domain, attester_id not the
                  key's registered owner, malformed envelope)  -> family INVALID (§2.2)
"""
from __future__ import annotations

from typing import Optional, Tuple

import prc_ref as R
import prc_scoring as S

REQUIRED = ("domain", "schema_ver", "attestation_id", "provenance_key_id", "provenance_trust_epoch",
            "attester_id", "evidence_digest", "dependencies", "tau_issued", "tau_expiry")


def evidence_core(member: dict) -> dict:
    return {k: v for k, v in member.items() if k not in ("provenance", "dependencies")}


def evidence_digest(member: dict) -> str:
    return R.H(evidence_core(member))


def make_attestation(member: dict, key: R.TestKey, attester_id: str, deps, *, epoch: str,
                     tau_issued: int, tau_expiry: int, unix_ms: int, label: str,
                     digest_override: Optional[str] = None, sort_deps: bool = True,
                     domain: str = R.DOMAIN_PROVENANCE) -> dict:
    dl = sorted(set(deps), key=lambda a: a.encode("utf-8")) if sort_deps else list(deps)
    payload = {
        "domain": domain,
        "schema_ver": R.SPEC_VERSION,
        "attestation_id": R.uuid7(unix_ms, "att|" + label),
        "provenance_key_id": key.key_id,
        "provenance_trust_epoch": epoch,
        "attester_id": attester_id,
        "evidence_digest": digest_override or evidence_digest(member),
        "dependencies": dl,
        "tau_issued": tau_issued,
        "tau_expiry": tau_expiry,
    }
    return {"payload": payload, "signature": key.sign_digest(R.H(payload))}


def _utf8(s):
    return s.encode("utf-8")


def admissibility(member: dict, trust: dict, prof: dict, tau_eval: int) -> Tuple[str, str, Optional[frozenset]]:
    """DependencyAdmissible(d, e, profile). Returns (outcome, detail, resolved atoms | None)."""
    env = member.get("provenance")
    if env is None:
        return "UNATTESTED", "no provenance attestation", None
    import prc_schema as SC
    if SC.envelope_errors(env):
        return "TAMPERED", "malformed attestation envelope", None
    p, sig = env["payload"], env["signature"]
    if SC.validate(p, "attestation"):
        return "TAMPERED", "attestation payload fails CanonicalObjectValid", None
    if p["domain"] != R.DOMAIN_PROVENANCE:
        return "TAMPERED", "wrong domain string", None
    reg = trust.get("key_registry", trust.get("registry", {}))   # 0.3.0 trust state | 0.2.x registry
    entry = reg.get(p["provenance_key_id"])
    if entry is None:
        return "INADMISSIBLE", "unknown attester key", None
    if entry["domain"] != "provenance":
        return "TAMPERED", f"signed with a {entry['domain']}-domain key", None
    if not R.ed25519_verify(entry["public_key"], R.H(p), sig):
        return "TAMPERED", "signature invalid", None
    if p["attester_id"] != entry.get("owner", entry.get("attester_id")):
        return "TAMPERED", "attester_id is not the key's registered owner", None
    if p["evidence_digest"] != evidence_digest(member):
        return "TAMPERED", "evidence_digest does not match this evidence", None
    if p["provenance_trust_epoch"] not in entry["epochs"]:
        return "INADMISSIBLE", "trust epoch not authorised", None
    if p["attestation_id"] in trust.get("revoked_attestation_ids", []):
        return "INADMISSIBLE", "attestation revoked", None
    if not p["tau_issued"] <= tau_eval <= p["tau_expiry"]:
        return "INADMISSIBLE", "attestation not fresh at tau_eval", None
    if prof["attester_independence_required"] and p["attester_id"] == member.get("producer"):
        return "INADMISSIBLE", "self-attested (attester is the evidence producer)", None
    deps = p["dependencies"]
    if deps != sorted(set(deps), key=_utf8):
        return "INADMISSIBLE", "dependency list not canonical (sorted, unique)", None
    resolved = set()
    for a in deps:
        m = S.ATOM_RE.match(a) if isinstance(a, str) else None
        if not m or m.group(1) not in S.DEPENDENCY_TYPES:
            return "INADMISSIBLE", f"malformed atom {a!r}", None
        if m.group(1) not in entry.get("authorized_atom_types", []):
            return "INADMISSIBLE", f"attester not authorised for {m.group(1)}", None
        c = prof["aliases"].get(a, a)
        if c not in prof["registered_atoms"]:
            return "INADMISSIBLE", f"unregistered atom {a}", None
        resolved.add(c)
    counts = {}
    for c in resolved:
        t = c.split(":", 1)[0]
        counts[t] = counts.get(t, 0) + 1
    for t, n in counts.items():
        if n > prof["max_atoms_per_type"].get(t, 0):
            return "INADMISSIBLE", f"{n} {t} atoms exceed cap {prof['max_atoms_per_type'].get(t, 0)}", None
    return "ADMITTED", "ok", frozenset(resolved)
