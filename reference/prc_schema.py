"""
prc_schema — CanonicalObjectValid(z, schema)   (spec 0.3.0-alpha §1.5)

A total function: for ANY Python value it returns a (possibly empty) list of error strings
and never raises. It runs after PRC-LP-0 decoding and before any signature or semantic
predicate. An object is canonical-object-valid iff the list is empty.

Rules common to every schema:
  * the object is a map with exactly the schema's keys (no missing, no extra)
  * every field has its declared type; bool is never accepted as an int
  * integers declared `uint` are 0 <= v <= 2^63 - 1 (this is also the 63-bit reason mask:
    bit 63 is reserved and a value with it set is negative in int64, so it is rejected)
  * `schema_ver` must be a supported version
  * digests are 64 lowercase hex characters (32 bytes); UUIDs are canonical lowercase UUIDv7
"""
from __future__ import annotations

import re
from typing import Any, List

SUPPORTED_SCHEMA_VERSIONS = ("0.3.0-alpha",)
UINT_MAX = 2**63 - 1

RE_HEX32 = re.compile(r"^[0-9a-f]{64}$")
RE_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
RE_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$")
RE_KEYID = re.compile(r"^kid:[a-z]+:[0-9a-f]{16}$")
RE_ATOM = re.compile(r"^[A-Z_]+:\S+$")
RE_SIG = re.compile(r"^[0-9a-f]{128}$")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _check(kind: str, v: Any) -> str:
    """Return '' if v conforms to kind, else a short reason."""
    if kind == "str":
        return "" if isinstance(v, str) and v != "" else "non-empty string"
    if kind == "uint":
        return "" if _is_int(v) and 0 <= v <= UINT_MAX else "integer in [0, 2^63-1]"
    if kind == "hex32":
        return "" if isinstance(v, str) and RE_HEX32.match(v) else "32-byte lowercase hex digest"
    if kind == "uuid7":
        return "" if isinstance(v, str) and RE_UUID7.match(v) else "canonical UUIDv7"
    if kind == "semver":
        return "" if isinstance(v, str) and RE_SEMVER.match(v) else "SemVer string"
    if kind == "keyid":
        return "" if isinstance(v, str) and RE_KEYID.match(v) else "key id kid:<domain>:<16 hex>"
    if kind == "schema_ver":
        return "" if v in SUPPORTED_SCHEMA_VERSIONS else "supported schema_ver"
    if kind == "bool":
        return "" if isinstance(v, bool) else "boolean"
    if kind == "map":
        return "" if isinstance(v, dict) else "map"
    if kind == "actor":
        ok = (isinstance(v, dict) and set(v) == {"id", "type"} and isinstance(v.get("id"), str) and v["id"] != ""
              and v.get("type") in ("service", "user"))
        return "" if ok else "actor {id, type in service|user}"
    if kind == "action":
        ok = isinstance(v, dict) and isinstance(v.get("action"), str) and v["action"] != ""
        return "" if ok else "action map with non-empty 'action'"
    if kind == "atoms":
        ok = isinstance(v, list) and all(isinstance(a, str) and RE_ATOM.match(a) for a in v)
        return "" if ok else "list of TYPE:id atoms"
    if kind == "manifest_members":
        if not isinstance(v, list):
            return "list of members"
        for m in v:
            if not (isinstance(m, dict) and set(m) == {"evidence_id", "evidence_digest", "parent_id"}
                    and isinstance(m["evidence_id"], str) and m["evidence_id"] != ""
                    and isinstance(m["evidence_digest"], str) and RE_HEX32.match(m["evidence_digest"])
                    and (m["parent_id"] is None or (isinstance(m["parent_id"], str) and m["parent_id"] != ""))):
                return "members [{evidence_id, evidence_digest, parent_id}]"
        return ""
    if kind.startswith("enum:"):
        return "" if v in kind[5:].split("|") else f"one of {kind[5:]}"
    if kind.startswith("opt_"):
        return "" if v is None else _check(kind[4:], v)
    return f"unknown schema kind {kind}"


SCHEMAS = {
    "decision": {
        "domain": "str", "schema_ver": "schema_ver", "profile_version": "semver", "lineage_schema_version": "semver",
        "capability_id": "uuid7", "req_id": "uuid7", "evidence_snapshot_id": "uuid7", "actor": "actor",
        "auth_mode": "enum:AUTOMATED|MANUAL", "x": "action", "a": "map", "target": "str", "state_ver": "uint",
        "control_profile_hash": "hex32", "scoring_profile_hash": "hex32", "trust_state_hash": "hex32",
        "evidence_hash": "hex32", "lineage_hash": "hex32", "approval_hash": "hex32",
        "adverse_disposition": "enum:CLEAR|CONTAIN", "containment_digest": "hex32",
        "decision_key_id": "keyid", "decision_trust_epoch": "str", "eval_clock_id": "str",
        "tau_eval": "uint", "tau_expiry": "uint", "decision": "enum:ALLOW|DENY", "reason_codes": "uint",
    },
    "approval": {
        "domain": "str", "schema_ver": "schema_ver", "approval_id": "uuid7", "approval_key_id": "keyid",
        "approval_trust_epoch": "str", "authority_class": "str", "authority_scope": "str", "x": "action", "a": "map",
        "target": "str", "actor": "actor", "req_id": "uuid7", "capability_id": "uuid7", "state_ver": "uint",
        "control_profile_hash": "hex32", "scoring_profile_hash": "hex32", "trust_state_hash": "hex32",
        "adverse_disposition": "enum:CLEAR|CONTAIN", "containment_digest": "hex32",
        "tau_issued": "uint", "tau_expiry": "uint", "decision": "enum:ALLOW|DENY",
    },
    "receipt": {
        "domain": "str", "schema_ver": "schema_ver", "receipt_id": "uuid7", "capability_id": "uuid7", "req_id": "uuid7",
        "decision_digest": "hex32", "x": "action", "target": "str", "control_profile_hash": "hex32",
        "expected_state_ver": "uint", "observed_pre_state_ver": "uint", "observed_post_state_ver": "opt_uint",
        "execution_status": "enum:COMMITTED|ROLLED_BACK|REJECTED|INDETERMINATE|UNRESOLVED",
        "failure_phase": "enum:PREPARE|PRECONDITION|DISPATCH|TARGET|RECONCILIATION|NONE",
        "reason_code": "uint", "reconciliation_required": "bool", "pre_state_digest": "hex32",
        "post_state_digest": "hex32", "tau_dispatch": "uint", "tau_finalized": "uint",
        "receipt_key_id": "keyid", "receipt_trust_epoch": "str",
    },
    "attestation": {
        "domain": "str", "schema_ver": "schema_ver", "attestation_id": "uuid7", "provenance_key_id": "keyid",
        "provenance_trust_epoch": "str", "attester_id": "str", "evidence_digest": "hex32", "dependencies": "atoms",
        "tau_issued": "uint", "tau_expiry": "uint",
    },
    "manifest": {
        "domain": "str", "schema_ver": "schema_ver", "manifest_id": "uuid7", "membership_key_id": "keyid",
        "membership_trust_epoch": "str", "authority_id": "str", "family_id": "str", "ingress_channel": "str",
        "members": "manifest_members", "tau_issued": "uint", "tau_expiry": "uint",
    },
}

RE_BITS64 = re.compile(r"^[0-9a-f]{16}$")
MEMBER_STATES = ("VALID", "UNAVAILABLE_OR_STALE", "DEGRADED", "CONTRADICTORY", "INVALID")


def member_errors(m: Any) -> List[str]:
    """Structural validity of an evidence member (open schema: extra claim fields are allowed)."""
    if not isinstance(m, dict):
        return ["member: not a map"]
    errs = []
    if not (isinstance(m.get("evidence_id"), str) and m["evidence_id"]):
        errs.append("member.evidence_id: expected non-empty string")
    if "parent_id" not in m or not (m["parent_id"] is None or (isinstance(m["parent_id"], str) and m["parent_id"])):
        errs.append("member.parent_id: expected null or non-empty string")
    if not (isinstance(m.get("producer"), str) and m["producer"]):
        errs.append("member.producer: expected non-empty string")
    if not (isinstance(m.get("value_bits"), str) and RE_BITS64.match(m["value_bits"])):
        errs.append("member.value_bits: expected 16 lowercase hex digits")
    if "state" in m and m["state"] not in MEMBER_STATES:
        errs.append("member.state: unknown state")
    if "dependencies" in m and not isinstance(m["dependencies"], list):
        errs.append("member.dependencies: expected list")
    return errs


# Signed-envelope shape shared by attestations and manifests
def envelope_errors(env: Any) -> List[str]:
    if not isinstance(env, dict) or set(env) != {"payload", "signature"}:
        return ["envelope must be exactly {payload, signature}"]
    if not isinstance(env.get("signature"), str) or not RE_SIG.match(env["signature"]):
        return ["signature must be 64 bytes of lowercase hex"]
    return []


def validate(z: Any, schema: str) -> List[str]:
    """CanonicalObjectValid(z, schema): [] iff valid. Never raises."""
    try:
        spec = SCHEMAS[schema]
    except KeyError:
        return [f"unknown schema {schema!r}"]
    if not isinstance(z, dict):
        return [f"{schema}: not a map"]
    errs = []
    keys = set(z)
    for k in sorted(set(spec) - keys):
        errs.append(f"{schema}.{k}: missing")
    for k in sorted(keys - set(spec), key=lambda s: str(s)):
        errs.append(f"{schema}.{k}: unexpected field")
    for k in sorted(set(spec) & keys):
        why = _check(spec[k], z[k])
        if why:
            errs.append(f"{schema}.{k}: expected {why}")
    return errs
