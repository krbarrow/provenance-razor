"""
prc_ref — Python reference model for the Provenance Razor Control Specification v0.3.0-alpha.

This module is the executable interpretation used to generate and check conformance
vectors. Where the specification is silent or ambiguous, the choice made here is
recorded in docs/CONFORMANCE_ASSUMPTIONS.md with an identifier (A-xx). Those choices
are provisional and must be ratified (or replaced) in the normative text.

Nothing in this module reads the wall clock or a random source. Every output is a
pure function of its inputs, so vectors regenerate byte-for-byte.
"""
from __future__ import annotations

import fnmatch
import hashlib
import math
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

SPEC_VERSION = "0.3.0-alpha"
ENCODING_ID = "PRC-LP-0"

DOMAIN_APPROVAL = "PROVENANCE-RAZOR-APPROVAL-V0.3.0-Alpha"
DOMAIN_DECISION = "PROVENANCE-RAZOR-DECISION-V0.3.0-Alpha"
DOMAIN_RECEIPT = "PROVENANCE-RAZOR-RECEIPT-V0.3.0-Alpha"
DOMAIN_PROVENANCE = "PROVENANCE-RAZOR-PROVENANCE-V0.3.0-Alpha"   # §2.4 P-1 (new in 0.2.0)
DOMAIN_MEMBERSHIP = "PROVENANCE-RAZOR-MEMBERSHIP-V0.3.0-Alpha"   # §2.6 M-1 (new in 0.3.0)
NO_CONTAINMENT_LABEL = "PROVENANCE-RAZOR-NO-CONTAINMENT-V0.3.0-Alpha"
NO_APPROVAL_LABEL = "PROVENANCE-RAZOR-NO-APPROVAL-V0.3.0-Alpha"
NO_STATE_LABEL = "PROVENANCE-RAZOR-NO-STATE-V0.3.0-Alpha"

KEY_DOMAINS = ("profile", "approval", "decision", "receipt", "provenance", "membership")

# ---------------------------------------------------------------------------
# 1. Canonical encoding  (A-01: PRC-LP-0 tag/length/value encoding)
# ---------------------------------------------------------------------------
#   value   := tag:u8 || len:u64be || payload[len]
#   0x00 null     len=0
#   0x01 false    len=0
#   0x02 true     len=0
#   0x10 int      len=8   signed two's complement, big-endian (int64 range only)
#   0x11 f64      len=8   IEEE 754 binary64 bit pattern, big-endian (no normalisation)
#   0x20 string   UTF-8 bytes (must be valid UTF-8)
#   0x21 bytes    raw bytes
#   0x30 list     concatenation of encoded items
#   0x31 map      concatenation of (encoded string key, encoded value) pairs,
#                 keys strictly ascending by UTF-8 byte order, no duplicates
T_NULL, T_FALSE, T_TRUE = 0x00, 0x01, 0x02
T_INT, T_F64 = 0x10, 0x11
T_STR, T_BYTES = 0x20, 0x21
T_LIST, T_MAP = 0x30, 0x31

INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1


class F64:
    """Explicit binary64 wrapper so a float's exact bit pattern (incl. NaN payloads) survives."""

    __slots__ = ("bits",)

    def __init__(self, bits: int):
        self.bits = bits & 0xFFFFFFFFFFFFFFFF

    @classmethod
    def of(cls, x: float) -> "F64":
        return cls(struct.unpack(">Q", struct.pack(">d", x))[0])

    def __eq__(self, other):
        return isinstance(other, F64) and other.bits == self.bits

    def __repr__(self):
        return f"F64(0x{self.bits:016x})"


class CanonicalDecodeError(ValueError):
    pass


def _frame(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + struct.pack(">Q", len(payload)) + payload


def encode(v: Any) -> bytes:
    if v is None:
        return _frame(T_NULL, b"")
    if v is True:
        return _frame(T_TRUE, b"")
    if v is False:
        return _frame(T_FALSE, b"")
    if isinstance(v, int):
        if not INT64_MIN <= v <= INT64_MAX:
            raise ValueError(f"int out of int64 range: {v}")
        return _frame(T_INT, struct.pack(">q", v))
    if isinstance(v, F64):
        return _frame(T_F64, struct.pack(">Q", v.bits))
    if isinstance(v, float):
        return _frame(T_F64, struct.pack(">d", v))
    if isinstance(v, str):
        return _frame(T_STR, v.encode("utf-8"))
    if isinstance(v, (bytes, bytearray)):
        return _frame(T_BYTES, bytes(v))
    if isinstance(v, (list, tuple)):
        return _frame(T_LIST, b"".join(encode(i) for i in v))
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise ValueError("map keys must be strings")
        keys = sorted(v.keys(), key=lambda s: s.encode("utf-8"))
        return _frame(T_MAP, b"".join(encode(k) + encode(v[k]) for k in keys))
    raise TypeError(f"unencodable type: {type(v).__name__}")


def _decode_at(buf: bytes, pos: int) -> Tuple[Any, int]:
    if pos + 9 > len(buf):
        raise CanonicalDecodeError("truncated header")
    tag = buf[pos]
    (ln,) = struct.unpack(">Q", buf[pos + 1 : pos + 9])
    start, end = pos + 9, pos + 9 + ln
    if end > len(buf):
        raise CanonicalDecodeError("length exceeds buffer")
    body = buf[start:end]
    if tag in (T_NULL, T_FALSE, T_TRUE):
        if ln != 0:
            raise CanonicalDecodeError("non-zero length for null/bool")
        return {T_NULL: None, T_FALSE: False, T_TRUE: True}[tag], end
    if tag == T_INT:
        if ln != 8:
            raise CanonicalDecodeError("int length != 8")
        return struct.unpack(">q", body)[0], end
    if tag == T_F64:
        if ln != 8:
            raise CanonicalDecodeError("f64 length != 8")
        return F64(struct.unpack(">Q", body)[0]), end
    if tag == T_STR:
        try:
            return body.decode("utf-8", errors="strict"), end
        except UnicodeDecodeError as e:
            raise CanonicalDecodeError("invalid UTF-8") from e
    if tag == T_BYTES:
        return bytes(body), end
    if tag == T_LIST:
        items, p = [], start
        while p < end:
            item, p = _decode_at(buf[:end], p)
            items.append(item)
        return items, end
    if tag == T_MAP:
        out, p, prev = {}, start, None
        while p < end:
            k, p = _decode_at(buf[:end], p)
            if not isinstance(k, str):
                raise CanonicalDecodeError("map key is not a string")
            kb = k.encode("utf-8")
            if prev is not None and kb <= prev:
                raise CanonicalDecodeError("map keys not strictly ascending (unsorted or duplicate)")
            prev = kb
            if p >= end:
                raise CanonicalDecodeError("map key without value")
            val, p = _decode_at(buf[:end], p)
            out[k] = val
        return out, end
    raise CanonicalDecodeError(f"unknown tag 0x{tag:02x}")


def decode(buf: bytes) -> Any:
    """Strict decoder: rejects anything that is not the unique canonical encoding."""
    v, end = _decode_at(buf, 0)
    if end != len(buf):
        raise CanonicalDecodeError("trailing bytes")
    if encode(v) != buf:  # belt and braces: round-trip must be exact
        raise CanonicalDecodeError("round-trip mismatch")
    return v


def H(v: Any) -> str:
    """H(z) = SHA256(CanonicalEncode(z)), returned as lowercase hex (A-02: single encoding layer)."""
    return hashlib.sha256(encode(v)).hexdigest()


def H_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


NULL_APPROVAL_DIGEST = H(NO_APPROVAL_LABEL)
NULL_STATE_DIGEST = H(NO_STATE_LABEL)
NULL_CONTAINMENT_DIGEST = H(NO_CONTAINMENT_LABEL)

# ---------------------------------------------------------------------------
# Deterministic identifiers and test keys
# ---------------------------------------------------------------------------


def uuid7(unix_ms: int, label: str) -> str:
    """RFC 9562 UUIDv7 with the 74 'random' bits derived from SHA256(label) (deterministic)."""
    r = int.from_bytes(hashlib.sha256(("PRC-UUID7|" + label).encode()).digest()[:10], "big")
    rand_a = (r >> 68) & 0xFFF
    rand_b = r & ((1 << 62) - 1)
    val = (unix_ms & ((1 << 48) - 1)) << 80
    val |= 0x7 << 76
    val |= rand_a << 64
    val |= 0b10 << 62
    val |= rand_b
    h = f"{val:032x}"
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


@dataclass
class TestKey:
    domain: str
    label: str
    seed: bytes
    private: Ed25519PrivateKey = field(repr=False)
    public_hex: str = ""
    key_id: str = ""

    @classmethod
    def derive(cls, domain: str, label: str) -> "TestKey":
        assert domain in KEY_DOMAINS
        seed = hashlib.sha256(f"PRC-TEST-KEY|{domain}|{label}".encode()).digest()
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        kid = f"kid:{domain}:{hashlib.sha256(pub).hexdigest()[:16]}"
        return cls(domain, label, seed, priv, pub.hex(), kid)

    def sign_digest(self, digest_hex: str) -> str:
        # Ed25519 is deterministic (RFC 8032), so signatures are stable golden values.
        return self.private.sign(bytes.fromhex(digest_hex)).hex()


def ed25519_verify(pub_hex: str, digest_hex: str, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), bytes.fromhex(digest_hex)
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# Reason-code registry (A-03: provisional bit assignments)
# ---------------------------------------------------------------------------
REASON_BITS = [
    "DECODE_INVALID",              # 0
    "SIGNATURE_INVALID",           # 1
    "DOMAIN_MISMATCH",             # 2
    "ACTION_MISMATCH",             # 3
    "ASSERTION_MISMATCH",          # 4
    "TARGET_MISMATCH",             # 5
    "STATE_VERSION_MISMATCH",      # 6
    "PROFILE_HASH_MISMATCH",       # 7
    "EVIDENCE_HASH_MISMATCH",      # 8
    "LINEAGE_HASH_MISMATCH",       # 9
    "DECISION_NOT_ALLOW",          # 10
    "NOT_YET_VALID",               # 11
    "EXPIRED_CAPABILITY",          # 12
    "EVAL_SKEW_EXCEEDED",          # 13
    "DECISION_KEY_UNAUTHORIZED",   # 14
    "CAPABILITY_UNAVAILABLE",      # 15
    "AUTH_MODE_INVALID",           # 16
    "APPROVAL_SIGNATURE_INVALID",  # 17
    "APPROVAL_DOMAIN_MISMATCH",    # 18
    "APPROVAL_KEY_UNAUTHORIZED",   # 19
    "APPROVAL_SCOPE_DENIED",       # 20
    "APPROVAL_BINDING_MISMATCH",   # 21
    "APPROVAL_EXPIRED",            # 22
    "APPROVAL_CONSUMED",           # 23
    "APPROVAL_HASH_MISMATCH",      # 24
    "SAFE_STATE_LOCK",             # 25
    "THRESHOLD_NOT_MET",           # 26
    "FAMILY_INVALIDATED",          # 27
    "NO_ELIGIBLE_EVIDENCE",        # 28
    "CAS_PRECONDITION_FAILED",     # 29
    "TARGET_REJECTED",             # 30
    "DISPATCH_TIMEOUT",            # 31
    "RECONCILIATION_UNRESOLVED",   # 32
    "LINEAGE_CLASS_MALFORMED",     # 33  (scoring profile)
    "CONSEQUENCE_CLASS_UNDEFINED", # 34  (scoring profile)
    "NONFINITE_INPUT",             # 35  (engine guard, E-1)
    "APPROVAL_SUBJECT_MISMATCH",   # 36  p.target/actor/req_id/capability_id != d (closes G-01, G-03)
    "APPROVAL_NOT_YET_VALID",      # 37  p.tau_issued > d.tau_eval (closes G-02)
    "DEFEATER_PRESENT",            # 38  authenticated contradicting evidence (categorical veto)
    "PROVENANCE_TAMPERED",         # 39  attestation signature/digest failure -> family invalidated
    "OBJECT_SCHEMA_INVALID",       # 40  CanonicalObjectValid failed for d                       (0.3.0)
    "APPROVAL_SCHEMA_INVALID",     # 41  CanonicalObjectValid failed for p                       (0.3.0)
    "TRUST_STATE_MISMATCH",        # 42  d.trust_state_hash != evaluated trust state              (0.3.0)
    "SCORING_PROFILE_MISMATCH",    # 43  d.scoring_profile_hash != active scoring profile         (0.3.0)
    "ADVERSE_DISPOSITION_MISMATCH",# 44  d.adverse_disposition / containment_digest != current    (0.3.0)
    "ADVERSE_CONTAINMENT",         # 45  unresolved adverse claim: automatic ALLOW prohibited     (0.3.0)
    "CLOCK_UNTRUSTED",             # 46  unregistered clock or uncertainty above its authority    (0.3.0)
    "MEMBERSHIP_UNVERIFIED",       # 47  family has no admissible manifest -> excluded            (0.3.0)
    "MEMBERSHIP_TAMPERED",         # 48  manifest forged / replayed / member altered              (0.3.0)
    "VERIFIER_FAULT",              # 49  a verifier raised; converted to DENY at the boundary     (0.3.0)
]
assert len(REASON_BITS) <= 63, "bit 63 is reserved: reason masks are non-negative int64"
RC = {name: 1 << i for i, name in enumerate(REASON_BITS)}


def reason_names(bits: int) -> List[str]:
    return [n for i, n in enumerate(REASON_BITS) if bits >> i & 1]


# ---------------------------------------------------------------------------
# Trust registry
# ---------------------------------------------------------------------------


def registry_entry(key: TestKey, epochs: List[str], authority_classes: Optional[List[str]] = None) -> dict:
    e = {"domain": key.domain, "public_key": key.public_hex, "epochs": sorted(epochs)}
    if authority_classes is not None:
        e["authority_classes"] = sorted(authority_classes)
    return e


def key_authorized(registry: dict, key_id: str, epoch: str, domain: str, authority_class: Optional[str] = None) -> bool:
    e = registry.get(key_id)
    if e is None or e["domain"] != domain or epoch not in e["epochs"]:
        return False
    if authority_class is not None and authority_class not in e.get("authority_classes", []):
        return False
    return True


# ---------------------------------------------------------------------------
# 1.1 Domain-scoped key resolution (0.3.0: identical for every object type)
# ---------------------------------------------------------------------------


def domain_key(registry: dict, key_id, domain: str) -> Optional[dict]:
    """Resolve key_id ONLY within `domain`. A key registered in another domain is not found."""
    e = registry.get(key_id) if isinstance(key_id, str) else None
    return e if isinstance(e, dict) and e.get("domain") == domain else None


def verify_in_domain(registry: dict, key_id, domain: str, digest_hex: str, sig_hex) -> bool:
    e = domain_key(registry, key_id, domain)
    return e is not None and isinstance(sig_hex, str) and ed25519_verify(e["public_key"], digest_hex, sig_hex)


# ---------------------------------------------------------------------------
# C-1 Clock authority (closes G-10)
# ---------------------------------------------------------------------------


def clock_bounds(trust_state: dict, eval_clock_id, exec_clock) -> Tuple[bool, int]:
    """Returns (trusted, U) with U = u_eval + u_exec, the combined worst-case uncertainty in µs.
    The evaluator's clock contributes its authority's registered maximum; the executor reports
    its current uncertainty, which must not exceed its authority's maximum."""
    clocks = trust_state.get("clock_authorities", {})
    ev = clocks.get(eval_clock_id) if isinstance(eval_clock_id, str) else None
    ex_id = exec_clock.get("clock_id") if isinstance(exec_clock, dict) else None
    ex = clocks.get(ex_id) if isinstance(ex_id, str) else None
    u_exec = exec_clock.get("uncertainty_us") if isinstance(exec_clock, dict) else None
    trusted = (ev is not None and ex is not None and isinstance(u_exec, int) and not isinstance(u_exec, bool)
               and 0 <= u_exec <= ex["max_uncertainty_us"])
    u_eval = ev["max_uncertainty_us"] if ev else 0
    return trusted, u_eval + (u_exec if isinstance(u_exec, int) and u_exec >= 0 else 0)


# ---------------------------------------------------------------------------
# 3.1 ExternalApprovalValid (0.3.0)
# ---------------------------------------------------------------------------


def external_approval_valid(ctx: dict, p_bytes_hex: str, sig_p, d: Optional[dict] = None,
                            U: int = 0) -> Tuple[bool, int, Optional[dict]]:
    import prc_schema as SC
    try:
        raw = bytes.fromhex(p_bytes_hex)
        p = decode(raw)
    except (CanonicalDecodeError, ValueError, TypeError):
        return False, RC["APPROVAL_SCHEMA_INVALID"], None
    if SC.validate(p, "approval"):
        return False, RC["APPROVAL_SCHEMA_INVALID"], None
    d = d or {}
    bits = 0
    reg = ctx["trust_state"]["key_registry"]
    kid = p["approval_key_id"]
    if not verify_in_domain(reg, kid, "approval", H_bytes(raw), sig_p):
        bits |= RC["APPROVAL_SIGNATURE_INVALID"]
    if p["domain"] != DOMAIN_APPROVAL:
        bits |= RC["APPROVAL_DOMAIN_MISMATCH"]
    if not key_authorized(reg, kid, p["approval_trust_epoch"], "approval", p["authority_class"]):
        bits |= RC["APPROVAL_KEY_UNAUTHORIZED"]
    if not fnmatch.fnmatchcase(f"{ctx['x']['action']}:{p['target']}", p["authority_scope"]):
        bits |= RC["APPROVAL_SCOPE_DENIED"]
    if (p["x"] != ctx["x"] or p["a"] != ctx["a"] or p["state_ver"] != ctx["current_state_ver"]
            or p["control_profile_hash"] != ctx["active_control_profile_hash"]
            or p["scoring_profile_hash"] != d.get("scoring_profile_hash")
            or p["trust_state_hash"] != d.get("trust_state_hash")):
        bits |= RC["APPROVAL_BINDING_MISMATCH"]
    if (p["target"] != ctx["current_target"] or p["target"] != d.get("target") or p["actor"] != d.get("actor")
            or p["req_id"] != d.get("req_id") or p["capability_id"] != d.get("capability_id")):
        bits |= RC["APPROVAL_SUBJECT_MISMATCH"]
    # the approver acknowledged exactly the adverse claims the decision carries (containment binding)
    if p["adverse_disposition"] != d.get("adverse_disposition") or p["containment_digest"] != d.get("containment_digest"):
        bits |= RC["ADVERSE_DISPOSITION_MISMATCH"]
    if not p["tau_issued"] <= d.get("tau_eval", -1):
        bits |= RC["APPROVAL_NOT_YET_VALID"]
    if not ctx["exec_clock"]["tau_exec"] + U <= p["tau_expiry"]:
        bits |= RC["APPROVAL_EXPIRED"]
    reusable = p["authority_class"] in ctx["profile"].get("reusable_authority_classes", [])
    if p["approval_id"] in ctx.get("consumed_approvals", []) and not reusable:
        bits |= RC["APPROVAL_CONSUMED"]
    return bits == 0, bits, p


# ---------------------------------------------------------------------------
# 3.4 / 3.5  AuthorizationModeValid and DecisionBindingValid (0.3.0)
# ---------------------------------------------------------------------------


def max_eval_skew_us(profile: dict, action: str) -> int:
    per = profile.get("max_eval_skew_us", {})
    return per.get(action, per["*"])


def _decision_binding_valid(ctx, d_bytes_hex, sig_d, p_bytes_hex=None, sig_p=None):
    import prc_schema as SC
    try:
        raw = bytes.fromhex(d_bytes_hex)
        d = decode(raw)
    except (CanonicalDecodeError, ValueError, TypeError):
        return False, RC["DECODE_INVALID"]
    if SC.validate(d, "decision"):
        return False, RC["OBJECT_SCHEMA_INVALID"]  # nothing semantic is evaluated on a malformed object

    bits = 0
    ts = ctx["trust_state"]
    reg = ts["key_registry"]
    if not verify_in_domain(reg, d["decision_key_id"], "decision", H_bytes(raw), sig_d):
        bits |= RC["SIGNATURE_INVALID"]
    if d["domain"] != DOMAIN_DECISION:
        bits |= RC["DOMAIN_MISMATCH"]
    if d["x"] != ctx["x"]:
        bits |= RC["ACTION_MISMATCH"]
    if d["a"] != ctx["a"]:
        bits |= RC["ASSERTION_MISMATCH"]
    if d["target"] != ctx["current_target"]:
        bits |= RC["TARGET_MISMATCH"]
    if d["state_ver"] != ctx["current_state_ver"]:
        bits |= RC["STATE_VERSION_MISMATCH"]
    if d["control_profile_hash"] != ctx["active_control_profile_hash"]:
        bits |= RC["PROFILE_HASH_MISMATCH"]
    if d["scoring_profile_hash"] != ctx["active_scoring_profile_hash"]:
        bits |= RC["SCORING_PROFILE_MISMATCH"]
    if d["trust_state_hash"] != ctx["trust_state_hash"] or d["trust_state_hash"] != H(ts):
        bits |= RC["TRUST_STATE_MISMATCH"]
    if d["evidence_hash"] != ctx["evidence_hash"]:
        bits |= RC["EVIDENCE_HASH_MISMATCH"]
    if d["lineage_hash"] != ctx["lineage_hash"]:
        bits |= RC["LINEAGE_HASH_MISMATCH"]
    if d["adverse_disposition"] != ctx["adverse_disposition"] or d["containment_digest"] != ctx["containment_digest"]:
        bits |= RC["ADVERSE_DISPOSITION_MISMATCH"]
    if (d["adverse_disposition"] == "CLEAR") != (d["containment_digest"] == NULL_CONTAINMENT_DIGEST):
        bits |= RC["ADVERSE_DISPOSITION_MISMATCH"]
    if d["decision"] != "ALLOW":
        bits |= RC["DECISION_NOT_ALLOW"]

    trusted, U = clock_bounds(ts, d["eval_clock_id"], ctx["exec_clock"])
    if not trusted:
        bits |= RC["CLOCK_UNTRUSTED"]
    t_exec, t_eval, t_exp = ctx["exec_clock"]["tau_exec"], d["tau_eval"], d["tau_expiry"]
    if not t_eval + U <= t_exec:
        bits |= RC["NOT_YET_VALID"]
    if not t_exec + U <= t_exp:
        bits |= RC["EXPIRED_CAPABILITY"]
    if not (t_exec - t_eval) + U <= max_eval_skew_us(ctx["profile"], ctx["x"]["action"]):
        bits |= RC["EVAL_SKEW_EXCEEDED"]
    if not key_authorized(reg, d["decision_key_id"], d["decision_trust_epoch"], "decision"):
        bits |= RC["DECISION_KEY_UNAUTHORIZED"]
    if d["capability_id"] in ctx.get("consumed_capabilities", []):
        bits |= RC["CAPABILITY_UNAVAILABLE"]

    # §3.4 (0.3.0): MANUAL is required for ManualOnly actions AND for contained evidence
    manual_only = ctx["x"]["action"] in ctx["profile"].get("manual_only_actions", [])
    contained = d["adverse_disposition"] == "CONTAIN"
    mode_ok = False
    if d["auth_mode"] == "AUTOMATED":
        mode_ok = (not manual_only) and (not contained) and d["approval_hash"] == NULL_APPROVAL_DIGEST
        if contained:
            bits |= RC["ADVERSE_CONTAINMENT"]
    elif p_bytes_hex is not None:
        ok_p, pbits, _ = external_approval_valid(ctx, p_bytes_hex, sig_p, d, U)
        hash_ok = isinstance(p_bytes_hex, str) and d["approval_hash"] == _safe_hash_hex(p_bytes_hex)
        if not hash_ok:
            pbits |= RC["APPROVAL_HASH_MISMATCH"]
        bits |= pbits
        mode_ok = (manual_only or contained) and hash_ok and ok_p
    if not mode_ok:
        bits |= RC["AUTH_MODE_INVALID"]
    return bits == 0, bits


def _safe_hash_hex(h):
    try:
        return H_bytes(bytes.fromhex(h))
    except (ValueError, TypeError):
        return None


def decision_binding_valid(ctx: dict, d_bytes_hex: str, sig_d, p_bytes_hex=None, sig_p=None) -> Tuple[bool, int]:
    """Total verifier boundary (0.3.0 V-1): never raises; any internal fault is a DENY."""
    try:
        return _decision_binding_valid(ctx, d_bytes_hex, sig_d, p_bytes_hex, sig_p)
    except Exception:  # noqa: BLE001 — the boundary converts faults into a structured rejection
        return False, RC["VERIFIER_FAULT"] | RC["SAFE_STATE_LOCK"]


# ---------------------------------------------------------------------------
# 2.3 Numerical comparison  (A-04, A-05)
# ---------------------------------------------------------------------------

def f64_from_bits(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits))[0]


def bits_of(x: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def _is_exceptional_bits(bits: int) -> bool:
    return (bits >> 52) & 0x7FF == 0x7FF  # exponent all ones → Inf or NaN (checked on bits, no FP op)


def _norm_zero(x: float) -> float:
    return 0.0 if x == 0.0 else x


def authorization_check(c_bits: int, t_bits: int) -> dict:
    """AuthorizationCheck(C, T) with §2.3 exception handling. Returns result, effective C bits, lock flag."""
    if _is_exceptional_bits(c_bits) or _is_exceptional_bits(t_bits):
        return {"result": False, "c_effective_bits": 0, "safe_state_lock": True}
    c = _norm_zero(f64_from_bits(c_bits))
    t = _norm_zero(f64_from_bits(t_bits))
    return {"result": c >= t, "c_effective_bits": bits_of(c), "safe_state_lock": False}


def kahan_sum(input_bits: List[int]) -> dict:
    """Informative harness op: compensated sum; any exceptional input/intermediate → 0.0 + lock."""
    if any(_is_exceptional_bits(b) for b in input_bits):
        return {"result_bits": 0, "safe_state_lock": True}
    s, c = 0.0, 0.0
    for b in input_bits:
        y = f64_from_bits(b) - c
        t = s + y
        c = (t - s) - y
        s = t
        if not math.isfinite(s) or not math.isfinite(c):
            return {"result_bits": 0, "safe_state_lock": True}
    return {"result_bits": bits_of(_norm_zero(s)), "safe_state_lock": False}


# ---------------------------------------------------------------------------
# 2.1 / 2.2 Lineage consolidation  (A-08 .. A-11)
# ---------------------------------------------------------------------------
STATE_FACTOR = {"VALID": 1.0, "CONTRADICTORY": 0.0}


def evaluate_lineage(case: dict) -> dict:
    kappa = case["kappa_degraded"]
    classes_out, audit, eligible = {}, [], []
    for cls in case["classes"]:
        cid = cls["id"]
        states = [m["state"] for m in cls.get("optional_members", [])]
        if "INVALID" in states:
            classes_out[cid] = {"eligible": False, "invalidated": True, "A": None, "V": None}
            bad = [m["id"] for m in cls["optional_members"] if m["state"] == "INVALID"]
            audit.append({"event": "FAMILY_INVALIDATED", "class": cid, "members": bad})
            continue
        factors = []
        for s in states:
            if s == "UNAVAILABLE_OR_STALE":
                continue  # excluded from positive support, A unaffected
            factors.append(kappa if s == "DEGRADED" else STATE_FACTOR[s])
        A = min(factors) if factors else 1.0
        V = cls["representative"]["value"] * A
        classes_out[cid] = {"eligible": True, "invalidated": False, "A": A, "V": V}
        eligible.append(cid)
    pair = case.get("pairwise_independence", {})
    for cid in eligible:
        if len(eligible) == 1:
            classes_out[cid]["I"] = 1.0
        else:
            classes_out[cid]["I"] = min(pair[f"{cid}|{j}"] for j in eligible if j != cid)
    out = {"classes": classes_out, "eligible": eligible, "audit_events": audit}
    if not eligible:
        out["M"], out["C"] = 0.0, 0.0
        out["reason_code"] = RC["NO_ELIGIBLE_EVIDENCE"] | (RC["FAMILY_INVALIDATED"] if audit else 0)
    else:
        out["M"], out["C"] = "UNDEFINED_BY_SPEC", "UNDEFINED_BY_SPEC"
        out["reason_code"] = RC["FAMILY_INVALIDATED"] if audit else 0
    return out


# ---------------------------------------------------------------------------
# 4. Transactions and receipts  (A-12 .. A-15)
# ---------------------------------------------------------------------------


def build_receipt(*, d: dict, d_hash: str, receipt_id: str, status: str, failure_phase: str,
                  reason: int, recon_required: bool, pre_state: dict, post_state: Optional[dict],
                  tau_dispatch: int, tau_finalized: int, key: TestKey, epoch: str) -> dict:
    """§4.3 as revised in 0.2.0 (R-1): the receipt separates what the decision *expected*
    from what the executor *observed*. `post_state` is None when the outcome is unknown
    (UNRESOLVED); then observed_post_state_ver is null and post_state_digest is NULL_STATE_DIGEST."""
    return {
        "domain": DOMAIN_RECEIPT,
        "schema_ver": SPEC_VERSION,
        "receipt_id": receipt_id,
        "capability_id": d["capability_id"],
        "req_id": d["req_id"],
        "decision_digest": d_hash,
        "x": d["x"],
        "target": d["target"],
        "control_profile_hash": d["control_profile_hash"],
        "expected_state_ver": d["state_ver"],
        "observed_pre_state_ver": pre_state["version"],
        "observed_post_state_ver": post_state["version"] if post_state is not None else None,
        "execution_status": status,
        "failure_phase": failure_phase,
        "reason_code": reason,
        "reconciliation_required": recon_required,
        "pre_state_digest": H(pre_state),
        "post_state_digest": H(post_state) if post_state is not None else NULL_STATE_DIGEST,
        "tau_dispatch": tau_dispatch,
        "tau_finalized": tau_finalized,
        "receipt_key_id": key.key_id,
        "receipt_trust_epoch": epoch,
    }


def apply_mutation(state: dict, mutation: dict) -> dict:
    data = dict(state["data"])
    data.update(mutation)
    return {"version": state["version"] + 1, "data": data}


def _res(status, phase, reason, post, consumed, recon, trace):
    return {"status": status, "phase": phase, "reason": reason, "post_state": post,
            "consumed": consumed, "recon": recon, "trace": trace}


def execute_local(state: dict, consumed: List[str], d: dict, mutation: dict) -> dict:
    """§4.1 single-phase CAS. On abort the transaction rolls back and a REJECTED receipt is
    written in a separate transaction (A-12). The state is known to be unchanged."""
    trace = ["BEGIN", f"LOCK target state_ver={d['state_ver']}"]
    if d["capability_id"] in consumed:
        trace += ["CapabilityAvailable=false", "ABORT"]
        return _res("REJECTED", "PRECONDITION", RC["CAPABILITY_UNAVAILABLE"], state, list(consumed), False, trace)
    trace.append("CapabilityAvailable=true")
    if state["version"] != d["state_ver"]:
        trace += [f"CurrentStateVersion={state['version']} != {d['state_ver']}", "ABORT"]
        return _res("REJECTED", "PRECONDITION", RC["CAS_PRECONDITION_FAILED"], state, list(consumed), False, trace)
    post = apply_mutation(state, mutation)
    trace += ["MarkCapabilityConsumed", "ApplyMutation", f"AdvanceStateVersion -> {post['version']}",
              "WriteReceipt", "COMMIT"]
    return _res("COMMITTED", "NONE", 0, post, sorted(consumed + [d["capability_id"]]), False, trace)


def execute_distributed(state: dict, reserved: List[str], d: dict, mutation: dict, target: dict) -> dict:
    """§4.2 prepare/dispatch/reconcile. `state` is the target's actual state; the *target*
    enforces State-Precondition. `target` scripts the network/target:
       {"dispatch": DELIVERED|TIMEOUT|REJECT, "reconcile": APPLIED|NOT_APPLIED|UNKNOWN}"""
    trace = []
    if d["capability_id"] in reserved:
        trace += ["PREPARE: capability already reserved/consumed", "FINALIZE REJECTED"]
        return _res("REJECTED", "PREPARE", RC["CAPABILITY_UNAVAILABLE"], state, list(reserved), False, trace)
    consumed = sorted(reserved + [d["capability_id"]])  # A-13: once reserved, never released
    trace += ["PREPARE: reserve capability_id", "PERSIST PREPARED",
              f"DISPATCH Idempotency-Key={d['capability_id']} State-Precondition={d['state_ver']}"]
    mode = target["dispatch"]
    if mode == "DELIVERED":
        if state["version"] != d["state_ver"]:
            trace += [f"TARGET CAS FAILURE observed_version={state['version']}", "FINALIZE REJECTED"]
            return _res("REJECTED", "PRECONDITION", RC["CAS_PRECONDITION_FAILED"], state, consumed, False, trace)
        post = apply_mutation(state, mutation)
        trace += ["TARGET ACK", "FINALIZE COMMITTED"]
        return _res("COMMITTED", "NONE", 0, post, consumed, False, trace)
    if mode == "REJECT":
        trace += ["TARGET REJECTION", "FINALIZE REJECTED"]
        return _res("REJECTED", "TARGET", RC["TARGET_REJECTED"], state, consumed, False, trace)
    assert mode == "TIMEOUT"
    trace += ["NETWORK TIMEOUT", "STATE INDETERMINATE", "RECONCILE"]
    rec = target["reconcile"]
    if rec == "APPLIED":
        post = apply_mutation(state, mutation)
        trace += ["RECONCILED: applied", "FINALIZE COMMITTED"]
        return _res("COMMITTED", "NONE", RC["DISPATCH_TIMEOUT"], post, consumed, False, trace)
    if rec == "NOT_APPLIED":
        trace += ["RECONCILED: not applied", "FINALIZE ROLLED_BACK"]
        return _res("ROLLED_BACK", "DISPATCH", RC["DISPATCH_TIMEOUT"], state, consumed, False, trace)
    trace += ["UNRESOLVABLE", "FINALIZE UNRESOLVED"]
    return _res("UNRESOLVED", "RECONCILIATION", RC["DISPATCH_TIMEOUT"] | RC["RECONCILIATION_UNRESOLVED"],
                None, consumed, True, trace)
