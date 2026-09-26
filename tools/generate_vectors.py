#!/usr/bin/env python3
"""
Deterministic conformance-vector generator for Provenance Razor v0.3.0-alpha.

    python tools/generate_vectors.py            # writes into ./tests
    python tools/generate_vectors.py --out DIR  # writes elsewhere (used by the determinism check)

Every case declares its *intended* outcome (from the spec text). The generator asks the
reference model for the outcome and refuses to write anything if the two disagree, so a
bug in the reference model cannot silently become a "golden" value.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reference"))
try:
    import prc_ref as R  # noqa: E402
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
except ModuleNotFoundError:
    raise SystemExit(
        "prc_ref not found. This script needs reference/prc_ref.py next to tools/ "
        "(repo layout: reference/prc_ref.py, tools/%s). In the notebook, run the "
        "'Reference model' %%%%writefile cell first, or unzip the whole repo." % os.path.basename(__file__))

import trust_fixture as TF  # noqa: E402  (single committed trust context, 0.3.0)

BASE_MS = 1767225600000            # 2026-01-01T00:00:00Z — fixed, never the wall clock
BASE_US = BASE_MS * 1000
S = 1_000_000                      # one second in microseconds
EPOCH = "epoch-2026-01"


def iso(us: int) -> str:
    return datetime.fromtimestamp(us / S, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Fixed test keys and shared material
# ---------------------------------------------------------------------------
K_PROFILE = R.TestKey.derive("profile", "k1")
K_APPROVAL = R.TestKey.derive("approval", "k1")
K_DECISION = R.TestKey.derive("decision", "k1")
K_RECEIPT = R.TestKey.derive("receipt", "k1")
KEYS = [K_PROFILE, K_APPROVAL, K_DECISION, K_RECEIPT]

REGISTRY = {
    K_PROFILE.key_id: R.registry_entry(K_PROFILE, [EPOCH]),
    K_APPROVAL.key_id: R.registry_entry(K_APPROVAL, [EPOCH], ["STANDING", "SUPERVISOR"]),
    K_DECISION.key_id: R.registry_entry(K_DECISION, [EPOCH]),
    K_RECEIPT.key_id: R.registry_entry(K_RECEIPT, [EPOCH]),
}

PROFILE = {
    "profile_version": "1.0.0",
    "manual_only_actions": ["wire.release"],
    "max_eval_skew_us": {"*": 300 * S, "payment.refund": 120 * S},
    "reusable_authority_classes": ["STANDING"],
}
PROFILE_HASH = R.H(PROFILE)

EVIDENCE = [
    {"evidence_id": R.uuid7(BASE_MS - 5000, "ev-1"), "source": "ledger", "value_bits": "3fe999999999999a"},
    {"evidence_id": R.uuid7(BASE_MS - 4000, "ev-2"), "source": "kyc", "value_bits": "3fe8000000000000"},
]
EVIDENCE_HASH = R.H(EVIDENCE)
LINEAGE = {"nodes": [e["evidence_id"] for e in EVIDENCE], "edges": []}
LINEAGE_HASH = R.H(LINEAGE)

X_REFUND = {"action": "payment.refund", "params": {"amount_minor": 12500, "currency": "USD"}}
A_REFUND = {"assertion": "refund-eligible", "subject": "order-8841"}
X_WIRE = {"action": "wire.release", "params": {"amount_minor": 9900000, "currency": "USD"}}
A_WIRE = {"assertion": "beneficiary-verified", "subject": "wire-5521"}
TARGET = "acct-000123"
ACTOR = {"id": "svc-ledger-bot", "type": "service"}
STATE_VER = 7


def decision(tag: str, **o) -> dict:
    d = {
        "domain": R.DOMAIN_DECISION,
        "schema_ver": R.SPEC_VERSION,
        "profile_version": "1.0.0",
        "lineage_schema_version": "1.0.0",
        "capability_id": R.uuid7(BASE_MS, "cap|" + tag),
        "req_id": R.uuid7(BASE_MS, "req|" + tag),
        "evidence_snapshot_id": R.uuid7(BASE_MS, "snap|" + tag),
        "actor": ACTOR,
        "auth_mode": "AUTOMATED",
        "x": X_REFUND,
        "a": A_REFUND,
        "target": TARGET,
        "state_ver": STATE_VER,
        "control_profile_hash": PROFILE_HASH,
        "scoring_profile_hash": TF.SCORING_PROFILE_HASH,
        "trust_state_hash": TF.TRUST_STATE_HASH,
        "evidence_hash": EVIDENCE_HASH,
        "lineage_hash": LINEAGE_HASH,
        "approval_hash": R.NULL_APPROVAL_DIGEST,
        "adverse_disposition": "CLEAR",
        "containment_digest": R.NULL_CONTAINMENT_DIGEST,
        "eval_clock_id": TF.CLOCK_IDEAL,
        "decision_key_id": K_DECISION.key_id,
        "decision_trust_epoch": EPOCH,
        "tau_eval": BASE_US,
        "tau_expiry": BASE_US + 600 * S,
        "decision": "ALLOW",
        "reason_codes": 0,
    }
    d.update(o)
    return d


def approval(tag: str, **o) -> dict:
    p = {
        "domain": R.DOMAIN_APPROVAL,
        "schema_ver": R.SPEC_VERSION,
        "approval_id": R.uuid7(BASE_MS - 60000, "appr|" + tag),
        "approval_key_id": K_APPROVAL.key_id,
        "approval_trust_epoch": EPOCH,
        "authority_class": "SUPERVISOR",
        "authority_scope": "wire.release:acct-*",
        "x": X_WIRE,
        "a": A_WIRE,
        "target": TARGET,
        "actor": ACTOR,
        "req_id": R.uuid7(BASE_MS, "req|" + tag),
        "capability_id": R.uuid7(BASE_MS, "cap|" + tag),
        "state_ver": STATE_VER,
        "control_profile_hash": PROFILE_HASH,
        "scoring_profile_hash": TF.SCORING_PROFILE_HASH,
        "trust_state_hash": TF.TRUST_STATE_HASH,
        "adverse_disposition": "CLEAR",
        "containment_digest": R.NULL_CONTAINMENT_DIGEST,
        "tau_issued": BASE_US - 60 * S,
        "tau_expiry": BASE_US + 900 * S,
        "decision": "ALLOW",
    }
    p.update(o)
    return p


def context(tau_exec=BASE_US + 60 * S, clock=None, uncertainty_us=0, **o) -> dict:
    c = {
        "x": X_REFUND,
        "a": A_REFUND,
        "current_target": TARGET,
        "current_state_ver": STATE_VER,
        "active_control_profile_hash": PROFILE_HASH,
        "active_scoring_profile_hash": TF.SCORING_PROFILE_HASH,
        "trust_state_hash": TF.TRUST_STATE_HASH,
        "evidence_hash": EVIDENCE_HASH,
        "lineage_hash": LINEAGE_HASH,
        "adverse_disposition": "CLEAR",
        "containment_digest": R.NULL_CONTAINMENT_DIGEST,
        "exec_clock": {"clock_id": clock or TF.CLOCK_IDEAL, "tau_exec": tau_exec, "uncertainty_us": uncertainty_us},
        "profile": PROFILE,
        "consumed_capabilities": [],
        "consumed_approvals": [],
    }
    c.update(o)
    return c


def wire_ctx(**o) -> dict:
    return context(x=X_WIRE, a=A_WIRE, **o)


def encode_map_unsorted(d: dict, order: list) -> bytes:
    """Deliberately non-canonical map encoding (keys in the given order)."""
    body = b"".join(R.encode(k) + R.encode(d[k]) for k in order)
    return bytes([R.T_MAP]) + struct.pack(">Q", len(body)) + body


# ---------------------------------------------------------------------------
# Authorization & expiry vectors (§3.1–3.5)
# ---------------------------------------------------------------------------

def auth_cases():
    """(id, scenario, spec_refs, d, sign_key, p, p_sign_key, ctx, expected_reason_names, extras)"""
    C = []

    def add(tid, scenario, refs, d, ctx, expect, key=K_DECISION, p=None, pkey=K_APPROVAL,
            d_bytes=None, gap=None, note=None, trust=None):
        C.append(dict(tid=tid, scenario=scenario, refs=refs, d=d, key=key, p=p, pkey=pkey, ctx=ctx,
                      expect=expect, d_bytes=d_bytes, gap=gap, note=note, trust=trust))

    # --- freshness & skew -----------------------------------------------------------------
    add("auth_expiry_001", "Valid AUTOMATED decision", ["3.5"], decision("001"), context(), [])
    add("auth_expiry_002", "Expired decision (exec after tau_expiry)", ["3.5"],
        decision("002", tau_eval=BASE_US - 3600 * S, tau_expiry=BASE_US - 1800 * S),
        context(tau_exec=BASE_US), ["EXPIRED_CAPABILITY", "EVAL_SKEW_EXCEEDED"],
        note="Exec is 1h after eval, so the 120s skew limit is also exceeded; both bits must be set.")
    add("auth_expiry_003", "Exec exactly at tau_expiry is valid (<=)", ["3.5"],
        decision("003", tau_expiry=BASE_US + 100 * S), context(tau_exec=BASE_US + 100 * S), [])
    add("auth_expiry_004", "Exec one microsecond after tau_expiry", ["3.5"],
        decision("004", tau_expiry=BASE_US + 100 * S), context(tau_exec=BASE_US + 100 * S + 1),
        ["EXPIRED_CAPABILITY"])
    add("auth_expiry_005", "Exec before tau_eval (decision from the future)", ["3.5"],
        decision("005"), context(tau_exec=BASE_US - 1), ["NOT_YET_VALID"])
    add("auth_expiry_006", "Unexpired but evaluation skew exceeded", ["3.5"],
        decision("006", tau_expiry=BASE_US + 3600 * S), context(tau_exec=BASE_US + 121 * S),
        ["EVAL_SKEW_EXCEEDED"])
    add("auth_expiry_007", "Skew exactly at per-action limit is valid", ["3.5"],
        decision("007"), context(tau_exec=BASE_US + 120 * S), [])
    add("auth_expiry_008", "Default ('*') skew limit applies to actions without an override", ["3.5"],
        decision("008", x=X_WIRE, a=A_WIRE, auth_mode="MANUAL",
                 approval_hash=R.H(approval("008"))),
        wire_ctx(tau_exec=BASE_US + 300 * S), [], p=approval("008"),
        note="Exec 300s after eval: exceeds payment.refund's 120s but equals the default 300s.")

    # --- key domains & signatures ---------------------------------------------------------
    add("auth_expiry_009", "Decision signed with a receipt-domain key", ["1", "3.5"],
        decision("009", decision_key_id=K_RECEIPT.key_id), context(), ["SIGNATURE_INVALID", "DECISION_KEY_UNAUTHORIZED"],
        key=K_RECEIPT, note="0.3.0: keys are resolved only inside the required domain, so a receipt key is not "
                            "found and the signature cannot verify — the same classification approvals get (031).")
    add("auth_expiry_010", "Unknown decision key id", ["3.5"],
        decision("010", decision_key_id="kid:decision:0000000000000000"), context(),
        ["SIGNATURE_INVALID", "DECISION_KEY_UNAUTHORIZED"])
    add("auth_expiry_011", "Decision key used outside its trust epoch", ["3.5"],
        decision("011", decision_trust_epoch="epoch-2025-12"), context(), ["DECISION_KEY_UNAUTHORIZED"])
    tampered = decision("012")
    add("auth_expiry_012", "Payload altered after signing", ["3.5"],
        dict(tampered, x={"action": "payment.refund", "params": {"amount_minor": 99999999, "currency": "USD"}}),
        context(x={"action": "payment.refund", "params": {"amount_minor": 99999999, "currency": "USD"}}),
        ["SIGNATURE_INVALID"], note="signature is over the original payload (see sign_original)")
    C[-1]["sign_original"] = tampered
    d013 = decision("013")
    order = list(d013.keys())  # insertion order, not canonical order
    add("auth_expiry_013", "Non-canonical encoding (unsorted map keys) with a valid signature", ["1", "3.5"],
        d013, context(), ["DECODE_INVALID"], d_bytes=encode_map_unsorted(d013, order))
    add("auth_expiry_014", "Wrong domain string in decision payload", ["3.5"],
        decision("014", domain=R.DOMAIN_RECEIPT), context(), ["DOMAIN_MISMATCH"])

    # --- bindings ---------------------------------------------------------------------------
    add("auth_expiry_015", "State version advanced since evaluation", ["3.5"],
        decision("015"), context(current_state_ver=STATE_VER + 1), ["STATE_VERSION_MISMATCH"])
    add("auth_expiry_016", "Different target entity", ["3.5"],
        decision("016"), context(current_target="acct-000999"), ["TARGET_MISMATCH"])
    add("auth_expiry_017", "Active profile changed", ["3.5"],
        decision("017"), context(active_control_profile_hash=R.H({"profile_version": "1.0.1"})), ["PROFILE_HASH_MISMATCH"])
    add("auth_expiry_018", "Evidence and lineage changed", ["3.5"],
        decision("018"), context(evidence_hash=R.H([]), lineage_hash=R.H({})),
        ["EVIDENCE_HASH_MISMATCH", "LINEAGE_HASH_MISMATCH"])
    add("auth_expiry_019", "Decision value is not ALLOW", ["3.5"],
        decision("019", decision="DENY"), context(), ["DECISION_NOT_ALLOW"])
    d020 = decision("020")
    add("auth_expiry_020", "Capability already consumed (replay)", ["3.5", "4.1"],
        d020, context(consumed_capabilities=[d020["capability_id"]]), ["CAPABILITY_UNAVAILABLE"])
    add("auth_expiry_021", "Multiple failures accumulate in the bitfield", ["3.5"],
        decision("021", tau_expiry=BASE_US + 30 * S), context(current_state_ver=STATE_VER + 2),
        ["STATE_VERSION_MISMATCH", "EXPIRED_CAPABILITY"])

    # --- authorization mode (bidirectional, §3.4) -------------------------------------------
    add("auth_expiry_022", "AUTOMATED on a manual-only action", ["3.4"],
        decision("022", x=X_WIRE, a=A_WIRE), wire_ctx(), ["AUTH_MODE_INVALID"])
    add("auth_expiry_023", "AUTOMATED with a non-null approval_hash", ["3.2", "3.4"],
        decision("023", approval_hash=R.H("something-else")), context(), ["AUTH_MODE_INVALID"])
    p024 = approval("024", x=X_REFUND, a=A_REFUND, authority_scope="payment.refund:*")
    add("auth_expiry_024", "MANUAL on an action that is not manual-only", ["3.4"],
        decision("024", auth_mode="MANUAL", approval_hash=R.H(p024)), context(), ["AUTH_MODE_INVALID"],
        p=p024, note="Approval itself is valid; the mode is rejected because x is not in ManualOnly.")
    add("auth_expiry_025", "MANUAL without an approval envelope", ["3.4"],
        decision("025", x=X_WIRE, a=A_WIRE, auth_mode="MANUAL", approval_hash=R.H(approval("025"))),
        wire_ctx(), ["AUTH_MODE_INVALID"])

    # --- manual approvals (§3.1) ------------------------------------------------------------
    def manual(tag, p, ctx, expect, pkey=K_APPROVAL, scenario="", note=None, gap=None, dover=None):
        d = decision(tag, x=X_WIRE, a=A_WIRE, auth_mode="MANUAL", approval_hash=R.H(p), **(dover or {}))
        add(f"auth_expiry_{tag}", scenario, ["3.1", "3.4", "3.5"], d, ctx, expect, p=p, pkey=pkey,
            note=note, gap=gap)

    manual("026", approval("026"), wire_ctx(), [], scenario="Valid MANUAL decision with approval")
    manual("027", approval("027", tau_expiry=BASE_US + 30 * S), wire_ctx(),
           ["APPROVAL_EXPIRED", "AUTH_MODE_INVALID"], scenario="Approval expired before execution")
    p028 = approval("028")
    manual("028", p028, wire_ctx(consumed_approvals=[p028["approval_id"]]),
           ["APPROVAL_CONSUMED", "AUTH_MODE_INVALID"], scenario="Single-use approval already consumed")
    p029 = approval("029", authority_class="STANDING")
    manual("029", p029, wire_ctx(consumed_approvals=[p029["approval_id"]]), [],
           scenario="Reusable (STANDING) approval already used is still valid")
    manual("030", approval("030", authority_scope="wire.release:acct-9*"), wire_ctx(),
           ["APPROVAL_SCOPE_DENIED", "AUTH_MODE_INVALID"], scenario="Approval scope does not cover target")
    manual("031", approval("031", approval_key_id=K_DECISION.key_id), wire_ctx(),
           ["APPROVAL_SIGNATURE_INVALID", "APPROVAL_KEY_UNAUTHORIZED", "AUTH_MODE_INVALID"],
           pkey=K_DECISION, scenario="Approval signed with a decision-domain key")
    manual("032", approval("032", authority_class="EXECUTIVE"), wire_ctx(),
           ["APPROVAL_KEY_UNAUTHORIZED", "AUTH_MODE_INVALID"],
           scenario="Approval key not authorized for the claimed authority class")
    manual("033", approval("033", state_ver=STATE_VER - 1), wire_ctx(),
           ["APPROVAL_BINDING_MISMATCH", "AUTH_MODE_INVALID"],
           scenario="Approval bound to an older state version")
    manual("034", approval("034", domain=R.DOMAIN_DECISION), wire_ctx(),
           ["APPROVAL_DOMAIN_MISMATCH", "AUTH_MODE_INVALID"], scenario="Approval carries the decision domain string")
    # approval_hash in d points to a different approval than the one presented
    p035 = approval("035")
    d035 = decision("035", x=X_WIRE, a=A_WIRE, auth_mode="MANUAL", approval_hash=R.H(approval("035-other")))
    add("auth_expiry_035", "approval_hash does not match presented approval", ["3.3", "3.4"],
        d035, wire_ctx(), ["APPROVAL_HASH_MISMATCH", "AUTH_MODE_INVALID"], p=p035)

    # --- 0.2.0 approval bindings: former spec gaps G-01..G-03, now must-reject ------------------
    manual("036", approval("036", target="acct-000777"), wire_ctx(),
           ["APPROVAL_SUBJECT_MISMATCH", "AUTH_MODE_INVALID"],
           scenario="Approval names a different target than the decision (closes G-01)",
           note="0.1.0 accepted this: an approval for acct-000777 authorised a wire on acct-000123.")
    manual("037", approval("037", tau_issued=BASE_US + 3600 * S), wire_ctx(),
           ["APPROVAL_NOT_YET_VALID", "AUTH_MODE_INVALID"],
           scenario="Approval issued after evaluation (closes G-02)",
           note="0.2.0 requires p.tau_issued <= d.tau_eval <= tau_exec <= p.tau_expiry.")
    manual("038", approval("038"), wire_ctx(), ["APPROVAL_SUBJECT_MISMATCH", "AUTH_MODE_INVALID"],
           dover={"actor": {"id": "someone-else", "type": "user"}},
           scenario="Decision actor differs from the approved actor (closes G-03)")
    manual("039", approval("039", req_id=R.uuid7(BASE_MS, "req|some-other-request")), wire_ctx(),
           ["APPROVAL_SUBJECT_MISMATCH", "AUTH_MODE_INVALID"],
           scenario="Approval for a different request id is replayed onto this decision (closes G-03)")
    manual("040", approval("040", capability_id=R.uuid7(BASE_MS, "cap|some-other-capability")), wire_ctx(),
           ["APPROVAL_SUBJECT_MISMATCH", "AUTH_MODE_INVALID"],
           scenario="Approval bound to a different capability id (closes G-03)",
           note="capability_id is pre-allocated at request time so the approver can bind to it.")
    manual("041", approval("041", tau_issued=BASE_US), wire_ctx(), [],
           scenario="Approval issued exactly at d.tau_eval is valid (<=)")

    # --- 0.3.0 CanonicalObjectValid: validly signed but malformed objects (V-1: never raise) --------
    def mut(tag, fn, **o):
        d = decision(tag, **o)
        fn(d)
        return d
    schema = [
        ("s01", "Extra field in a signed decision", lambda d: d.update(debug_override="allow-all")),
        ("s02", "Required field tau_eval missing", lambda d: d.pop("tau_eval")),
        ("s03", "tau_eval given as a string", lambda d: d.update(tau_eval="2026-01-01T00:00:00Z")),
        ("s04", "capability_id is a UUIDv4, not UUIDv7", lambda d: d.update(capability_id="0b7b2e8c-2f5c-4b9a-9e4d-5a2f1c3d4e5f")),
        ("s05", "evidence_hash is 31 bytes", lambda d: d.update(evidence_hash=d["evidence_hash"][:62])),
        ("s06", "Unsupported schema_ver", lambda d: d.update(schema_ver="9.9.9")),
        ("s07", "Unknown auth_mode string", lambda d: d.update(auth_mode="SEMI_AUTOMATED")),
        ("s08", "Negative state_ver", lambda d: d.update(state_ver=-1)),
        ("s09", "reason_codes with reserved bit 63 set (negative int64)", lambda d: d.update(reason_codes=-(2 ** 63))),
        ("s10", "actor.type outside {service, user}", lambda d: d.update(actor={"id": "svc-ledger-bot", "type": "robot"})),
        ("s11", "Boolean where an integer is required", lambda d: d.update(state_ver=True)),
        ("s12", "Uppercase hex digest", lambda d: d.update(lineage_hash=d["lineage_hash"].upper())),
    ]
    for sid, title, fn in schema:
        add(f"auth_schema_{sid}", title, ["1.5", "3.5"], mut(sid, fn), context(), ["OBJECT_SCHEMA_INVALID"],
            note="Before 0.3.0 some of these were accepted and some raised an exception inside the verifier.")
    p_extra = approval("s13")
    p_extra["note_to_self"] = "approved over the phone"
    add("auth_schema_s13", "Approval with an extra field", ["1.5", "3.1"],
        decision("s13", x=X_WIRE, a=A_WIRE, auth_mode="MANUAL", approval_hash=R.H(p_extra)), wire_ctx(),
        ["APPROVAL_SCHEMA_INVALID", "AUTH_MODE_INVALID"], p=p_extra)
    p_missing = approval("s14")
    p_missing.pop("capability_id")
    add("auth_schema_s14", "Approval missing capability_id", ["1.5", "3.1"],
        decision("s14", x=X_WIRE, a=A_WIRE, auth_mode="MANUAL", approval_hash=R.H(p_missing)), wire_ctx(),
        ["APPROVAL_SCHEMA_INVALID", "AUTH_MODE_INVALID"], p=p_missing)

    # --- 0.3.0 trust-context binding --------------------------------------------------------------
    other_ts = dict(TF.TRUST_STATE, revoked_attestation_ids=["00000000-0000-7000-8000-000000000000"])
    add("auth_trust_t01", "Decision evaluated under a different trust state", ["3.3", "3.5"],
        decision("t01", trust_state_hash=R.H(other_ts)), context(), ["TRUST_STATE_MISMATCH"])
    add("auth_trust_t02", "Decision evaluated under a different scoring profile", ["3.3", "3.5"],
        decision("t02", scoring_profile_hash=R.H({"id": "coverage-v0.2.1-alpha"})), context(), ["SCORING_PROFILE_MISMATCH"])
    add("auth_trust_t03", "Verifier handed a trust state that does not match the hash it was told to enforce",
        ["3.5"], decision("t03"), context(), ["TRUST_STATE_MISMATCH"], trust=other_ts)

    # --- 0.3.0 adverse disposition: containment requires bound manual authorization ----------------
    CD = R.H(["c0ffee" * 10 + "abcd"])  # a containment digest (hash of the obligation list)
    cctx = dict(adverse_disposition="CONTAIN", containment_digest=CD)
    add("auth_contain_a01", "CONTAIN evidence with an AUTOMATED decision", ["2.5", "3.4"],
        decision("a01", adverse_disposition="CONTAIN", containment_digest=CD), context(**cctx),
        ["AUTH_MODE_INVALID", "ADVERSE_CONTAINMENT"])
    p_ack = approval("a02", x=X_REFUND, a=A_REFUND, authority_scope="payment.refund:*",
                     adverse_disposition="CONTAIN", containment_digest=CD)
    add("auth_contain_a02", "CONTAIN evidence with MANUAL approval that acknowledges the exact claims", ["2.5", "3.4"],
        decision("a02", adverse_disposition="CONTAIN", containment_digest=CD, auth_mode="MANUAL",
                 approval_hash=R.H(p_ack)), context(**cctx), [], p=p_ack,
        note="payment.refund is not ManualOnly; containment is what makes MANUAL the required mode.")
    p_clear = approval("a03", x=X_REFUND, a=A_REFUND, authority_scope="payment.refund:*")
    add("auth_contain_a03", "Approval acknowledges CLEAR but the decision carries CONTAIN", ["2.5", "3.1"],
        decision("a03", adverse_disposition="CONTAIN", containment_digest=CD, auth_mode="MANUAL",
                 approval_hash=R.H(p_clear)), context(**cctx), ["ADVERSE_DISPOSITION_MISMATCH", "AUTH_MODE_INVALID"],
        p=p_clear)
    p_other = approval("a04", x=X_REFUND, a=A_REFUND, authority_scope="payment.refund:*",
                       adverse_disposition="CONTAIN", containment_digest=R.H(["another-claim"]))
    add("auth_contain_a04", "Approval acknowledged a different set of adverse claims", ["2.5", "3.1"],
        decision("a04", adverse_disposition="CONTAIN", containment_digest=CD, auth_mode="MANUAL",
                 approval_hash=R.H(p_other)), context(**cctx), ["ADVERSE_DISPOSITION_MISMATCH", "AUTH_MODE_INVALID"],
        p=p_other)
    add("auth_contain_a05", "Decision says CLEAR but current evidence is CONTAIN", ["2.5", "3.5"],
        decision("a05"), context(**cctx), ["ADVERSE_DISPOSITION_MISMATCH"])
    add("auth_contain_a06", "CONTAIN with the null containment digest is internally inconsistent", ["2.5", "3.3"],
        decision("a06", adverse_disposition="CONTAIN"), context(adverse_disposition="CONTAIN"),
        ["ADVERSE_DISPOSITION_MISMATCH", "AUTH_MODE_INVALID", "ADVERSE_CONTAINMENT"])

    # --- 0.3.0 C-1 clock authority (closes G-10) --------------------------------------------------
    add("auth_clock_k01", "Executor clock is not a registered clock authority", ["3.5"],
        decision("k01"), context(clock="clk:laptop"), ["CLOCK_UNTRUSTED"])
    add("auth_clock_k02", "Executor reports uncertainty above its authority's maximum", ["3.5"],
        decision("k02"), context(clock=TF.CLOCK_NTP, uncertainty_us=600_000), ["CLOCK_UNTRUSTED"])
    add("auth_clock_k03", "Evaluator clock in the decision is not registered", ["3.5"],
        decision("k03", eval_clock_id="clk:rogue"), context(), ["CLOCK_UNTRUSTED"])
    add("auth_clock_k04", "200 ms before expiry with a 1 ms clock: valid", ["3.5"],
        decision("k04", tau_expiry=BASE_US + 60 * S + 200_000), context(clock=TF.CLOCK_PTP, uncertainty_us=1_000), [])
    add("auth_clock_k05", "Same timing with a 500 ms clock: expiry cannot be excluded", ["3.5"],
        decision("k05", tau_expiry=BASE_US + 60 * S + 200_000), context(clock=TF.CLOCK_NTP, uncertainty_us=500_000),
        ["EXPIRED_CAPABILITY"])
    add("auth_clock_k06", "Exec 100 ms after eval with a 500 ms clock: ordering cannot be proven", ["3.5"],
        decision("k06"), context(tau_exec=BASE_US + 100_000, clock=TF.CLOCK_NTP, uncertainty_us=500_000),
        ["NOT_YET_VALID"])
    add("auth_clock_k07", "Skew limit tightened by clock uncertainty", ["3.5"],
        decision("k07", tau_expiry=BASE_US + 3600 * S), context(tau_exec=BASE_US + 119_600_000, clock=TF.CLOCK_NTP,
                                                              uncertainty_us=500_000),
        ["EVAL_SKEW_EXCEEDED"], note="119.6 s + 0.5 s > 120 s for payment.refund.")
    return C


def build_auth_vectors():
    out = []
    for c in auth_cases():
        d, key, ctx = c["d"], c["key"], c["ctx"]
        if c.get("sign_original"):
            sig = key.sign_digest(R.H(c["sign_original"]))
            d_bytes = R.encode(d)
        elif c["d_bytes"] is not None:
            d_bytes = c["d_bytes"]
            sig = key.sign_digest(R.H_bytes(d_bytes))
        else:
            d_bytes = R.encode(d)
            sig = key.sign_digest(R.H_bytes(d_bytes))
        p_hex = p_sig = None
        if c["p"] is not None:
            pb = R.encode(c["p"])
            p_hex, p_sig = pb.hex(), c["pkey"].sign_digest(R.H_bytes(pb))
        full_ctx = dict(ctx, trust_state=c["trust"] or TF.TRUST_STATE)
        valid, bits = R.decision_binding_valid(full_ctx, d_bytes.hex(), sig, p_hex, p_sig)
        want = sum(R.RC[n] for n in c["expect"])
        if bits != want:
            raise SystemExit(f"{c['tid']}: reference model gives {R.reason_names(bits)}, "
                             f"case declares {c['expect']}")
        v = {
            "test_id": c["tid"],
            "scenario": c["scenario"],
            "spec_refs": c["refs"],
            "input": {
                "decision_payload": d,
                "decision_bytes": d_bytes.hex(),
                "decision_hash": R.H_bytes(d_bytes),
                "decision_signature": sig,
                "approval_payload": c["p"],
                "approval_bytes": p_hex,
                "approval_signature": p_sig,
                "context": ctx,
            },
            "expected_output": {
                "DecisionBindingValid": valid,
                "reason_bitfield": bits,
                "reason_codes": R.reason_names(bits),
            },
            "timestamps_iso": {k: (iso(v) if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None)
                               for k, v in (("tau_eval", d.get("tau_eval")), ("tau_expiry", d.get("tau_expiry")),
                                            ("tau_exec", ctx["exec_clock"]["tau_exec"]))},
        }
        if c["trust"] is not None:
            v["trust_state"] = c["trust"]
        if c["note"]:
            v["note"] = c["note"]
        if c["gap"]:
            v["spec_gap"] = c["gap"]
        out.append(v)
    return {
        "vector_set": "authorization-expiry-skew",
        "spec_version": R.SPEC_VERSION,
        "encoding": R.ENCODING_ID,
        "time_unit": "microseconds since Unix epoch, UTC",
        "trust_state": TF.TRUST_STATE,
        "trust_state_hash": TF.TRUST_STATE_HASH,
        "reason_code_registry": "tests/reason_codes.json",
        "vectors": out,
    }


# ---------------------------------------------------------------------------
# Golden binary vectors (§1, §3, §4.3)
# ---------------------------------------------------------------------------

def tj(v):
    """Python value -> typed JSON (lossless, language-neutral)."""
    if v is None:
        return {"type": "null"}
    if isinstance(v, bool):
        return {"type": "bool", "value": v}
    if isinstance(v, int):
        return {"type": "int", "value": str(v)}
    if isinstance(v, R.F64):
        return {"type": "f64", "bits": f"{v.bits:016x}"}
    if isinstance(v, str):
        return {"type": "str", "value": v}
    if isinstance(v, bytes):
        return {"type": "bytes", "hex": v.hex()}
    if isinstance(v, list):
        return {"type": "list", "items": [tj(i) for i in v]}
    if isinstance(v, dict):
        return {"type": "map", "entries": [[k, tj(v[k])] for k in v]}
    raise TypeError(type(v))


def build_golden():
    prims = [
        ("null", None), ("false", False), ("true", True),
        ("int_zero", 0), ("int_neg_one", -1), ("int64_max", R.INT64_MAX), ("int64_min", R.INT64_MIN),
        ("f64_pos_zero", R.F64(0x0000000000000000)), ("f64_neg_zero", R.F64(0x8000000000000000)),
        ("f64_min_subnormal", R.F64(0x0000000000000001)), ("f64_quiet_nan", R.F64(0x7FF8000000000000)),
        ("str_empty", ""), ("str_ascii", "provenance"), ("str_unicode", "\u00e9\U0001F642\u4e2d"),
        ("str_nfc_vs_nfd", "é"),
        ("bytes_empty", b""), ("bytes_sha256_len", bytes(range(32))),
        ("list_empty", []), ("list_mixed", [1, "a", None, True]),
        ("map_empty", {}),
        ("map_key_order", {"b": 1, "a": 2, "B": 3, "aa": 4, "é": 5, "": 6}),
        ("map_nested", {"z": {"y": [1, {"x": None}]}, "a": []}),
    ]
    primitives = []
    for pid, v in prims:
        b = R.encode(v)
        assert R.encode(R.decode(b)) == b
        primitives.append({"id": pid, "value": tj(v), "expected_bytes": b.hex(), "expected_hash": R.H_bytes(b)})

    good = R.encode({"a": 1, "b": 2})
    rejects = [
        ("unsorted_keys", encode_map_unsorted({"a": 1, "b": 2}, ["b", "a"]), "map keys not ascending"),
        ("duplicate_keys", bytes([R.T_MAP]) + struct.pack(">Q", 2 * len(R.encode("a") + R.encode(1)))
         + (R.encode("a") + R.encode(1)) * 2, "duplicate map key"),
        ("trailing_bytes", good + b"\x00", "trailing bytes after top-level value"),
        ("truncated", good[:-1], "length exceeds buffer"),
        ("bool_with_length", bytes([R.T_TRUE]) + struct.pack(">Q", 1) + b"\x01", "bool must have length 0"),
        ("int_short", bytes([R.T_INT]) + struct.pack(">Q", 4) + b"\x00\x00\x00\x01", "int must be 8 bytes"),
        ("invalid_utf8", bytes([R.T_STR]) + struct.pack(">Q", 2) + b"\xc3\x28", "invalid UTF-8"),
        ("non_string_key", bytes([R.T_MAP]) + struct.pack(">Q", len(R.encode(1) + R.encode(2)))
         + R.encode(1) + R.encode(2), "map key must be a string"),
        ("unknown_tag", bytes([0x7F]) + struct.pack(">Q", 0), "unknown tag"),
    ]
    reject_out = []
    for rid, b, why in rejects:
        try:
            R.decode(b)
            raise SystemExit(f"reject vector {rid} was accepted by the reference decoder")
        except R.CanonicalDecodeError:
            pass
        reject_out.append({"id": rid, "bytes": b.hex(), "must_reject": True, "reason": why})

    p = approval("golden-manual")
    d_auto = decision("golden-auto")
    d_man = decision("golden-manual", x=X_WIRE, a=A_WIRE, auth_mode="MANUAL", approval_hash=R.H(p))
    pre = {"version": STATE_VER, "data": {"balance_minor": 50000}}
    post = R.apply_mutation(pre, {"balance_minor": 37500})
    r = R.build_receipt(d=d_auto, d_hash=R.H(d_auto), receipt_id=R.uuid7(BASE_MS + 61000, "rcpt|golden"),
                        status="COMMITTED", failure_phase="NONE", reason=0, recon_required=False,
                        pre_state=pre, post_state=post, tau_dispatch=BASE_US + 60 * S,
                        tau_finalized=BASE_US + 61 * S, key=K_RECEIPT, epoch=EPOCH)
    objects = []
    for oid, typ, payload, key in [
        ("profile_default", "profile", PROFILE, K_PROFILE),
        ("approval_supervisor", "approval", p, K_APPROVAL),
        ("decision_automated", "decision", d_auto, K_DECISION),
        ("decision_manual", "decision", d_man, K_DECISION),
        ("receipt_committed", "receipt", r, K_RECEIPT),
    ]:
        b = R.encode(payload)
        h = R.H_bytes(b)
        objects.append({"id": oid, "artifact_type": typ, "payload": payload, "expected_bytes": b.hex(),
                        "expected_hash": h, "signing_key_id": key.key_id, "expected_signature": key.sign_digest(h)})

    return {
        "vector_set": "golden-binary",
        "spec_version": R.SPEC_VERSION,
        "encoding": R.ENCODING_ID,
        "encoding_definition": "docs/CONFORMANCE_ASSUMPTIONS.md#a-01",
        "hash": "SHA-256 over the PRC-LP-0 encoding (single layer, A-02)",
        "signature": "Ed25519 (RFC 8032) over the raw 32-byte digest H(z)",
        "WARNING": "Test keys are derived from public seeds. Never use them outside conformance testing.",
        "keys": [{"domain": k.domain, "label": k.label, "seed": k.seed.hex(), "public_key": k.public_hex,
                  "key_id": k.key_id} for k in KEYS],
        "constants": {
            "NULL_APPROVAL_DIGEST": {"preimage": R.NO_APPROVAL_LABEL,
                                     "preimage_bytes": R.encode(R.NO_APPROVAL_LABEL).hex(),
                                     "value": R.NULL_APPROVAL_DIGEST},
            "NULL_STATE_DIGEST": {"preimage": R.NO_STATE_LABEL,
                                  "preimage_bytes": R.encode(R.NO_STATE_LABEL).hex(),
                                  "value": R.NULL_STATE_DIGEST},
            "UUIDv7_example": {"unix_ms": BASE_MS, "label": "example", "value": R.uuid7(BASE_MS, "example")},
        },
        "primitives": primitives,
        "must_reject": reject_out,
        "objects": objects,
    }


# ---------------------------------------------------------------------------
# Numerical vectors (§2.3)
# ---------------------------------------------------------------------------
OP_AUTH_CHECK, OP_KAHAN_SUM = 1, 2
b = R.bits_of
NUM_CASES = [
    # (id, op, input bits, expected result(bool)|None, expected output bits, expected lock, note)
    ("above_threshold", OP_AUTH_CHECK, [b(0.75), b(0.7)], True, b(0.75), False, ""),
    ("equal_threshold", OP_AUTH_CHECK, [b(0.7), b(0.7)], True, b(0.7), False, ">= is inclusive"),
    ("one_ulp_below", OP_AUTH_CHECK, [b(0.7) - 1, b(0.7)], False, b(0.7) - 1, False, "no epsilon tolerance"),
    ("sum_0.1_0.2_vs_0.3", OP_AUTH_CHECK, [b(0.1 + 0.2), b(0.3)], True, b(0.1 + 0.2), False,
     "0.1+0.2 = 0.30000000000000004 > 0.3"),
    ("0.3_vs_sum_0.1_0.2", OP_AUTH_CHECK, [b(0.3), b(0.1 + 0.2)], False, b(0.3), False, ""),
    ("neg_zero_normalised", OP_AUTH_CHECK, [0x8000000000000000, b(0.0)], True, 0, False, "-0.0 -> +0.0"),
    ("threshold_neg_zero", OP_AUTH_CHECK, [b(0.0), 0x8000000000000000], True, 0, False, ""),
    ("min_subnormal_preserved", OP_AUTH_CHECK, [0x1, b(0.0)], True, 0x1, False, "no flush-to-zero"),
    ("subnormal_order", OP_AUTH_CHECK, [0x1, 0x2], False, 0x1, False, "5e-324 < 1e-323"),
    ("max_subnormal_vs_min_normal", OP_AUTH_CHECK, [0x000FFFFFFFFFFFFF, 0x0010000000000000], False,
     0x000FFFFFFFFFFFFF, False, ""),
    ("quiet_nan", OP_AUTH_CHECK, [0x7FF8000000000000, b(0.5)], False, 0, True, "C forced to 0.0, State 2"),
    ("signaling_nan", OP_AUTH_CHECK, [0x7FF0000000000001, b(0.0)], False, 0, True,
     "lock denies even though 0.0 >= 0.0 (A-05)"),
    ("negative_nan", OP_AUTH_CHECK, [0xFFF8000000000000, b(0.5)], False, 0, True, ""),
    ("pos_inf", OP_AUTH_CHECK, [0x7FF0000000000000, b(0.5)], False, 0, True, "Inf is an exception, not 'very high'"),
    ("neg_inf", OP_AUTH_CHECK, [0xFFF0000000000000, b(0.5)], False, 0, True, ""),
    ("nan_threshold", OP_AUTH_CHECK, [b(0.9), 0x7FF8000000000000], False, 0, True, "A-04: exceptional T also locks"),
    ("kahan_small_terms", OP_KAHAN_SUM, [b(1.0)] + [b(1e-16)] * 10, None, b(1.000000000000001), False,
     "naive left-to-right sum returns exactly 1.0"),
    ("kahan_tenths", OP_KAHAN_SUM, [b(0.1)] * 10, None, b(1.0), False, "naive sum gives 0.9999999999999999"),
    ("kahan_neg_zeros", OP_KAHAN_SUM, [0x8000000000000000] * 2, None, 0, False, "-0.0 result normalised"),
    ("kahan_subnormals", OP_KAHAN_SUM, [0x1] * 3, None, 0x3, False, "subnormals preserved"),
    ("kahan_empty", OP_KAHAN_SUM, [], None, 0, False, ""),
    ("kahan_overflow", OP_KAHAN_SUM, [b(1e308), b(1e308)], None, 0, True, "intermediate Inf -> lock"),
    ("kahan_nan_input", OP_KAHAN_SUM, [b(1.0), 0x7FF8000000000000], None, 0, True, ""),
]


def build_numeric():
    recs, manifest = [], []
    for cid, op, ins, want_res, want_bits, want_lock, note in NUM_CASES:
        if op == OP_AUTH_CHECK:
            got = R.authorization_check(*ins)
            ok = (got["result"], got["c_effective_bits"], got["safe_state_lock"]) == (want_res, want_bits, want_lock)
            out_bits, res = got["c_effective_bits"], got["result"]
        else:
            got = R.kahan_sum(ins)
            ok = (got["result_bits"], got["safe_state_lock"]) == (want_bits, want_lock)
            out_bits, res = got["result_bits"], False
        if not ok:
            raise SystemExit(f"numeric case {cid}: reference gives {got}")
        flags = (1 if res else 0) | (2 if want_lock else 0)
        recs.append(struct.pack("<BBHI", op, flags, 0, len(ins)) + b"".join(struct.pack("<Q", x) for x in ins)
                    + struct.pack("<Q", out_bits))
        manifest.append({
            "id": cid, "op": {1: "AUTH_CHECK", 2: "KAHAN_SUM"}[op],
            "inputs_bits": [f"{x:016x}" for x in ins],
            "inputs_repr": [repr(R.f64_from_bits(x)) for x in ins],
            "expected": ({"result": res} if op == OP_AUTH_CHECK else {}) | {
                "output_bits": f"{out_bits:016x}", "output_repr": repr(R.f64_from_bits(out_bits)),
                "safe_state_lock": want_lock},
            "normative": op == OP_AUTH_CHECK,
            "note": note,
        })
    blob = b"PRNV" + struct.pack("<HHI", 1, 0, len(recs)) + b"".join(recs)
    doc = {
        "vector_set": "numerical-ieee754",
        "spec_version": R.SPEC_VERSION,
        "binary_file": "kahan_cordic_ieee754.bin",
        "binary_sha256": hashlib.sha256(blob).hexdigest(),
        "binary_layout": {
            "header": "magic 'PRNV' | u16 version=1 | u16 reserved=0 | u32 record_count  (little-endian)",
            "record": "u8 op (1=AUTH_CHECK, 2=KAHAN_SUM) | u8 flags (bit0 result, bit1 safe_state_lock) | "
                      "u16 reserved=0 | u32 n | n x u64 input bit patterns | u64 expected output bits",
            "AUTH_CHECK": "inputs [C, T]; output = effective C after §2.3 handling",
            "KAHAN_SUM": "informative harness op (not in spec text); output = compensated sum",
        },
        "cordic": "No CORDIC vectors: the specification does not define a CORDIC operation (see A-06).",
        "cases": manifest,
    }
    return blob, doc


# ---------------------------------------------------------------------------
# Lineage fixtures (§2.1–2.2)
# ---------------------------------------------------------------------------

def rep(i, v):
    return {"id": i, "value": v}


LINEAGE_CASES = [
    ("01_singleton_valid", "Single class, valid optional member", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.8),
                     "optional_members": [{"id": "ev-a2", "state": "VALID"}]}]},
     {"eligible": ["F1"], "V": {"F1": 0.8}, "I": {"F1": 1.0}}),
    ("02_degraded", "DEGRADED member applies kappa", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.9),
                     "optional_members": [{"id": "ev-a2", "state": "DEGRADED"}]}]},
     {"eligible": ["F1"], "V": {"F1": 0.45}, "I": {"F1": 1.0}}),
    ("03_contradictory", "CONTRADICTORY member zeroes A; class stays eligible", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.9),
                     "optional_members": [{"id": "ev-b", "state": "CONTRADICTORY"}]}]},
     {"eligible": ["F1"], "V": {"F1": 0.0}, "I": {"F1": 1.0}}),
    ("04_unavailable_ignored", "UNAVAILABLE_OR_STALE leaves A unaffected", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.7),
                     "optional_members": [{"id": "ev-a2", "state": "UNAVAILABLE_OR_STALE"}]}]},
     {"eligible": ["F1"], "V": {"F1": 0.7}, "I": {"F1": 1.0}}),
    ("05_invalid_family", "INVALID member invalidates the family and emits an audit event", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.95),
                     "optional_members": [{"id": "ev-a2", "state": "INVALID"}]}]},
     {"eligible": [], "V": {}, "I": {}, "C": 0.0, "audit": ["F1"]}),
    ("06_empty_evidence", "No evidence at all: M = C = 0.0", {"kappa_degraded": 0.5, "classes": []},
     {"eligible": [], "V": {}, "I": {}, "C": 0.0, "audit": []}),
    ("07_pairwise_min", "Three classes: I_k is the minimum pairwise conditional independence", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.8)},
                    {"id": "F2", "representative": rep("ev-b", 0.6)},
                    {"id": "F3", "representative": rep("ev-c", 0.5)}],
        "pairwise_independence": {"F1|F2": 0.9, "F1|F3": 0.4, "F2|F1": 0.7, "F2|F3": 1.0,
                                  "F3|F1": 0.3, "F3|F2": 0.6}},
     {"eligible": ["F1", "F2", "F3"], "V": {"F1": 0.8, "F2": 0.6, "F3": 0.5}, "I": {"F1": 0.4, "F2": 0.7, "F3": 0.3}}),
    ("08_invalidation_shrinks_pairs", "An invalidated class is excluded from pairwise reduction", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.8)},
                    {"id": "F2", "representative": rep("ev-b", 0.6)},
                    {"id": "F3", "representative": rep("ev-c", 0.5),
                     "optional_members": [{"id": "ev-c2", "state": "INVALID"}]}],
        "pairwise_independence": {"F1|F2": 0.9, "F1|F3": 0.1, "F2|F1": 0.7, "F2|F3": 0.1,
                                  "F3|F1": 0.1, "F3|F2": 0.1}},
     {"eligible": ["F1", "F2"], "V": {"F1": 0.8, "F2": 0.6}, "I": {"F1": 0.9, "F2": 0.7}, "audit": ["F3"]}),
    ("09_invalidation_to_singleton", "Invalidation leaves one class, which takes the singleton identity I = 1.0", {
        "kappa_degraded": 0.5,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.8)},
                    {"id": "F2", "representative": rep("ev-b", 0.6),
                     "optional_members": [{"id": "ev-b2", "state": "INVALID"}]}],
        "pairwise_independence": {"F1|F2": 0.2, "F2|F1": 0.2}},
     {"eligible": ["F1"], "V": {"F1": 0.8}, "I": {"F1": 1.0}, "audit": ["F2"]}),
    ("10_mixed_states_min", "Several optional members: A takes the most adverse factor", {
        "kappa_degraded": 0.25,
        "classes": [{"id": "F1", "representative": rep("ev-a", 0.8),
                     "optional_members": [{"id": "m1", "state": "VALID"}, {"id": "m2", "state": "DEGRADED"},
                                          {"id": "m3", "state": "UNAVAILABLE_OR_STALE"}]}]},
     {"eligible": ["F1"], "V": {"F1": 0.2}, "I": {"F1": 1.0}}),
]


def build_lineage():
    files = {}
    for fid, title, case, want in LINEAGE_CASES:
        got = R.evaluate_lineage(case)
        assert got["eligible"] == want["eligible"], (fid, got)
        for k, v in want["V"].items():
            assert got["classes"][k]["V"] == v, (fid, k, got["classes"][k]["V"], v)
        for k, v in want["I"].items():
            assert got["classes"][k]["I"] == v, (fid, k)
        if "C" in want:
            assert got["C"] == want["C"], fid
        assert [e["class"] for e in got["audit_events"]] == want.get("audit", []), fid
        exp = {"eligible_classes": got["eligible"], "classes": {}, "audit_events": got["audit_events"],
               "M": got["M"], "C": got["C"], "reason_bitfield": got["reason_code"],
               "reason_codes": R.reason_names(got["reason_code"])}
        for k, cv in got["classes"].items():
            e = {"eligible": cv["eligible"], "invalidated": cv["invalidated"]}
            if cv["eligible"]:
                e.update({"A": cv["A"], "V": cv["V"], "V_bits": f"{R.bits_of(cv['V']):016x}", "I": cv["I"]})
            exp["classes"][k] = e
        files[f"{fid}.yaml"] = {
            "name": title, "spec_refs": ["2.1", "2.2"], "spec_version": R.SPEC_VERSION,
            "input": case, "expected": exp,
        }
    return files


# ---------------------------------------------------------------------------
# CAS / reconciliation fixtures (§4)
# ---------------------------------------------------------------------------
CAS_CASES = [
    ("01_local_commit", "local", "Local CAS succeeds", {"version": 7}, [], None,
     ("COMMITTED", "NONE", [], False)),
    ("02_local_cas_mismatch", "local", "Local CAS precondition failure (state advanced)", {"version": 8}, [], None,
     ("REJECTED", "PRECONDITION", ["CAS_PRECONDITION_FAILED"], False)),
    ("03_local_capability_consumed", "local", "Local replay of a consumed capability", {"version": 7}, ["SELF"], None,
     ("REJECTED", "PRECONDITION", ["CAPABILITY_UNAVAILABLE"], False)),
    ("04_dist_ack", "distributed", "Target acknowledges", {"version": 7}, [], {"dispatch": "DELIVERED"},
     ("COMMITTED", "NONE", [], False)),
    ("05_dist_timeout_applied", "distributed", "Timeout, reconciliation finds mutation applied", {"version": 7}, [],
     {"dispatch": "TIMEOUT", "reconcile": "APPLIED"}, ("COMMITTED", "NONE", ["DISPATCH_TIMEOUT"], False)),
    ("06_dist_timeout_not_applied", "distributed", "Timeout, reconciliation finds nothing applied", {"version": 7}, [],
     {"dispatch": "TIMEOUT", "reconcile": "NOT_APPLIED"}, ("ROLLED_BACK", "DISPATCH", ["DISPATCH_TIMEOUT"], False)),
    ("07_dist_unresolved", "distributed", "Timeout, reconciliation cannot determine outcome", {"version": 7}, [],
     {"dispatch": "TIMEOUT", "reconcile": "UNKNOWN"},
     ("UNRESOLVED", "RECONCILIATION", ["DISPATCH_TIMEOUT", "RECONCILIATION_UNRESOLVED"], True)),
    ("08_dist_target_reject", "distributed", "Target rejects the request", {"version": 7}, [], {"dispatch": "REJECT"},
     ("REJECTED", "TARGET", ["TARGET_REJECTED"], False)),
    ("09_dist_target_cas_fail", "distributed", "Target reports State-Precondition mismatch", {"version": 9}, [],
     {"dispatch": "DELIVERED"}, ("REJECTED", "PRECONDITION", ["CAS_PRECONDITION_FAILED"], False)),
    ("10_dist_capability_reserved", "distributed", "Capability already reserved by an earlier attempt",
     {"version": 7}, ["SELF"], {"dispatch": "DELIVERED"}, ("REJECTED", "PREPARE", ["CAPABILITY_UNAVAILABLE"], False)),
]


def build_cas():
    files = {}
    for i, (fid, kind, title, st, consumed_spec, target, want) in enumerate(CAS_CASES):
        d = decision(f"cas-{fid}")
        d_hash = R.H(d)
        consumed = [d["capability_id"] if c == "SELF" else c for c in consumed_spec]
        pre = {"version": st["version"], "data": {"balance_minor": 50000}}
        mutation = {"balance_minor": 37500}
        if kind == "local":
            res = R.execute_local(pre, consumed, d, mutation)
        else:
            res = R.execute_distributed(pre, consumed, d, mutation, target)
        want_status, want_phase, want_reasons, want_recon = want
        got = (res["status"], res["phase"], res["reason"], res["recon"])
        if got != (want_status, want_phase, sum(R.RC[n] for n in want_reasons), want_recon):
            raise SystemExit(f"CAS case {fid}: reference gives {got}")
        t_dispatch = BASE_US + 60 * S
        t_final = t_dispatch + (30 * S if "timeout" in fid or "unresolved" in fid else 1 * S)
        rcpt = R.build_receipt(d=d, d_hash=d_hash, receipt_id=R.uuid7(BASE_MS + 61000, "rcpt|" + fid),
                               status=res["status"], failure_phase=res["phase"], reason=res["reason"],
                               recon_required=res["recon"], pre_state=pre,
                               post_state=res["post_state"],
                               tau_dispatch=t_dispatch, tau_finalized=t_final, key=K_RECEIPT, epoch=EPOCH)
        rb = R.encode(rcpt)
        rh = R.H_bytes(rb)
        files[f"{fid}.yaml"] = {
            "name": title, "spec_refs": ["4.1"] if kind == "local" else ["4.2"], "spec_version": R.SPEC_VERSION,
            "boundary": kind,
            "input": {
                "initial_state": pre, "consumed_or_reserved_capabilities": consumed, "mutation": mutation,
                "decision_payload": d, "decision_hash": d_hash, "target_behaviour": target,
            },
            "expected": {
                "execution_status": res["status"], "failure_phase": res["phase"],
                "reason_bitfield": res["reason"], "reason_codes": R.reason_names(res["reason"]),
                "reconciliation_required": res["recon"],
                "final_state": res["post_state"],
                "capability_consumed": d["capability_id"] in res["consumed"],
                "phase_trace": res["trace"],
                "receipt_payload": rcpt, "receipt_bytes": rb.hex(), "receipt_hash": rh,
                "receipt_signature": K_RECEIPT.sign_digest(rh), "receipt_key_id": K_RECEIPT.key_id,
            },
        }
    return files


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def dump_json(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, sort_keys=False)
        f.write("\n")


def dump_yaml(path, obj):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("# GENERATED by tools/generate_vectors.py — do not edit by hand.\n")
        yaml.safe_dump(obj, f, sort_keys=False, allow_unicode=True, width=120)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests"))
    args = ap.parse_args(argv)
    out = os.path.abspath(args.out)
    for sub in ("fixtures/lineage_graphs", "fixtures/cas_reconciliation", "vectors"):
        os.makedirs(os.path.join(out, sub), exist_ok=True)

    written = {}

    def rel(p):
        return os.path.relpath(p, out).replace(os.sep, "/")

    p = os.path.join(out, "reason_codes.json")
    dump_json(p, {"spec_version": R.SPEC_VERSION, "status": "provisional (A-03)",
                  "encoding": "non-negative int64 bitfield; bit 63 is reserved and must be zero (a mask with it "
                              "set is negative in int64 and fails CanonicalObjectValid)",
                  "bits": [{"bit": i, "name": n, "mask": str(1 << i)} for i, n in enumerate(R.REASON_BITS)],
                  "reserved": [{"bit": 63, "reason": "sign bit of int64"}]})
    written[rel(p)] = p
    p = os.path.join(out, "fixtures", "golden_vectors.json")
    dump_json(p, build_golden()); written[rel(p)] = p
    p = os.path.join(out, "vectors", "auth_expiry_skew.json")
    dump_json(p, build_auth_vectors()); written[rel(p)] = p
    blob, ndoc = build_numeric()
    p = os.path.join(out, "vectors", "kahan_cordic_ieee754.bin")
    with open(p, "wb") as f:
        f.write(blob)
    written[rel(p)] = p
    p = os.path.join(out, "vectors", "kahan_cordic_ieee754.json")
    dump_json(p, ndoc); written[rel(p)] = p
    for name, doc in build_lineage().items():
        p = os.path.join(out, "fixtures", "lineage_graphs", name)
        dump_yaml(p, doc); written[rel(p)] = p
    import scoring_cases  # EXPERIMENTAL scoring profile jaccard-v0.1.0-alpha
    p = os.path.join(out, "vectors", "scoring_jaccard_v0.1.0-alpha.json")
    dump_json(p, scoring_cases.build()); written[rel(p)] = p
    import coverage_cases  # EXPERIMENTAL scoring profile coverage-v0.2.0-alpha + engine guard
    p = os.path.join(out, "vectors", "scoring_coverage_v0.2.0-alpha.json")
    dump_json(p, coverage_cases.build()); written[rel(p)] = p
    import coverage_v021_cases  # EXPERIMENTAL coverage-v0.2.1-alpha: P-1 provenance + defeater channel
    p = os.path.join(out, "vectors", "scoring_coverage_v0.2.1-alpha.json")
    dump_json(p, coverage_v021_cases.build()); written[rel(p)] = p
    import coverage_v030_cases  # EXPERIMENTAL coverage-v0.3.0-alpha: A-1 containment + M-1 membership
    p = os.path.join(out, "vectors", "scoring_coverage_v0.3.0-alpha.json")
    dump_json(p, coverage_v030_cases.build()); written[rel(p)] = p
    for name, doc in build_cas().items():
        p = os.path.join(out, "fixtures", "cas_reconciliation", name)
        dump_yaml(p, doc); written[rel(p)] = p

    manifest = {"spec_version": R.SPEC_VERSION, "generator": "tools/generate_vectors.py", "files": {}}
    for r in sorted(written):
        with open(written[r], "rb") as f:
            manifest["files"][r] = hashlib.sha256(f.read()).hexdigest()
    dump_json(os.path.join(out, "MANIFEST.json"), manifest)
    print(f"wrote {len(written)} artifact files + MANIFEST.json to {out}")


if __name__ == "__main__":
    main()
