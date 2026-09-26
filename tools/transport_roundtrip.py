#!/usr/bin/env python3
"""
Transport round trip: canonical object -> Protobuf -> bytes -> Protobuf -> canonical object
-> PRC-LP-0 -> SHA-256 -> Ed25519 verify, for every signed object in the vector suite.

Also demonstrates why Protobuf bytes must never be hashed:
  * two different, valid wire encodings of the same message (field splitting + merge)
  * an unknown field that a lenient parser keeps and a strict verifier must reject

Requires: pip install grpcio-tools protobuf     (skips with exit 0 if they are missing and
PRC_REQUIRE_TRANSPORT is not set)

    python tools/transport_roundtrip.py
"""
from __future__ import annotations

import glob
import hashlib
import importlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "reference"))
import prc_ref as R  # noqa: E402

PROTO = os.path.join(ROOT, "schema", "protobuf", "provenance_razor_v1alpha3.proto")
FBS = os.path.join(ROOT, "schema", "flatbuffers", "provenance_razor_v1alpha3.fbs")
FB_NS = "Provenance.Razor.V1Alpha3"


class TransportError(ValueError):
    pass


def load_pb2():
    from grpc_tools import protoc
    out = tempfile.mkdtemp(prefix="prc_pb2_")
    rc = protoc.main(["protoc", f"-I{os.path.dirname(PROTO)}", f"--python_out={out}", PROTO])
    if rc != 0:
        raise SystemExit("protoc failed to compile the transport schema")
    sys.path.insert(0, out)
    return importlib.import_module("provenance_razor_v1alpha3_pb2")


# field kinds: s=string, i=int64, b=bool, v=Value, d=32-byte digest, e:<Enum>=enum, oi=optional int64, atoms
APPROVAL = [("domain", "s"), ("schema_ver", "s"), ("approval_id", "s"), ("approval_key_id", "s"),
            ("approval_trust_epoch", "s"), ("authority_class", "s"), ("authority_scope", "s"), ("x", "v"),
            ("a", "v"), ("target", "s"), ("state_ver", "i"), ("control_profile_hash", "d"), ("tau_issued", "i"),
            ("tau_expiry", "i"), ("decision", "e:DecisionOutcome"), ("actor", "v"), ("req_id", "s"),
            ("capability_id", "s"), ("scoring_profile_hash", "d"), ("trust_state_hash", "d"),
            ("adverse_disposition", "e:AdverseDisposition"), ("containment_digest", "d")]
DECISION = [("domain", "s"), ("schema_ver", "s"), ("profile_version", "s"), ("lineage_schema_version", "s"),
            ("capability_id", "s"), ("req_id", "s"), ("evidence_snapshot_id", "s"), ("actor", "v"),
            ("auth_mode", "e:AuthorizationMode"), ("x", "v"), ("a", "v"), ("target", "s"), ("state_ver", "i"),
            ("control_profile_hash", "d"), ("evidence_hash", "d"), ("lineage_hash", "d"), ("approval_hash", "d"),
            ("decision_key_id", "s"), ("decision_trust_epoch", "s"), ("tau_eval", "i"), ("tau_expiry", "i"),
            ("decision", "e:DecisionOutcome"), ("reason_codes", "i"), ("scoring_profile_hash", "d"),
            ("trust_state_hash", "d"), ("adverse_disposition", "e:AdverseDisposition"), ("containment_digest", "d"),
            ("eval_clock_id", "s")]
RECEIPT = [("domain", "s"), ("schema_ver", "s"), ("receipt_id", "s"), ("capability_id", "s"), ("req_id", "s"),
           ("decision_digest", "d"), ("x", "v"), ("target", "s"), ("control_profile_hash", "d"),
           ("execution_status", "e:ExecutionStatus"), ("failure_phase", "e:FailurePhase"), ("reason_code", "i"),
           ("reconciliation_required", "b"), ("pre_state_digest", "d"), ("post_state_digest", "d"),
           ("tau_dispatch", "i"), ("tau_finalized", "i"), ("receipt_key_id", "s"), ("receipt_trust_epoch", "s"),
           ("expected_state_ver", "i"), ("observed_pre_state_ver", "i"), ("observed_post_state_ver", "oi")]
ATTESTATION = [("domain", "s"), ("schema_ver", "s"), ("attestation_id", "s"), ("provenance_key_id", "s"),
               ("provenance_trust_epoch", "s"), ("attester_id", "s"), ("evidence_digest", "d"),
               ("dependencies", "atoms"), ("tau_issued", "i"), ("tau_expiry", "i")]
MANIFEST = [("domain", "s"), ("schema_ver", "s"), ("manifest_id", "s"), ("membership_key_id", "s"),
            ("membership_trust_epoch", "s"), ("authority_id", "s"), ("family_id", "s"), ("ingress_channel", "s"),
            ("members", "members"), ("tau_issued", "i"), ("tau_expiry", "i")]
ENUM_PREFIX = {"AdverseDisposition": "ADVERSE_DISPOSITION_", "DecisionOutcome": "DECISION_OUTCOME_", "AuthorizationMode": "AUTHORIZATION_MODE_",
               "ExecutionStatus": "EXECUTION_STATUS_", "FailurePhase": "FAILURE_PHASE_"}


class Codec:
    def __init__(self, pb2):
        self.pb = pb2
        from google.protobuf import unknown_fields
        self._unknown = unknown_fields.UnknownFieldSet

    # ---- canonical Value <-> proto Value (lossless) ----
    def to_value(self, v):
        m = self.pb.Value()
        if v is None:
            m.null_value = True
        elif isinstance(v, bool):
            m.bool_value = v
        elif isinstance(v, int):
            m.int_value = v
        elif isinstance(v, R.F64):
            m.f64_bits = v.bits
        elif isinstance(v, str):
            m.string_value = v
        elif isinstance(v, bytes):
            m.bytes_value = v
        elif isinstance(v, list):
            m.list_value.SetInParent()
            for it in v:
                m.list_value.items.append(self.to_value(it))
        elif isinstance(v, dict):
            m.map_value.SetInParent()
            for k in sorted(v):
                e = m.map_value.entries.add()
                e.key = k
                e.value.CopyFrom(self.to_value(v[k]))
        else:
            raise TypeError(type(v))
        return m

    def from_value(self, m):
        self._strict(m)
        k = m.WhichOneof("kind")
        if k is None:
            raise TransportError("Value has no kind")
        if k == "null_value":
            if not m.null_value:
                raise TransportError("null_value must be true")
            return None
        if k == "bool_value":
            return m.bool_value
        if k == "int_value":
            return m.int_value
        if k == "f64_bits":
            return R.F64(m.f64_bits)
        if k == "string_value":
            return m.string_value
        if k == "bytes_value":
            return bytes(m.bytes_value)
        if k == "list_value":
            return [self.from_value(i) for i in m.list_value.items]
        out = {}
        for e in m.map_value.entries:
            if e.key in out:
                raise TransportError(f"duplicate map key {e.key!r}")
            if not e.HasField("value"):
                raise TransportError("map entry without value")
            out[e.key] = self.from_value(e.value)
        return out

    def _strict(self, msg):
        if len(self._unknown(msg)):
            raise TransportError(f"unknown fields present in {msg.DESCRIPTOR.name}")

    # ---- canonical object <-> proto message ----
    def to_proto(self, obj, spec, cls):
        m = cls()
        if set(obj) != {k for k, _ in spec}:
            raise TransportError(f"canonical object keys do not match {cls.DESCRIPTOR.name}")
        for key, kind in spec:
            v = obj[key]
            if kind in ("s", "i", "b"):
                setattr(m, key, v)
            elif kind == "v":
                getattr(m, key).CopyFrom(self.to_value(v))
            elif kind == "d":
                raw = bytes.fromhex(v)
                if len(raw) != 32:
                    raise TransportError(f"{key} is not 32 bytes")
                setattr(m, key, raw)
            elif kind.startswith("e:"):
                enum = getattr(self.pb, kind[2:])
                setattr(m, key, enum.Value(ENUM_PREFIX[kind[2:]] + v))
            elif kind == "oi":
                if v is not None:
                    setattr(m, key, v)
            elif kind == "atoms":
                for a in v:
                    t, _, i = a.partition(":")
                    at = m.dependencies.add()
                    at.dependency_type, at.dependency_id = t, i
            elif kind == "members":
                for mm in v:
                    e = m.members.add()
                    e.evidence_id, e.evidence_digest = mm["evidence_id"], bytes.fromhex(mm["evidence_digest"])
                    if mm["parent_id"] is not None:
                        e.parent_id = mm["parent_id"]
        return m

    def from_proto(self, m, spec):
        self._strict(m)
        obj = {}
        for key, kind in spec:
            if kind == "s":
                if getattr(m, key) == "":
                    raise TransportError(f"required string {key} missing")
                obj[key] = getattr(m, key)
            elif kind in ("i", "b"):
                obj[key] = getattr(m, key)
            elif kind == "v":
                if not m.HasField(key):
                    raise TransportError(f"required value {key} missing")
                obj[key] = self.from_value(getattr(m, key))
            elif kind == "d":
                raw = getattr(m, key)
                if len(raw) != 32:
                    raise TransportError(f"{key} must be exactly 32 bytes")
                obj[key] = raw.hex()
            elif kind.startswith("e:"):
                name = getattr(self.pb, kind[2:]).Name(getattr(m, key))
                if name.endswith("_UNSPECIFIED"):
                    raise TransportError(f"{key} unspecified")
                obj[key] = name[len(ENUM_PREFIX[kind[2:]]):]
            elif kind == "oi":
                obj[key] = getattr(m, key) if m.HasField(key) else None
            elif kind == "atoms":
                atoms = []
                for at in m.dependencies:
                    self._strict(at)
                    atoms.append(f"{at.dependency_type}:{at.dependency_id}")
                obj[key] = atoms  # canonical-order rule is enforced by admissibility, not silently fixed here
            elif kind == "members":
                out = []
                for e in m.members:
                    self._strict(e)
                    if len(e.evidence_digest) != 32 or e.evidence_id == "":
                        raise TransportError("manifest member malformed")
                    out.append({"evidence_id": e.evidence_id, "evidence_digest": e.evidence_digest.hex(),
                                "parent_id": e.parent_id if e.HasField("parent_id") else None})
                obj[key] = out
        return obj


def collect(tests):
    """Every signed object in the suite: (label, kind, canonical payload, public key | None, signature | None)."""
    items = []
    g = json.load(open(os.path.join(tests, "fixtures", "golden_vectors.json"), encoding="utf-8"))
    keys = {k["key_id"]: k["public_key"] for k in g["keys"]}
    for o in g["objects"]:
        if o["artifact_type"] in ("approval", "decision", "receipt"):
            items.append((f"golden:{o['id']}", o["artifact_type"], o["payload"], keys[o["signing_key_id"]],
                          o["expected_signature"]))
    auth = json.load(open(os.path.join(tests, "vectors", "auth_expiry_skew.json"), encoding="utf-8"))
    for v in auth["vectors"]:
        i = v["input"]
        if v["test_id"].startswith("auth_schema_"):  # deliberately schema-invalid: not representable
            continue
        if v["test_id"] != "auth_expiry_013":  # 013 is deliberately non-canonical bytes
            items.append((f"auth:{v['test_id']}:d", "decision", i["decision_payload"], None, None))
        if i["approval_payload"]:
            items.append((f"auth:{v['test_id']}:p", "approval", i["approval_payload"], None, None))
    import yaml
    for f in sorted(glob.glob(os.path.join(tests, "fixtures", "cas_reconciliation", "*.yaml"))):
        e = yaml.safe_load(open(f, encoding="utf-8"))["expected"]
        items.append((f"cas:{os.path.basename(f)}", "receipt", e["receipt_payload"], None, None))
    v30 = json.load(open(os.path.join(tests, "vectors", "scoring_coverage_v0.3.0-alpha.json"), encoding="utf-8"))
    reg30 = v30["trust_state"]["key_registry"]
    seen_m = set()
    for c in v30["cases"]:
        for f_ in c["input"]["families"]:
            env = f_.get("manifest") if isinstance(f_, dict) else None
            if env and env["payload"]["manifest_id"] not in seen_m:
                seen_m.add(env["payload"]["manifest_id"])
                pk = reg30.get(env["payload"]["membership_key_id"], {}).get("public_key")
                items.append((f"v030:{c['id']}:{f_['family_id']}", "manifest", env["payload"], pk, env["signature"]))
            for m in (f_.get("members", []) if isinstance(f_, dict) else []):
                pe = m.get("provenance") if isinstance(m, dict) else None
                if pe and pe["payload"]["attestation_id"] not in seen_m:
                    seen_m.add(pe["payload"]["attestation_id"])
                    pk = reg30.get(pe["payload"]["provenance_key_id"], {}).get("public_key")
                    items.append((f"v030:{c['id']}:{m['evidence_id']}", "attestation", pe["payload"], pk, pe["signature"]))
    v21 = json.load(open(os.path.join(tests, "vectors", "scoring_coverage_v0.2.1-alpha.json"), encoding="utf-8"))
    reg = v21["trust_state"]["registry"]
    seen = set()
    for c in v21["cases"]:
        for f_ in c["input"]["families"]:
            for m in f_["members"]:
                env = m.get("provenance")
                if env and env["payload"]["attestation_id"] not in seen:
                    seen.add(env["payload"]["attestation_id"])
                    pk = reg.get(env["payload"]["provenance_key_id"], {}).get("public_key")
                    items.append((f"v021:{c['id']}:{m['evidence_id']}", "attestation", env["payload"], pk,
                                  env["signature"]))
    return items


# ---------------------------------------------------------------------------
# FlatBuffers: canonical -> flatc JSON -> binary -> flatc JSON -> canonical (uses the flatc CLI)
# ---------------------------------------------------------------------------
FB_ROOT = {"approval": "SignedApproval", "decision": "SignedDecision", "receipt": "SignedReceipt",
           "attestation": "SignedProvenanceAttestation", "manifest": "SignedFamilyManifest"}


def fb_value(v):
    if v is None:
        return {"kind_type": "NullValue", "kind": {}}
    if isinstance(v, bool):
        return {"kind_type": "BoolValue", "kind": {"value": v}}
    if isinstance(v, int):
        return {"kind_type": "IntValue", "kind": {"value": v}}
    if isinstance(v, R.F64):
        return {"kind_type": "F64Bits", "kind": {"bits": v.bits}}
    if isinstance(v, str):
        return {"kind_type": "StringValue", "kind": {"value": v}}
    if isinstance(v, bytes):
        return {"kind_type": "BytesValue", "kind": {"value": list(v)}}
    if isinstance(v, list):
        return {"kind_type": "ValueList", "kind": {"items": [fb_value(i) for i in v]}}
    return {"kind_type": "ValueMap", "kind": {"entries": [{"key": k, "value": fb_value(v[k])} for k in sorted(v)]}}


def fb_unvalue(j):
    t, k = j.get("kind_type"), j.get("kind", {})
    if t == "NullValue":
        return None
    if t == "BoolValue":
        return bool(k.get("value", False))
    if t == "IntValue":
        return int(k.get("value", 0))
    if t == "F64Bits":
        return R.F64(int(k.get("bits", 0)))
    if t == "StringValue":
        return k["value"]
    if t == "BytesValue":
        return bytes(k["value"])
    if t == "ValueList":
        return [fb_unvalue(i) for i in k["items"]]
    if t == "ValueMap":
        out = {}
        for e in k["entries"]:
            if e["key"] in out:
                raise TransportError("duplicate map key")
            out[e["key"]] = fb_unvalue(e["value"])
        return out
    raise TransportError(f"unknown Value kind {t!r}")


def to_fb(obj, spec):
    out = {}
    for key, kind in spec:
        v = obj[key]
        if kind in ("s", "i", "b"):
            out[key] = v
        elif kind == "v":
            out[key] = fb_value(v)
        elif kind == "d":
            out[key] = list(bytes.fromhex(v))
        elif kind.startswith("e:"):
            out[key] = v
        elif kind == "oi":
            if v is not None:
                out[key] = {"value": v}
        elif kind == "atoms":
            out[key] = [{"dependency_type": a.partition(":")[0], "dependency_id": a.partition(":")[2]} for a in v]
        elif kind == "members":
            out[key] = [dict({"evidence_id": m["evidence_id"], "evidence_digest": list(bytes.fromhex(m["evidence_digest"]))},
                             **({"parent_id": m["parent_id"]} if m["parent_id"] is not None else {})) for m in v]
    return out


def from_fb(j, spec):
    allowed = {k for k, _ in spec}
    if set(j) - allowed:
        raise TransportError(f"unexpected FlatBuffers fields {sorted(set(j) - allowed)}")
    obj = {}
    for key, kind in spec:
        if kind == "s":
            if not j.get(key):
                raise TransportError(f"required string {key} missing")
            obj[key] = j[key]
        elif kind == "i":
            obj[key] = int(j.get(key, 0))
        elif kind == "b":
            obj[key] = bool(j.get(key, False))
        elif kind == "v":
            obj[key] = fb_unvalue(j[key])
        elif kind == "d":
            if len(j.get(key, [])) != 32:
                raise TransportError(f"{key} must be exactly 32 bytes")
            obj[key] = bytes(j[key]).hex()
        elif kind.startswith("e:"):
            if j.get(key, "UNSPECIFIED") == "UNSPECIFIED":
                raise TransportError(f"{key} unspecified")
            obj[key] = j[key]
        elif kind == "oi":
            obj[key] = int(j[key].get("value", 0)) if key in j else None
        elif kind == "atoms":
            obj[key] = [f"{a['dependency_type']}:{a['dependency_id']}" for a in j.get(key, [])]
        elif kind == "members":
            obj[key] = [{"evidence_id": m["evidence_id"], "evidence_digest": bytes(m["evidence_digest"]).hex(),
                         "parent_id": m.get("parent_id")} for m in j.get(key, [])]
    return obj


def flatc_path():
    import shutil
    return os.environ.get("FLATC") or shutil.which("flatc")


def flatbuffers_roundtrip(items, specs):
    import subprocess
    flatc = flatc_path()
    if not flatc:
        return None
    work = tempfile.mkdtemp(prefix="prc_fb_")
    fails, count, sigs = [], 0, 0
    by_kind = {}
    for n, (label, kind, payload, pub, sig) in enumerate(items):
        by_kind.setdefault(kind, []).append((n, label, payload, pub, sig))
    for kind, group in by_kind.items():
        spec = specs[kind]
        root = f"{FB_NS}.{FB_ROOT[kind]}"
        ins, outs = os.path.join(work, kind, "in"), os.path.join(work, kind, "bin")
        back = os.path.join(work, kind, "back")
        for d in (ins, outs, back):
            os.makedirs(d, exist_ok=True)
        for n, label, payload, pub, sig in group:
            doc = {"payload": to_fb(payload, spec), "signature": list(bytes.fromhex(sig)) if sig else []}
            json.dump(doc, open(os.path.join(ins, f"o{n}.json"), "w"))
        files = sorted(glob.glob(os.path.join(ins, "*.json")))
        r = subprocess.run([flatc, "-b", "--root-type", root, "-o", outs, FBS] + files, capture_output=True, text=True)
        if r.returncode != 0:
            return {"error": r.stderr.strip()[:300]}
        bins = sorted(glob.glob(os.path.join(outs, "*.bin")))
        r = subprocess.run([flatc, "-t", "--strict-json", "--defaults-json", "--raw-binary", "--root-type", root,
                            "-o", back, FBS, "--"] + bins, capture_output=True, text=True)
        if r.returncode != 0:
            return {"error": r.stderr.strip()[:300]}
        for n, label, payload, pub, sig in group:
            try:
                j = json.load(open(os.path.join(back, f"o{n}.json")))
                canon = from_fb(j["payload"], spec)
            except (TransportError, KeyError, ValueError) as ex:
                fails.append(f"{label}: {ex}")
                continue
            if R.H(canon) != R.H(payload):
                fails.append(f"{label}: canonical hash changed across FlatBuffers transport")
            if pub and sig:
                sigs += 1
                if R.ed25519_verify(pub, R.H(payload), sig) != R.ed25519_verify(pub, R.H(canon), bytes(j.get("signature", [])).hex()):
                    fails.append(f"{label}: signature verdict changed")
            count += 1
    # FlatBuffers bytes are not canonical either: same message, different field order in the source JSON
    first = by_kind["decision"][0]
    a = to_fb(first[2], specs["decision"])
    b = dict(reversed(list(a.items())))
    for name, doc in (("a", a), ("b", b)):
        json.dump({"payload": doc, "signature": []}, open(os.path.join(work, f"demo_{name}.json"), "w"))
    subprocess.run([flatc, "-b", "--root-type", f"{FB_NS}.SignedDecision", "-o", work, FBS,
                    os.path.join(work, "demo_a.json"), os.path.join(work, "demo_b.json")], capture_output=True)
    ba, bb = open(os.path.join(work, "demo_a.bin"), "rb").read(), open(os.path.join(work, "demo_b.bin"), "rb").read()
    unknown = dict(a, not_in_schema=1)
    json.dump({"payload": unknown, "signature": []}, open(os.path.join(work, "demo_u.json"), "w"))
    ru = subprocess.run([flatc, "-b", "--root-type", f"{FB_NS}.SignedDecision", "-o", work, FBS,
                         os.path.join(work, "demo_u.json")], capture_output=True, text=True)
    return {"count": count, "sigs": sigs, "fails": fails,
            "demo": {"field_order_changes_bytes": ba != bb, "flatc_rejects_unknown_field": ru.returncode != 0}}


def main():
    try:
        pb = load_pb2()
    except ImportError:
        if os.environ.get("PRC_REQUIRE_TRANSPORT"):
            raise
        print("transport round trip: SKIPPED (pip install grpcio-tools protobuf)")
        return 0
    codec = Codec(pb)
    spec = {"approval": (APPROVAL, pb.ExternalApproval, pb.SignedApproval),
            "decision": (DECISION, pb.DecisionCapability, pb.SignedDecision),
            "receipt": (RECEIPT, pb.ExecutionReceipt, pb.SignedReceipt),
            "attestation": (ATTESTATION, pb.ProvenanceAttestation, pb.SignedProvenanceAttestation),
            "manifest": (MANIFEST, pb.FamilyManifest, pb.SignedFamilyManifest)}
    fails, counts, sig_checked = [], {}, 0
    for label, kind, payload, pub, sig in collect(os.path.join(ROOT, "tests")):
        fields, cls, signed_cls = spec[kind]
        try:
            wrapper = signed_cls()
            wrapper.payload.CopyFrom(codec.to_proto(payload, fields, cls))
            wrapper.signature = bytes.fromhex(sig) if sig else b""
            wire = wrapper.SerializeToString()
            back = signed_cls.FromString(wire)
            codec._strict(back)
            canon = codec.from_proto(back.payload, fields)
        except TransportError as ex:
            fails.append(f"{label}: {ex}")
            continue
        if R.H(canon) != R.H(payload):
            fails.append(f"{label}: canonical hash changed across transport")
        if pub and sig:
            before = R.ed25519_verify(pub, R.H(payload), sig)
            after = R.ed25519_verify(pub, R.H(canon), back.signature.hex())
            sig_checked += 1
            if before != after:
                fails.append(f"{label}: signature verdict changed across transport")
        counts[kind] = counts.get(kind, 0) + 1

    # --- why Protobuf bytes are not canonical --------------------------------------------------
    g = json.load(open(os.path.join(ROOT, "tests", "fixtures", "golden_vectors.json"), encoding="utf-8"))
    d = next(o for o in g["objects"] if o["id"] == "decision_automated")
    full = pb.SignedDecision()
    full.payload.CopyFrom(codec.to_proto(d["payload"], DECISION, pb.DecisionCapability))
    full.signature = bytes.fromhex(d["expected_signature"])
    wire_a = full.SerializeToString()
    first, second = pb.SignedDecision(), pb.SignedDecision()
    names = [k for k, _ in DECISION]
    for i, n in enumerate(names):
        tgt = first if i % 2 else second
        fld = getattr(full.payload, n)
        if hasattr(fld, "CopyFrom"):
            getattr(tgt.payload, n).CopyFrom(fld)
        else:
            setattr(tgt.payload, n, fld)
    first.signature = full.signature
    wire_b = second.SerializeToString() + first.SerializeToString()  # protobuf merges concatenated messages
    parsed_b = pb.SignedDecision.FromString(wire_b)
    same_msg = parsed_b == full
    canon_b = R.H(codec.from_proto(parsed_b.payload, DECISION))
    demo1 = {"same_parsed_message": same_msg,
             "wire_sha256_differs": hashlib.sha256(wire_a).hexdigest() != hashlib.sha256(wire_b).hexdigest(),
             "canonical_hash_identical": canon_b == d["expected_hash"]}
    tampered = wire_a + bytes([0x98, 0x06, 0x01])  # field 99, varint 1: unknown to the schema
    lenient = pb.SignedDecision.FromString(tampered)
    try:
        codec._strict(lenient)
        strict_rejects = False
    except TransportError:
        strict_rejects = True
    demo2 = {"lenient_parser_accepts": lenient.payload == full.payload, "strict_verifier_rejects": strict_rejects}

    print(f"transport round trip: {sum(counts.values())} signed objects "
          f"({', '.join(f'{k}={v}' for k, v in sorted(counts.items()))}), {sig_checked} signatures re-verified, "
          f"{len(fails)} failures")
    print(f"  non-canonical wire demo: {demo1}")
    print(f"  unknown-field demo:      {demo2}")
    for f in fails:
        print("  FAIL", f)
    ok = not fails and all(demo1.values()) and all(demo2.values())
    fb = flatbuffers_roundtrip(collect(os.path.join(ROOT, "tests")), {k: v[0] for k, v in spec.items()})
    if fb is None:
        print("  FlatBuffers: SKIPPED (set FLATC or put flatc on PATH)")
    elif "error" in fb:
        print("  FlatBuffers: flatc error:", fb["error"])
        ok = False
    else:
        print(f"  FlatBuffers round trip: {fb['count']} signed objects, {fb['sigs']} signatures re-verified, "
              f"{len(fb['fails'])} failures; demo {fb['demo']}")
        for f in fb["fails"]:
            print("  FAIL (fb)", f)
        ok = ok and not fb["fails"] and all(fb["demo"].values())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
