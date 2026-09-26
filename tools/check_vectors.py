#!/usr/bin/env python3
"""
Checks the committed conformance vectors.

  1. MANIFEST.json hashes match the files on disk (vectors have not drifted).
  2. Every expected value is recomputed from the vector's *inputs* by the reference model.
  3. Internal consistency (payload <-> bytes <-> hash <-> signature <-> public key <-> seed).
  4. Determinism: regenerating into a temp directory reproduces every file byte-for-byte.

Exit status is non-zero on any failure.
"""
from __future__ import annotations

import filecmp
import hashlib
import json
import os
import struct
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "reference"))
try:
    import prc_ref as R  # noqa: E402
except ModuleNotFoundError:
    raise SystemExit(
        "prc_ref not found. This script needs reference/prc_ref.py next to tools/ "
        "(repo layout: reference/prc_ref.py, tools/%s). In the notebook, run the "
        "'Reference model' %%%%writefile cell first, or unzip the whole repo." % os.path.basename(__file__))

FAIL: list = []
COUNT = {"checks": 0}


def check(cond, msg):
    COUNT["checks"] += 1
    if not cond:
        FAIL.append(msg)


def from_tj(t):
    k = t["type"]
    if k == "null":
        return None
    if k == "bool":
        return t["value"]
    if k == "int":
        return int(t["value"])
    if k == "f64":
        return R.F64(int(t["bits"], 16))
    if k == "str":
        return t["value"]
    if k == "bytes":
        return bytes.fromhex(t["hex"])
    if k == "list":
        return [from_tj(i) for i in t["items"]]
    if k == "map":
        return {kk: from_tj(v) for kk, v in t["entries"]}
    raise ValueError(k)


def check_manifest(tests):
    m = json.load(open(os.path.join(tests, "MANIFEST.json")))
    for rel, h in m["files"].items():
        with open(os.path.join(tests, rel), "rb") as f:
            check(hashlib.sha256(f.read()).hexdigest() == h, f"manifest: {rel} hash drift")


def check_golden(tests):
    g = json.load(open(os.path.join(tests, "fixtures", "golden_vectors.json"), encoding="utf-8"))
    keys = {}
    for k in g["keys"]:
        tk = R.TestKey.derive(k["domain"], k["label"])
        check(tk.seed.hex() == k["seed"] and tk.public_hex == k["public_key"] and tk.key_id == k["key_id"],
              f"golden: key {k['key_id']} derivation")
        keys[k["key_id"]] = k
    for name in ("NULL_APPROVAL_DIGEST", "NULL_STATE_DIGEST"):
        c = g["constants"][name]
        check(R.encode(c["preimage"]).hex() == c["preimage_bytes"], f"golden: {name} preimage")
        check(R.H(c["preimage"]) == c["value"] == getattr(R, name), f"golden: {name} value")
    u = g["constants"]["UUIDv7_example"]
    check(R.uuid7(u["unix_ms"], u["label"]) == u["value"], "golden: uuid7")
    for p in g["primitives"]:
        b = R.encode(from_tj(p["value"]))
        check(b.hex() == p["expected_bytes"], f"golden: primitive {p['id']} bytes")
        check(R.H_bytes(b) == p["expected_hash"], f"golden: primitive {p['id']} hash")
    for r in g["must_reject"]:
        try:
            R.decode(bytes.fromhex(r["bytes"]))
            check(False, f"golden: reject {r['id']} was accepted")
        except R.CanonicalDecodeError:
            check(True, "")
    for o in g["objects"]:
        b = R.encode(o["payload"])
        check(b.hex() == o["expected_bytes"], f"golden: object {o['id']} bytes")
        check(R.H_bytes(b) == o["expected_hash"], f"golden: object {o['id']} hash")
        k = keys[o["signing_key_id"]]
        check(k["domain"] == o["artifact_type"], f"golden: object {o['id']} signed outside its key domain")
        check(R.ed25519_verify(k["public_key"], o["expected_hash"], o["expected_signature"]),
              f"golden: object {o['id']} signature")
    return len(g["primitives"]) + len(g["must_reject"]) + len(g["objects"])


def check_auth(tests):
    doc = json.load(open(os.path.join(tests, "vectors", "auth_expiry_skew.json"), encoding="utf-8"))
    check(R.H(doc["trust_state"]) == doc["trust_state_hash"], "auth: trust_state_hash")
    for v in doc["vectors"]:
        i, e = v["input"], v["expected_output"]
        ctx = dict(i["context"], trust_state=v.get("trust_state", doc["trust_state"]))
        valid, bits = R.decision_binding_valid(ctx, i["decision_bytes"], i["decision_signature"],
                                               i["approval_bytes"], i["approval_signature"])
        tid = v["test_id"]
        check(valid == e["DecisionBindingValid"], f"auth: {tid} validity")
        check(bits == e["reason_bitfield"], f"auth: {tid} bitfield {R.reason_names(bits)} != {e['reason_codes']}")
        check(R.reason_names(e["reason_bitfield"]) == e["reason_codes"], f"auth: {tid} names/bits disagree")
        check(R.H_bytes(bytes.fromhex(i["decision_bytes"])) == i["decision_hash"], f"auth: {tid} hash")
        canonical = R.encode(i["decision_payload"]).hex() == i["decision_bytes"]
        check(canonical == ("DECODE_INVALID" not in e["reason_codes"]), f"auth: {tid} payload/bytes consistency")
        if i["approval_bytes"]:
            check(R.encode(i["approval_payload"]).hex() == i["approval_bytes"], f"auth: {tid} approval bytes")
        import prc_schema as SC
        schema_ok = not SC.validate(i["decision_payload"], "decision")
        check(schema_ok == ("OBJECT_SCHEMA_INVALID" not in e["reason_codes"] and "DECODE_INVALID" not in e["reason_codes"])
              or "DECODE_INVALID" in e["reason_codes"], f"auth: {tid} schema verdict consistency")
    return len(doc["vectors"])


def check_numeric(tests):
    vdir = os.path.join(tests, "vectors")
    blob = open(os.path.join(vdir, "kahan_cordic_ieee754.bin"), "rb").read()
    doc = json.load(open(os.path.join(vdir, "kahan_cordic_ieee754.json")))
    check(hashlib.sha256(blob).hexdigest() == doc["binary_sha256"], "numeric: bin sha256")
    check(blob[:4] == b"PRNV", "numeric: magic")
    ver, _res, n = struct.unpack("<HHI", blob[4:12])
    check(ver == 1 and n == len(doc["cases"]), "numeric: header")
    pos = 12
    for case in doc["cases"]:
        op, flags, _r, cnt = struct.unpack("<BBHI", blob[pos:pos + 8]); pos += 8
        ins = list(struct.unpack(f"<{cnt}Q", blob[pos:pos + 8 * cnt])); pos += 8 * cnt
        (out,) = struct.unpack("<Q", blob[pos:pos + 8]); pos += 8
        cid = case["id"]
        check([f"{x:016x}" for x in ins] == case["inputs_bits"], f"numeric: {cid} inputs bin/json")
        check(f"{out:016x}" == case["expected"]["output_bits"], f"numeric: {cid} output bin/json")
        check(bool(flags & 2) == case["expected"]["safe_state_lock"], f"numeric: {cid} lock bin/json")
        if op == 1:
            g = R.authorization_check(*ins)
            check(g["result"] == bool(flags & 1) == case["expected"]["result"], f"numeric: {cid} result")
            check(g["c_effective_bits"] == out and g["safe_state_lock"] == bool(flags & 2), f"numeric: {cid} recompute")
        else:
            g = R.kahan_sum(ins)
            check(g["result_bits"] == out and g["safe_state_lock"] == bool(flags & 2), f"numeric: {cid} recompute")
    check(pos == len(blob), "numeric: trailing bytes in bin")
    return len(doc["cases"])


def check_lineage(tests):
    d = os.path.join(tests, "fixtures", "lineage_graphs")
    n = 0
    for f in sorted(os.listdir(d)):
        doc = yaml.safe_load(open(os.path.join(d, f), encoding="utf-8"))
        got, exp = R.evaluate_lineage(doc["input"]), doc["expected"]
        check(got["eligible"] == exp["eligible_classes"], f"lineage: {f} eligible")
        check(got["M"] == exp["M"] and got["C"] == exp["C"], f"lineage: {f} M/C")
        check(got["audit_events"] == exp["audit_events"], f"lineage: {f} audit")
        check(got["reason_code"] == exp["reason_bitfield"], f"lineage: {f} reason")
        for k, e in exp["classes"].items():
            c = got["classes"][k]
            check(c["eligible"] == e["eligible"] and c["invalidated"] == e["invalidated"], f"lineage: {f} {k} flags")
            if e["eligible"]:
                check(f"{R.bits_of(c['V']):016x}" == e["V_bits"] and c["A"] == e["A"] and c["I"] == e["I"],
                      f"lineage: {f} {k} values")
        n += 1
    return n


def check_cas(tests):
    d = os.path.join(tests, "fixtures", "cas_reconciliation")
    keys = {k.key_id: k for k in [R.TestKey.derive("receipt", "k1")]}
    n = 0
    for f in sorted(os.listdir(d)):
        doc = yaml.safe_load(open(os.path.join(d, f), encoding="utf-8"))
        i, e = doc["input"], doc["expected"]
        dd = i["decision_payload"]
        check(R.H(dd) == i["decision_hash"], f"cas: {f} decision hash")
        if doc["boundary"] == "local":
            res = R.execute_local(i["initial_state"], i["consumed_or_reserved_capabilities"], dd, i["mutation"])
        else:
            res = R.execute_distributed(i["initial_state"], i["consumed_or_reserved_capabilities"], dd,
                                        i["mutation"], i["target_behaviour"])
        check((res["status"], res["phase"], res["reason"], res["recon"]) ==
              (e["execution_status"], e["failure_phase"], e["reason_bitfield"], e["reconciliation_required"]),
              f"cas: {f} outcome")
        check(res["post_state"] == e["final_state"], f"cas: {f} final state")
        check((dd["capability_id"] in res["consumed"]) == e["capability_consumed"], f"cas: {f} capability")
        check(res["trace"] == e["phase_trace"], f"cas: {f} trace")
        r = e["receipt_payload"]
        check(r["execution_status"] == e["execution_status"] and r["decision_digest"] == i["decision_hash"],
              f"cas: {f} receipt fields")
        known = e["final_state"] is not None
        check(r["post_state_digest"] == (R.H(e["final_state"]) if known else R.NULL_STATE_DIGEST),
              f"cas: {f} post_state_digest")
        check(r["pre_state_digest"] == R.H(i["initial_state"]), f"cas: {f} pre_state_digest")
        # R-1: no receipt may contradict itself (expected vs observed state)
        check(r["observed_pre_state_ver"] == i["initial_state"]["version"], f"cas: {f} observed_pre_state_ver")
        check(r["expected_state_ver"] == dd["state_ver"], f"cas: {f} expected_state_ver")
        check(r["observed_post_state_ver"] == (e["final_state"]["version"] if known else None),
              f"cas: {f} observed_post_state_ver")
        check(known or e["execution_status"] in ("UNRESOLVED", "INDETERMINATE"), f"cas: {f} unknown post only if unresolved")
        rb = R.encode(r)
        check(rb.hex() == e["receipt_bytes"] and R.H_bytes(rb) == e["receipt_hash"], f"cas: {f} receipt bytes/hash")
        k = keys[e["receipt_key_id"]]
        check(R.ed25519_verify(k.public_hex, e["receipt_hash"], e["receipt_signature"]), f"cas: {f} receipt sig")
        n += 1
    return n


def check_scoring(tests):
    import prc_scoring as P
    doc = json.load(open(os.path.join(tests, "vectors", "scoring_jaccard_v0.1.0-alpha.json"), encoding="utf-8"))
    profiles = {k: v["declaration"] for k, v in doc["profiles"].items()}
    for k, v in doc["profiles"].items():
        check(R.H(v["declaration"]) == v["fingerprint"], f"scoring: profile {k} fingerprint")
    for x in doc["prc_exp_v1"]["vectors"]:
        check(P.hx(P.prc_exp(P.f(x["input_bits"]))) == x["expected_bits"], f"scoring: prc_exp({x['input_repr']})")
    by_id = {}
    for c in doc["cases"]:
        tr = P.evaluate(c["input"]["request"], c["input"]["families"], profiles[c["profile"]])
        check(R.encode(tr) == R.encode(c["expected_trace"]), f"scoring: {c['id']} trace")
        check(tr["profile_fingerprint"] == doc["profiles"][c["profile"]]["fingerprint"], f"scoring: {c['id']} fp")
        by_id[c["id"]] = c
    h = doc["headline"]
    a, b = by_id[h["allow_case"]], by_id[h["deny_case"]]
    check(a["expected_trace"]["decision"] == "ALLOW" and b["expected_trace"]["decision"] == "DENY", "scoring: headline flip")
    def strip(fams):
        import copy
        f2 = copy.deepcopy(fams)
        for f_ in f2:
            for m in f_["members"]:
                m["dependencies"] = []
        return R.encode(f2)
    check(strip(a["input"]["families"]) == strip(b["input"]["families"]) and
          a["input"]["request"] == b["input"]["request"], "scoring: headline inputs differ beyond lineage")
    check(a["expected_trace"]["T_bits"] == b["expected_trace"]["T_bits"], "scoring: headline thresholds differ")
    return len(doc["cases"]) + len(doc["prc_exp_v1"]["vectors"])


def check_coverage(tests):
    import prc_engine as ENG
    import prc_scoring as P
    doc = json.load(open(os.path.join(tests, "vectors", "scoring_coverage_v0.2.0-alpha.json"), encoding="utf-8"))
    base = doc["profiles"]["calibrated"]
    check(R.H(base["declaration"]) == base["fingerprint"], "coverage: profile fingerprint")
    by_id = {}
    for c in doc["cases"]:
        prof = c.get("profile_declaration", base["declaration"])
        try:
            tr = ENG.evaluate(c["input"]["request"], c["input"]["families"], prof)
        except Exception as ex:  # a regression may raise instead of failing closed
            check(False, f"coverage: {c['id']} raised {type(ex).__name__}: {ex}")
            by_id[c["id"]] = c
            continue
        check(R.encode(tr) == R.encode(c["expected_trace"]), f"coverage: {c['id']} trace")
        by_id[c["id"]] = c
    xfail = 0
    for c in doc["cases"]:
        ke = c.get("known_exploit")
        if ke:
            sec = ke["security_expectation"]
            meets = (c["expected_trace"]["decision"] == sec["decision"] and
                     c["expected_trace"]["M_bits"] == by_id[sec["same_M_as"]]["expected_trace"]["M_bits"])
            check(not meets, f"coverage: {c['id']} exploit no longer reproduces (XPASS) — promote it")
            xfail += 1
    for i, w in enumerate(doc["property_witnesses"]):
        prof = base["declaration"]
        t0 = ENG.evaluate(w["request"], w["base"], prof)
        t1 = ENG.evaluate(w["request"], w["base"] + [w["added"]], prof)
        check(t0["M_bits"] == w["M_base_bits"] and t1["M_bits"] == w["M_after_bits"], f"coverage: witness {i} bits")
        ok = (w["M_after_bits"] == w["M_base_bits"]) if w["kind"] == "idempotent" else \
            P.f(w["M_after_bits"]) >= P.f(w["M_base_bits"])
        check(ok and not (w["decision_base"] == "ALLOW" and w["decision_after"] == "DENY"), f"coverage: witness {i} property")
    import property_tests
    import contextlib, io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = property_tests.main(["--trials", "400"])
    check(rc == 0, "coverage: randomised property tests failed:\n" + buf.getvalue())
    COUNT["xfail"] = xfail
    return len(doc["cases"]) + len(doc["property_witnesses"])


def check_coverage_v021(tests):
    import prc_engine as ENG
    import prc_scoring as P
    doc = json.load(open(os.path.join(tests, "vectors", "scoring_coverage_v0.2.1-alpha.json"), encoding="utf-8"))
    profs = {k: v["declaration"] for k, v in doc["profiles"].items()}
    for k, v in doc["profiles"].items():
        check(R.H(v["declaration"]) == v["fingerprint"], f"v0.2.1: profile {k} fingerprint")
    for k in doc["provenance_keys"]:
        tk = R.TestKey.derive(k["domain"], k["label"])
        check(tk.public_hex == k["public_key"] and tk.key_id == k["key_id"], f"v0.2.1: key {k['label']}")
    check(doc["known_exploits_open"] == [], "v0.2.1: no known exploit may remain open in the current profile")
    for c in doc["cases"]:
        trust = c.get("trust_state", doc["trust_state"])
        try:
            tr = ENG.evaluate(c["input"]["request"], c["input"]["families"], profs[c["profile"]], trust)
        except Exception as ex:
            check(False, f"v0.2.1: {c['id']} raised {type(ex).__name__}: {ex}")
            continue
        check(R.encode(tr) == R.encode(c["expected_trace"]), f"v0.2.1: {c['id']} trace")
    by = {c["id"]: c["expected_trace"] for c in doc["cases"]}
    check(by["x01_self_declared_padding"]["decision"] == "DENY" and
          by["x01_self_declared_padding"]["M_bits"] == by["c04_three_correlated_fail"]["M_bits"], "v0.2.1: x01 must deny")
    check(by["c03_three_independent_pass"]["decision"] == "ALLOW" and by["c04_three_correlated_fail"]["decision"] == "DENY",
          "v0.2.1: lineage flip")
    d1, d2 = by["d01_unverified_contradiction"], by["d02_authenticated_defeater_vetoes"]
    check((d1["M_bits"], d1["C_bits"]) == (d2["M_bits"], d2["C_bits"]) and d1["decision"] == "ALLOW" and
          d2["decision"] == "DENY", "v0.2.1: defeater must be a categorical veto")
    for i, w in enumerate(doc["property_witnesses"]):
        t0 = ENG.evaluate(w["request"], w["base"], profs["calibrated"], doc["trust_state"])
        t1 = ENG.evaluate(w["request"], w["base"] + [w["added"]], profs["calibrated"], doc["trust_state"])
        check(t0["M_bits"] == w["M_base_bits"] and t1["M_bits"] == w["M_after_bits"], f"v0.2.1: witness {i} bits")
        ok = {"monotone": P.f(w["M_after_bits"]) >= P.f(w["M_base_bits"]) and
                          not (w["decision_base"] == "ALLOW" and w["decision_after"] == "DENY"),
              "idempotent": w["M_after_bits"] == w["M_base_bits"],
              "defeater": w["decision_after"] == "DENY"}[w["kind"]]
        check(ok, f"v0.2.1: witness {i} ({w['kind']}) property")
    return len(doc["cases"]) + len(doc["property_witnesses"])


def check_transport():
    """Optional: runs only when grpcio-tools/protobuf are installed (or PRC_REQUIRE_TRANSPORT=1)."""
    import contextlib, io
    if os.environ.get("PRC_SKIP_TRANSPORT"):
        COUNT["transport"] = "transport round trip: skipped (PRC_SKIP_TRANSPORT)"
        return
    import transport_roundtrip as TR
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = TR.main()
    out = buf.getvalue().strip()
    check(rc == 0, "transport round trip failed:\n" + out)
    COUNT["transport"] = out.splitlines()[0] if out else "no output"


def check_coverage_v030(tests):
    import prc_engine as ENG
    doc = json.load(open(os.path.join(tests, "vectors", "scoring_coverage_v0.3.0-alpha.json"), encoding="utf-8"))
    check(R.H(doc["scoring_profile_declaration"]) == doc["scoring_profile_hash"], "v0.3.0: scoring profile hash")
    check(R.H(doc["trust_state"]) == doc["trust_state_hash"], "v0.3.0: trust state hash")
    prof = doc["scoring_profile_declaration"]
    by = {}
    for c in doc["cases"]:
        tr = ENG.evaluate(c["input"]["request"], c["input"]["families"], prof, c.get("trust_state", doc["trust_state"]))
        check(R.encode(tr) == R.encode(c["expected_trace"]), f"v0.3.0: {c['id']} trace")
        by[c["id"]] = c["expected_trace"]
    base = by["a00_four_independent_pass"]
    for cid, want in (("a01_admitted_contradiction_defeats", "DENY"), ("a02_unattested_contradiction_contains", "MANUAL_REQUIRED")):
        check((by[cid]["M_bits"], by[cid]["C_bits"]) == (base["M_bits"], base["C_bits"]) and by[cid]["decision"] == want,
              f"v0.3.0: {cid} must leave M/C untouched and yield {want}")
    for cid in [k for k in by if k.startswith("m0") and k < "m07"]:
        check(by[cid]["decision"] == "ALLOW", f"v0.3.0: injection {cid} must be neutral")
    for i, w in enumerate(doc["property_witnesses"]):
        t0 = ENG.evaluate(w["request"], w["base"], prof, doc["trust_state"])
        t1 = ENG.evaluate(w["request"], w["after"], prof, doc["trust_state"])
        check((t0["M_bits"], t1["M_bits"], t0["C_bits"], t1["C_bits"]) ==
              (w["M_base_bits"], w["M_after_bits"], w["C_base_bits"], w["C_after_bits"]), f"v0.3.0: witness {i} bits")
    return len(doc["cases"]) + len(doc["property_witnesses"])


def check_determinism(tests):
    import generate_vectors as G
    with tempfile.TemporaryDirectory() as tmp:
        try:
            G.main(["--out", tmp])
        except SystemExit as e:  # generator refuses when the model disagrees with a declared intent
            check(False, f"determinism: generator refused to run: {e}")
            return
        for root, _dirs, files in os.walk(tmp):
            for fn in files:
                a = os.path.join(root, fn)
                rel = os.path.relpath(a, tmp)
                b = os.path.join(tests, rel)
                check(os.path.exists(b) and filecmp.cmp(a, b, shallow=False), f"determinism: {rel} differs")


def main():
    tests = os.path.join(ROOT, "tests")
    check_manifest(tests)
    counts = {
        "golden": check_golden(tests),
        "auth_expiry": check_auth(tests),
        "numeric": check_numeric(tests),
        "lineage": check_lineage(tests),
        "cas": check_cas(tests),
        "scoring": check_scoring(tests),
        "coverage_v0.2.0": check_coverage(tests),
        "coverage_v0.2.1": check_coverage_v021(tests),
        "coverage_v0.3.0": check_coverage_v030(tests),
    }
    check_transport()
    check_determinism(tests)
    print("vectors:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    print(COUNT.get("transport", ""))
    print(f"checks run: {COUNT['checks']}, failures: {len(FAIL)}")
    print("current profile coverage-v0.3.0-alpha: no known open exploit UNDER the declared trust state, atom "
          "registry/aliases, membership authorities, clock authorities and calibration")
    print(f"superseded coverage-v0.2.0-alpha still reproduces its atom-padding exploit by design: {COUNT.get('xfail', 0)}")
    for m in FAIL:
        print("  FAIL", m)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
