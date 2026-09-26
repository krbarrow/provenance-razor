#!/usr/bin/env python3
"""
Randomised property tests for the scoring profiles.

For coverage-v0.2.0-alpha these MUST all hold (exit status 1 otherwise):
  P1 monotone      M(E ∪ {e}) ≥ M(E) for any added eligible family e
  P2 idempotent    M(E ∪ {dup}) == M(E) bit-for-bit, dup = structural copy of a member of E under new ids
  P3 order-free    permuting families, members and atom lists leaves the whole trace bit-identical
  P4 bridge-safe   adding a family whose atoms are drawn from several existing families never lowers M
  P5 decision      none of the additions above turns ALLOW into DENY

The same generators are run against jaccard-v0.1.0-alpha for comparison; its violations are
reported, not failed on (they are the reason coverage exists).

    python tools/property_tests.py [--trials N] [--seed S]
"""
from __future__ import annotations

import argparse
import copy
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "reference"))
sys.path.insert(0, HERE)
import prc_ref as R            # noqa: E402
import prc_scoring as S        # noqa: E402
import prc_engine as ENG       # noqa: E402
import scoring_cases as J      # noqa: E402
import coverage_cases as CC    # noqa: E402

ATOMS = CC.ATOM_POOL
REQS = [J.WIRE, J.REFUND, J.ANNOTATE]


def rfam(rng: random.Random, fid: str) -> dict:
    deps = sorted({rng.choice(ATOMS) for _ in range(rng.randrange(5))})
    members = [J.ev(f"ev-{fid}", rng.randrange(1025) / 1024.0, deps)]
    if rng.random() < 0.3:
        members.append(J.ev(f"ev-{fid}-d", rng.randrange(1025) / 1024.0, deps[:1], parent=f"ev-{fid}",
                            state=rng.choice(["VALID", "DEGRADED", "UNAVAILABLE_OR_STALE"])))
    return J.fam(fid, *members)


def permute(rng, fams):
    p = copy.deepcopy(fams)
    rng.shuffle(p)
    for f_ in p:
        rng.shuffle(f_["members"])
        for m in f_["members"]:
            rng.shuffle(m["dependencies"])
    return p


def run(profile, trials, seed):
    rng = random.Random(seed)
    viol = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0}
    example = {}
    for t in range(trials):
        req = rng.choice(REQS)
        base = [rfam(rng, f"B{t}-{k}") for k in range(1 + rng.randrange(6))]
        t0 = ENG.evaluate(req, base, profile)
        m0 = S.f(t0["M_bits"])
        adds = {
            "P1": rfam(rng, f"N{t}"),
            "P2": CC.rename_family(rng.choice(base), f"D{t}"),
        }
        pool = sorted({a for f_ in base for a in f_["members"][0]["dependencies"]})
        adds["P4"] = J.fam(f"X{t}", J.ev(f"ev-X{t}", rng.randrange(1025) / 1024.0,
                                         sorted({rng.choice(pool) for _ in range(3)}) if pool else []))
        for prop, fam_ in adds.items():
            t1 = ENG.evaluate(req, base + [fam_], profile)
            m1 = S.f(t1["M_bits"])
            bad = (t1["M_bits"] != t0["M_bits"]) if prop == "P2" else (m1 < m0)
            if bad:
                viol[prop] += 1
                example.setdefault(prop, (m0, m1))
            if t0["decision"] == "ALLOW" and t1["decision"] == "DENY":
                viol["P5"] += 1
                example.setdefault("P5", (m0, m1))
        if R.encode(ENG.evaluate(req, permute(rng, base), profile)) != R.encode(t0):
            viol["P3"] += 1
    return viol, example


def run_v021(trials, seed):
    """coverage-v0.2.1-alpha over attested evidence. Adds:
       P6 defeater      adding an admitted CONTRADICTORY member always yields DENY
       P7 unattested    on a wire (κ_eff = 0) an unattested family leaves M bit-identical
       P8 tampered      a family whose attestation is forged/lifted leaves M bit-identical"""
    import coverage_v021_cases as V
    rng = CC.DRng(f"props-v021-{seed}")
    prof, trust = V.PROFILE, V.TRUST
    viol = {k: 0 for k in ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8")}
    for t in range(trials):
        rq = rng.pick([V.WIRE, V.REFUND, V.ANNOTATE])
        base = [V.random_attested_family(rng, f"B{t}-{k}") for k in range(1 + rng.below(5))]
        t0 = ENG.evaluate(rq, base, prof, trust)
        m0 = t0["M_bits"]

        def after(extra, r=rq, b=base):
            return ENG.evaluate(r, b + [extra], prof, trust)
        t1 = after(V.random_attested_family(rng, f"N{t}"))
        viol["P1"] += S.f(t1["M_bits"]) < S.f(m0)
        viol["P5"] += t0["decision"] == "ALLOW" and t1["decision"] == "DENY"
        viol["P2"] += after(V.reattest_rename(rng.pick(base), f"D{t}"))["M_bits"] != m0
        pool = sorted({a for f_ in base for m in f_["members"] if "provenance" in m
                       for a in m["provenance"]["payload"]["dependencies"]}, key=lambda s: s.encode())
        bridge = V.fam(f"X{t}", V.attest(V.ev(f"ev-X{t}", rng.unit(), f"org:X{t}"),
                                         sorted({rng.pick(pool) for _ in range(2)}) if pool else ["SOURCE:p"]))
        tb = after(bridge)
        viol["P4"] += S.f(tb["M_bits"]) < S.f(m0)
        viol["P5"] += t0["decision"] == "ALLOW" and tb["decision"] == "DENY"
        viol["P6"] += after(V.random_defeater_family(rng, f"Y{t}"))["decision"] != "DENY"
        tw0 = ENG.evaluate(V.WIRE, base, prof, trust)
        tw1 = ENG.evaluate(V.WIRE, base + [V.fam(f"U{t}", V.ev(f"ev-U{t}", rng.unit(), f"org:U{t}"))], prof, trust)
        viol["P7"] += tw1["M_bits"] != tw0["M_bits"]
        src = next((m for f_ in base for m in f_["members"] if "provenance" in m), None)
        if src is not None:
            forged = V.ev(f"ev-Z{t}", 1.0, f"org:Z{t}")
            forged["provenance"] = copy.deepcopy(src["provenance"])  # lifted onto new evidence
            viol["P8"] += after(V.fam(f"Z{t}", forged))["M_bits"] != m0
        shuffled = copy.deepcopy(base)
        for i in range(len(shuffled) - 1, 0, -1):
            j = rng.below(i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        for f_ in shuffled:
            f_["members"].reverse()
        viol["P3"] += R.encode(ENG.evaluate(rq, shuffled, prof, trust)) != R.encode(t0)
    return viol


def run_v030(trials, seed):
    """coverage-v0.3.0-alpha over attested evidence with signed family manifests. Adds:
       P9  injection    a member NOT listed in the manifest (INVALID, CONTRADICTORY, attested or forged
                        contradiction, rogue root, same-id impostor) changes no M, C, disposition or decision
       P10 containment  a listed unattested relevant contradiction leaves M and C bit-identical and
                        prevents ALLOW (ALLOW becomes MANUAL_REQUIRED)"""
    import coverage_v030_cases as W
    rng = CC.DRng(f"props-v030-{seed}")
    prof, ts = W.PROFILE, W.TS
    viol = {k: 0 for k in ("P1", "P2", "P3", "P4", "P5", "P6", "P9", "P10")}
    for t in range(trials):
        rq = rng.pick([W.ANNOTATE, W.ANNOTATE, W.REFUND, W.WIRE])
        base = [W.random_family(rng, f"F-B{t}-{k}") for k in range(2 + rng.below(4))]
        t0 = ENG.evaluate(rq, base, prof, ts)
        key0 = (t0["M_bits"], t0["C_bits"], t0.get("adverse_disposition"), t0["decision"])
        ev_ = lambda fams: ENG.evaluate(rq, fams, prof, ts)  # noqa: E731
        t1 = ev_(base + [W.random_family(rng, f"F-N{t}")])
        viol["P1"] += S.f(t1["M_bits"]) < S.f(t0["M_bits"])
        viol["P5"] += t0["decision"] == "ALLOW" and t1["decision"] == "DENY"
        src = rng.pick(base)
        dup = W.fam(f"F-D{t}", *__import__("coverage_v021_cases").reattest_rename(src, f"F-D{t}")["members"])
        viol["P2"] += ev_(base + [dup])["M_bits"] != t0["M_bits"]
        pool = sorted({a for f_ in base for m in f_["members"] if "provenance" in m
                       for a in m["provenance"]["payload"]["dependencies"]}, key=lambda x: x.encode())
        br = W.fam(f"F-X{t}", W.attest(W.ev(f"ev-X{t}", rng.unit(), f"org:X{t}"),
                                       sorted({rng.pick(pool) for _ in range(2)}) if pool else ["SOURCE:p"]))
        tb = ev_(base + [br])
        viol["P4"] += S.f(tb["M_bits"]) < S.f(t0["M_bits"])
        viol["P5"] += t0["decision"] == "ALLOW" and tb["decision"] == "DENY"
        binding = {k: rq[k] for k in ("action", "assertion", "target", "evidence_snapshot_id")}
        tgt_i = rng.below(len(base))
        tgt = base[tgt_i]
        root_id = tgt["members"][0]["evidence_id"]
        # P6: a listed, auditor-attested relevant contradiction always defeats
        c_att = W.attest(W.contra(f"ev-Y{t}", root_id, producer=f"org:Y{t}", binding=binding), [rng.pick(V_POOL())])
        fams6 = base[:tgt_i] + [W.fam(tgt["family_id"], *tgt["members"], c_att)] + base[tgt_i + 1:]
        viol["P6"] += ev_(fams6)["decision"] != "DENY"
        # P10: a listed unattested relevant contradiction contains
        c_un = W.contra(f"ev-Z{t}", root_id, producer=f"org:Z{t}", binding=binding)
        fams10 = base[:tgt_i] + [W.fam(tgt["family_id"], *tgt["members"], c_un)] + base[tgt_i + 1:]
        t10 = ev_(fams10)
        viol["P10"] += ((t10["M_bits"], t10["C_bits"]) != (t0["M_bits"], t0["C_bits"])
                        or t10["decision"] == "ALLOW"
                        or (t0["decision"] == "ALLOW" and t10["decision"] != "MANUAL_REQUIRED"))
        # P9: injection of an unlisted member of every adversarial kind
        kind = rng.below(6)
        if kind == 0:
            m = W.ev(f"ev-I{t}", 1.0, "org:attacker", parent=root_id, state="INVALID")
        elif kind == 1:
            m = c_un
        elif kind == 2:
            m = c_att
        elif kind == 3:
            m = copy.deepcopy(c_att)
            m["provenance"]["signature"] = "22" * 64
        elif kind == 4:
            m = W.ev(f"ev-R{t}", 0.99, "org:attacker")
        else:
            m = W.ev(root_id, 0.01, "org:attacker")  # same-id impostor
        fams9 = base[:tgt_i] + [W.inject(tgt, m)] + base[tgt_i + 1:]
        t9 = ev_(fams9)
        viol["P9"] += (t9["M_bits"], t9["C_bits"], t9.get("adverse_disposition"), t9["decision"]) != key0
        sh = copy.deepcopy(base)
        for i in range(len(sh) - 1, 0, -1):
            j = rng.below(i + 1)
            sh[i], sh[j] = sh[j], sh[i]
        for f_ in sh:
            f_["members"].reverse()
        viol["P3"] += R.encode(ev_(sh)) != R.encode(t0)
    return viol


def V_POOL():
    import coverage_v021_cases as V
    return V.POOL


def fuzz_verifiers(trials, seed):
    """P11 totality. Mutates signed decisions/approvals from the vector suite and malformed scoring
    inputs; counts exceptions escaping the *inner* verifiers (must be 0 for DecisionBindingValid) and
    faults that the scoring boundary converted into DENY (reported)."""
    import json
    import random as _r
    import generate_vectors as G
    import coverage_v030_cases as W
    rng = _r.Random(seed)
    doc = json.load(open(os.path.join(HERE, "..", "tests", "vectors", "auth_expiry_skew.json"), encoding="utf-8"))
    ts = doc["trust_state"]
    vs = [v for v in doc["vectors"] if v["expected_output"]["DecisionBindingValid"]]
    junk = [None, True, -1, 2 ** 63 - 1, "", "x", [], {}, [1, "a"], {"k": None}, 0.5, "0" * 64, "zz"]
    raised = flipped_allowed = resigned = 0
    for _ in range(trials):
        v = rng.choice(vs)
        i = v["input"]
        ctx = dict(i["context"], trust_state=ts)
        # (a) random byte flip without re-signing: must never be valid
        b = bytearray(bytes.fromhex(i["decision_bytes"]))
        k = rng.randrange(len(b))
        b[k] ^= 1 << rng.randrange(8)
        try:
            ok, _ = R._decision_binding_valid(ctx, b.hex(), i["decision_signature"], i["approval_bytes"], i["approval_signature"])
            flipped_allowed += ok
        except Exception:  # noqa: BLE001
            raised += 1
        # (b) replace a random field with junk and RE-SIGN validly: must never raise
        d = copy.deepcopy(i["decision_payload"])
        fld = rng.choice(sorted(d))
        d[fld] = copy.deepcopy(rng.choice(junk))
        if rng.random() < 0.2:
            d.pop(rng.choice(sorted(d)))
        try:
            db = R.encode(d)
        except Exception:  # noqa: BLE001  (unencodable junk, e.g. float is fine; skip nothing)
            continue
        sig = G.K_DECISION.sign_digest(R.H_bytes(db))
        p_hex, p_sig = i["approval_bytes"], i["approval_signature"]
        if p_hex and rng.random() < 0.5:
            p = copy.deepcopy(i["approval_payload"])
            p[rng.choice(sorted(p))] = copy.deepcopy(rng.choice(junk))
            pb = R.encode(p)
            p_hex, p_sig = pb.hex(), G.K_APPROVAL.sign_digest(R.H_bytes(pb))
        try:
            R._decision_binding_valid(ctx, db.hex(), sig, p_hex, p_sig)
            resigned += 1
        except Exception:  # noqa: BLE001
            raised += 1
    # scoring inputs
    faults = 0
    for t in range(trials // 4):
        fams = [W.random_family(CC.DRng(f"fz{seed}-{t}-{k}"), f"F-Z{t}-{k}") for k in range(2)]
        f_ = rng.choice(fams)
        target = rng.choice([f_, rng.choice(f_["members"]), f_.get("manifest", {}).get("payload", {})])
        if isinstance(target, dict) and target:
            target[rng.choice(sorted(target))] = copy.deepcopy(rng.choice(junk))
        tr = ENG.evaluate(W.WIRE, fams, W.PROFILE, W.TS)   # public boundary: must return, never raise
        faults += tr["stage"] == "VERIFIER_FAULT"
    return {"decision_verifier_exceptions": raised, "bitflips_accepted": flipped_allowed,
            "resigned_mutations_evaluated": resigned, "scoring_faults_converted_to_deny": faults}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=20260925)
    a = ap.parse_args(argv)
    cov, cex = run(CC.PROFILE, a.trials, a.seed)
    jac, jex = run(J.PROFILE, a.trials, a.seed)
    print(f"property tests, {a.trials} random trials per property")
    print(f"  {'':<14}{'P1 mono':>9}{'P2 idem':>9}{'P3 order':>10}{'P4 bridge':>11}{'P5 decision':>13}")
    for name, v in (("coverage-v0.2", cov), ("jaccard-v0.1", jac)):
        print(f"  {name:<14}{v['P1']:>9}{v['P2']:>9}{v['P3']:>10}{v['P4']:>11}{v['P5']:>13}")
    if jex:
        k = next(iter(jex))
        print(f"  jaccard counterexample ({k}): M {jex[k][0]!r} -> {jex[k][1]!r}")
    v21 = run_v021(max(1, a.trials // 3), a.seed)
    print(f"  coverage-v0.2.1-alpha over attested evidence, {max(1, a.trials // 3)} trials: " +
          ", ".join(f"{k}={v}" for k, v in v21.items()))
    print("    (P6 defeater always DENY, P7 unattested neutral on a wire, P8 forged/lifted attestation neutral)")
    n30 = max(1, a.trials // 3)
    v30 = run_v030(n30, a.seed)
    print(f"  coverage-v0.3.0-alpha with membership manifests, {n30} trials: " + ", ".join(f"{k}={v}" for k, v in v30.items()))
    print("    (P9 unlisted injection changes nothing, P10 containment keeps M/C and forbids ALLOW)")
    fz = fuzz_verifiers(max(1, a.trials), a.seed)
    print(f"  P11 totality fuzz ({max(1, a.trials)} mutations): " + ", ".join(f"{k}={v}" for k, v in fz.items()))
    failed = (any(cov.values()) or any(v21.values()) or any(v30.values())
              or fz["decision_verifier_exceptions"] or fz["bitflips_accepted"] or fz["scoring_faults_converted_to_deny"])
    print("coverage profiles:", "FAIL" if failed else "all properties hold")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
