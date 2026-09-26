"""
Vectors for scoring profile `coverage-v0.3.0-alpha` (EXPERIMENTAL):
  A-1 adverse disposition (CLEAR / CONTAIN / DEFEAT / LOCK) with the MANUAL_REQUIRED outcome,
  M-1 family-membership admissibility via signed family manifests, and the P-1 carry-overs.

Every case declares its intended decision (and key invariants); build() aborts on disagreement.
"""
from __future__ import annotations

import copy
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reference"))
import prc_ref as R              # noqa: E402
import prc_scoring as S          # noqa: E402
import prc_provenance as PV      # noqa: E402
import prc_membership as PM      # noqa: E402
import prc_engine as ENG         # noqa: E402
import coverage_cases as CC      # noqa: E402
import coverage_v021_cases as V  # noqa: E402
import trust_fixture as TF       # noqa: E402

bits = V.bits
BASE_MS, BASE_US, DAY = V.BASE_MS, V.BASE_US, V.DAY
TS, PROFILE = TF.TRUST_STATE, TF.SCORING_PROFILE_V030


def req(action, assertion, target, snap):
    return {"action": action, "assertion": assertion, "target": target, "evidence_snapshot_id": snap, "tau_eval": BASE_US}


WIRE = req("wire.release", "beneficiary-verified", "acct-9921", "snap-wire-001")
REFUND = req("payment.refund", "refund-eligible", "acct-000123", "snap-refund-001")
ANNOTATE = req("ledger.annotate", "memo-accurate", "acct-000123", "snap-annotate-001")
BIND_WIRE = {k: WIRE[k] for k in ("action", "assertion", "target", "evidence_snapshot_id")}
ev, attest = V.ev, V.attest


def manifest_for(family, key=TF.K_MEMB, authority=TF.GATEWAY, **kw):
    return PM.make_manifest(family, key, authority, epoch=TF.EPOCH,
                            tau_issued=kw.pop("tau_issued", BASE_US - DAY), tau_expiry=kw.pop("tau_expiry", BASE_US + 30 * DAY),
                            unix_ms=BASE_MS - 86_400_000, **kw)


def fam(fid, *members, manifest=True, **mkw):
    f = {"family_id": fid, "members": list(members)}
    if manifest:
        f["manifest"] = manifest_for(f, **mkw)
    return f


def inject(f, *members):
    """Append members AFTER the manifest was issued (they are not listed)."""
    g = copy.deepcopy(f)
    g["members"] += list(members)
    return g


def contra(eid, parent, producer="org:internal-kyc-service", conflict="BENEFICIARY_NAME_MISMATCH",
           claim="beneficiary name on file differs from payment instruction", binding=None, **extra):
    return ev(eid, 0.9, producer, parent=parent, state="CONTRADICTORY", conflict_type=conflict,
              contradicts=binding or BIND_WIRE, claim=claim, **extra)


def three(correlated=False):
    out = []
    for f in V.three(correlated):
        out.append(fam(f["family_id"], *f["members"]))
    return out


def four():
    return three() + [fam("F-registry", attest(ev("ev-registry", 0.9, "org:gov-registry"), ["SOURCE:reg"]))]


def with_member(families, fid, member, listed=True):
    out = []
    for f in families:
        if f["family_id"] != fid:
            out.append(f)
            continue
        base = {"family_id": fid, "members": f["members"] + [member]}
        out.append(fam(fid, *base["members"]) if listed else inject(f, member))
    return out


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def cases():
    C = []

    def add(cid, title, request, families, expect, checks=None, note=None, trust=TS, **extra):
        C.append(dict(id=cid, title=title, request=request, families=families, expect=expect,
                      checks=checks or {}, note=note, trust=trust, **extra))

    add("c01_three_independent_pass", "Wire: three independent attested confirmations with manifests", WIRE, three(), "ALLOW")
    add("c02_three_correlated_fail", "Wire: same confirmations, one shared upstream feed", WIRE, three(True), "DENY")
    add("c03_two_independent_insufficient", "Wire: two independent confirmations", WIRE,
        [f for f in three() if f["family_id"] != "F-vendor-b"], "DENY")

    # --- A-1 adverse disposition -----------------------------------------------------------------
    base = four()
    add("a00_four_independent_pass", "Wire: four independent confirmations (baseline)", WIRE, base, "ALLOW",
        {"disposition": "CLEAR"})
    add("a01_admitted_contradiction_defeats", "Auditor-attested relevant contradiction -> DEFEAT", WIRE,
        with_member(base, "F-webhook", attest(contra("ev-contra", "ev-internal-webhook"), ["SOURCE:internal-kyc"])),
        "DENY", {"disposition": "DEFEAT", "same_MC_as": "a00_four_independent_pass"})
    add("a02_unattested_contradiction_contains", "Unattested relevant contradiction -> CONTAIN -> MANUAL_REQUIRED",
        WIRE, with_member(base, "F-webhook", contra("ev-contra", "ev-internal-webhook")), "MANUAL_REQUIRED",
        {"disposition": "CONTAIN", "same_MC_as": "a00_four_independent_pass", "obligations": 1},
        note="The contradiction changes neither M, C nor T; it removes eligibility for automatic authorization.")
    add("a03_inadmissible_contradiction_contains", "Self-attested (inadmissible) contradiction -> CONTAIN", WIRE,
        with_member(base, "F-webhook", attest(contra("ev-contra", "ev-internal-webhook", producer=TF.VENDOR_A),
                                              ["SOURCE:vendor-a-registry"], key=TF.K_VENDOR_A, attester=TF.VENDOR_A)),
        "MANUAL_REQUIRED", {"disposition": "CONTAIN", "same_MC_as": "a00_four_independent_pass"})
    bad = attest(contra("ev-contra", "ev-internal-webhook"), ["SOURCE:internal-kyc"])
    bad["provenance"]["signature"] = "00" * 64
    add("a04_tampered_contradiction_locks", "Listed contradiction with a forged attestation -> LOCK", WIRE,
        with_member(base, "F-webhook", bad), "DENY", {"disposition": "LOCK", "reasons_include": ["SAFE_STATE_LOCK"]})
    two = [f for f in three() if f["family_id"] != "F-vendor-b"]
    add("a05_contain_below_manual_threshold", "CONTAIN but C < T_manual -> DENY", WIRE,
        with_member(two, "F-webhook", contra("ev-contra", "ev-internal-webhook")), "DENY",
        {"disposition": "CONTAIN", "reasons_include": ["ADVERSE_CONTAINMENT", "THRESHOLD_NOT_MET"]})
    dup2 = with_member(with_member(base, "F-webhook", contra("ev-contra", "ev-internal-webhook")),
                       "F-vendor-b", contra("ev-contra-b", "ev-vendor-b", producer="org:vendor-b"))
    add("a06_same_claim_two_families_one_obligation", "The same adverse claim in two families is one obligation",
        WIRE, dup2, "MANUAL_REQUIRED", {"obligations": 1, "occurrences": 2})
    many = base[:2] + [fam("F-webhook", base[2]["members"][0],
                           *[contra(f"ev-contra-{i:02d}", "ev-internal-webhook") for i in range(20)])] + base[3:]
    add("a07_twenty_identical_claims_one_obligation", "Twenty identical submissions create one review obligation",
        WIRE, many, "MANUAL_REQUIRED", {"obligations": 1, "occurrences": 20,
                                        "same_containment_as": "a02_unattested_contradiction_contains"})
    add("a08_contradiction_other_target_irrelevant", "Contradiction bound to a different target has no effect", WIRE,
        with_member(base, "F-webhook", contra("ev-contra", "ev-internal-webhook", binding=dict(BIND_WIRE, target="acct-1"))),
        "ALLOW", {"disposition": "CLEAR", "same_MC_as": "a00_four_independent_pass"})
    add("a09_unrecognised_conflict_type_irrelevant", "Unrecognised conflict_type has no effect", WIRE,
        with_member(base, "F-webhook", contra("ev-contra", "ev-internal-webhook", conflict="VIBES")), "ALLOW",
        {"disposition": "CLEAR"})
    root_contra = fam("F-tip", contra("ev-tip", None, producer="org:tipline"))
    add("a10_contradicting_root", "A family whose root is an unattested contradiction: no support, CONTAIN", WIRE,
        base + [root_contra], "MANUAL_REQUIRED", {"disposition": "CONTAIN", "same_MC_as": "a00_four_independent_pass"})
    both = with_member(with_member(base, "F-webhook", contra("ev-contra", "ev-internal-webhook")),
                       "F-registry", attest(contra("ev-contra-r", "ev-registry", producer="org:gov-registry",
                                                   conflict="SANCTIONS_HIT", claim="beneficiary on sanctions list"),
                                            ["SOURCE:reg"]))
    add("a11_defeat_outranks_contain", "DEFEAT and CONTAIN together: DEFEAT wins", WIRE, both, "DENY",
        {"disposition": "DEFEAT", "obligations": 2})
    add("a12_contradiction_no_longer_zeroes_family", "Three independent + unattested contradiction: M unchanged (was zeroed in 0.2.x)",
        WIRE, with_member(three(), "F-webhook", contra("ev-contra", "ev-internal-webhook")), "MANUAL_REQUIRED",
        {"same_MC_as": "c01_three_independent_pass"},
        note="coverage-v0.2.1-alpha set A(F-webhook) = 0 for this input (M 2.77 -> 1.85, DENY).")

    # --- M-1 family membership -------------------------------------------------------------------
    ind = three()
    forged = ev("ev-forged", 1.0, "org:attacker", parent="ev-vendor-a", state="INVALID")
    add("m01_injected_invalid_member_quarantined", "Injected INVALID member cannot invalidate vendor A's family", WIRE,
        [inject(ind[0], forged)] + ind[1:], "ALLOW", {"same_MC_as": "c01_three_independent_pass", "quarantined": 1},
        note="In 0.2.x any INVALID member invalidated its family: a one-item denial of service.")
    add("m02_injected_second_root_quarantined", "Injected second root cannot make the family malformed", WIRE,
        [inject(ind[0], ev("ev-rogue-root", 0.99, "org:attacker"))] + ind[1:], "ALLOW",
        {"same_MC_as": "c01_three_independent_pass"})
    add("m03_injected_unattested_contradiction", "Injected unattested contradiction: no containment", WIRE,
        [inject(ind[0], contra("ev-inj", "ev-vendor-a", producer="org:attacker"))] + ind[1:], "ALLOW",
        {"disposition": "CLEAR"})
    add("m04_injected_attested_contradiction", "Injected contradiction with a valid auditor attestation: still quarantined",
        WIRE, [inject(ind[0], attest(contra("ev-inj", "ev-vendor-a", producer="org:attacker"), ["SOURCE:reg"]))] + ind[1:],
        "ALLOW", {"disposition": "CLEAR"},
        note="Adverse evidence must enter through a membership authority; a valid attestation alone does not place it in a family.")
    badinj = attest(contra("ev-inj", "ev-vendor-a", producer="org:attacker"), ["SOURCE:reg"])
    badinj["provenance"]["signature"] = "11" * 64
    add("m05_injected_tampered_contradiction", "Injected forged contradiction cannot trigger LOCK", WIRE,
        [inject(ind[0], badinj)] + ind[1:], "ALLOW", {"disposition": "CLEAR"})
    impostor = ev("ev-vendor-a", 0.10, "org:attacker")
    add("m06_same_id_impostor", "Impostor reusing a listed evidence_id is quarantined; the listed item is used", WIRE,
        [{"family_id": ind[0]["family_id"], "members": [impostor] + ind[0]["members"], "manifest": ind[0]["manifest"]}]
        + ind[1:], "ALLOW", {"same_MC_as": "c01_three_independent_pass"})
    add("m07_no_manifest", "Family without a manifest is excluded", WIRE,
        [fam(ind[0]["family_id"], *ind[0]["members"], manifest=False)] + ind[1:], "DENY",
        {"family_status": ("F-vendor-a", "MEMBERSHIP_UNVERIFIED")})
    add("m08_manifest_out_of_scope", "Partner gateway's scope (F-partner-*) does not cover F-vendor-a", WIRE,
        [fam(ind[0]["family_id"], *ind[0]["members"], key=TF.K_MEMB_PARTNER, authority=TF.PARTNER)] + ind[1:], "DENY",
        {"family_status": ("F-vendor-a", "MEMBERSHIP_UNVERIFIED")})
    add("m09_manifest_unregistered_key", "Manifest from a key not in the trust state", WIRE,
        [fam(ind[0]["family_id"], *ind[0]["members"], key=TF.K_MEMB_UNREG, authority="org:unknown")] + ind[1:], "DENY",
        {"family_status": ("F-vendor-a", "MEMBERSHIP_UNVERIFIED")})
    add("m10_manifest_wrong_key_domain", "Manifest signed with a provenance-domain key", WIRE,
        [fam(ind[0]["family_id"], *ind[0]["members"], key=TF.K_AUD, authority=TF.AUD)] + ind[1:], "DENY",
        {"family_status": ("F-vendor-a", "INVALIDATED"), "reasons_include": ["MEMBERSHIP_TAMPERED"]})
    replay = dict(ind[0], family_id="F-vendor-a-copy")
    add("m11_manifest_replayed_onto_other_family", "Vendor A's manifest attached to a different family id", WIRE,
        [replay] + ind[1:], "DENY", {"family_status": ("F-vendor-a-copy", "INVALIDATED")})
    altered = copy.deepcopy(ind[0])
    altered["members"][0]["value_bits"] = bits(1.0)
    add("m12_listed_member_altered", "Listed member edited after the manifest was issued", WIRE,
        [altered] + ind[1:], "DENY", {"family_status": ("F-vendor-a", "INVALIDATED"), "reasons_include": ["MEMBERSHIP_TAMPERED"]})
    listed_c = with_member(base, "F-webhook", contra("ev-contra", "ev-internal-webhook"))
    withheld = [dict(f, members=[m for m in f["members"] if m["evidence_id"] != "ev-contra"]) if f["family_id"] == "F-webhook" else f
                for f in listed_c]
    add("m13_listed_contradiction_withheld", "Submitter drops a listed contradiction to avoid containment", WIRE,
        withheld, "ALLOW", {"family_status": ("F-webhook", "MEMBERSHIP_UNVERIFIED"), "disposition": "CLEAR"},
        note="The family is excluded rather than silently cleared; four families minus one still pass here, "
             "so withholding costs the submitter that family's support and gains nothing.")
    add("m14_manifest_expired", "Expired manifest", WIRE,
        [fam(ind[0]["family_id"], *ind[0]["members"], tau_expiry=BASE_US - 1)] + ind[1:], "DENY",
        {"family_status": ("F-vendor-a", "MEMBERSHIP_UNVERIFIED")})
    add("m15_manifest_revoked", "Revoked manifest", WIRE, ind, "DENY",
        {"family_status": ("F-vendor-a", "MEMBERSHIP_UNVERIFIED")},
        trust=dict(TS, revoked_manifest_ids=[ind[0]["manifest"]["payload"]["manifest_id"]]))

    # --- P-1 carried over under M-1 ------------------------------------------------------------------
    cor = three(True)
    pad = fam("F-pad", ev("ev-pad", 0.95, "org:pad", self_declared=V.SHARED + [f"COLLECTOR:fab-{k:03d}" for k in range(200)]))
    add("x01_self_declared_padding", "Listed but self-declared padded lineage is ignored", WIRE, cor + [pad], "DENY",
        {"same_MC_as": "c02_three_correlated_fail"})
    lifted = ev("ev-lift", 0.95, "org:pad")
    lifted["provenance"] = copy.deepcopy(ind[0]["members"][0]["provenance"])
    add("x05_attestation_lifted", "Valid attestation copied onto other listed evidence", WIRE, cor + [fam("F-lift", lifted)],
        "DENY", {"same_MC_as": "c02_three_correlated_fail", "reasons_include": ["PROVENANCE_TAMPERED"]})
    alias = [fam(f["family_id"], *f["members"]) for f in V.three(False, partial=True, aliased_b=True)]
    add("x07_alias_resolves_correlation", "Aliased shared feed is resolved through the trust state's alias table",
        WIRE, alias, "DENY")

    # --- boundaries and the total-function boundary -------------------------------------------------
    eqb, belowb = boundary_values()
    add("b01_c_equals_t", "C == T exactly must ALLOW", REFUND, [solo(eqb)], "ALLOW", {"C_equals_T": True})
    add("b02_one_ulp_below", "C one ulp below T must DENY", REFUND, [solo(belowb)], "DENY", {"C_ulps_below_T": 1})
    add("e01_engine_guard_nan", "Engine guard still runs first (NaN value)", WIRE,
        [fam("F1", ev("ev-1", "7ff8000000000000", "org:x"))], "DENY", {"stage": "ENGINE_GUARD"})
    add("f01_malformed_family_is_structured", "A family without family_id is excluded and audited, not an exception",
        WIRE, ind + [{"members": []}], "ALLOW", {"stage": "PROFILE", "reasons_include": ["LINEAGE_CLASS_MALFORMED"]})
    add("f02_malformed_member_quarantined", "A member with junk value_bits is quarantined, not an exception", WIRE,
        [inject(ind[0], {"evidence_id": "ev-junk", "parent_id": "ev-vendor-a", "producer": "org:x", "value_bits": [1, 2]})]
        + ind[1:], "ALLOW", {"same_MC_as": "c01_three_independent_pass"})
    return C


def solo(vb):
    return fam("F-solo", attest(ev("ev-solo", vb, "org:solo"), ["SOURCE:solo"]))


def boundary_values():
    def one(vb):
        return ENG.evaluate(REFUND, [solo(vb)], PROFILE, TS)
    T = S.f(one(bits(0.5))["T_bits"])
    lob, hib = R.bits_of(0.0), R.bits_of(1.0)
    while hib - lob > 1:
        mid = (lob + hib) // 2
        if S.f(one(f"{mid:016x}")["C_bits"]) >= T:
            hib = mid
        else:
            lob = mid
    target = struct.unpack(">d", struct.pack(">Q", R.bits_of(T) - 1))[0]
    b = hib
    while S.f(one(f"{b:016x}")["C_bits"]) > target:
        b -= 1
    if S.f(one(f"{hib:016x}")["C_bits"]) != T or S.f(one(f"{b:016x}")["C_bits"]) != target:
        raise SystemExit("v0.3.0 boundary search failed")
    return f"{hib:016x}", f"{b:016x}"


# ---------------------------------------------------------------------------
# Random generators (shared with property tests)
# ---------------------------------------------------------------------------

def random_family(rng, fid, attested_p=8):
    f = V.random_attested_family(rng, fid)
    return fam(fid, *f["members"])


def random_contradiction(rng, parent, eid, attested):
    c = contra(eid, parent, producer=f"org:{eid}", conflict=rng.pick(TS["conflict_types"]),
               claim=f"claim-{rng.below(4)}")
    return attest(c, [rng.pick(V.POOL)]) if attested else c


def witnesses(n=18):
    rng = CC.DRng("v030-witness")
    kinds = ["monotone", "contain", "inject"]
    out = []
    for i in range(n):
        kind = kinds[i % 3]
        basef = [random_family(rng, f"F-W{i}-{k}") for k in range(2 + rng.below(4))]
        rq = rng.pick([ANNOTATE, ANNOTATE, REFUND, WIRE])
        if kind == "monotone":
            after = basef + [random_family(rng, f"F-W{i}-new")]
        elif kind == "contain":
            tgt = basef[0]
            root_id = tgt["members"][0]["evidence_id"]
            b = dict(BIND_WIRE, **{k: rq[k] for k in ("action", "assertion", "target", "evidence_snapshot_id")})
            c = contra(f"ev-W{i}-c", root_id, producer=f"org:W{i}c", binding=b)
            after = [fam(tgt["family_id"], *tgt["members"], c)] + basef[1:]
        else:
            tgt = basef[0]
            after = [inject(tgt, ev(f"ev-W{i}-inj", 1.0, "org:attacker", parent=tgt["members"][0]["evidence_id"],
                                    state=rng.pick(["INVALID", "CONTRADICTORY"])))] + basef[1:]
        t0 = ENG.evaluate(rq, basef, PROFILE, TS)
        t1 = ENG.evaluate(rq, after, PROFILE, TS)
        ok = {"monotone": S.f(t1["M_bits"]) >= S.f(t0["M_bits"]) and not (t0["decision"] == "ALLOW" and t1["decision"] == "DENY"),
              "contain": (t1["M_bits"], t1["C_bits"]) == (t0["M_bits"], t0["C_bits"]) and t1["decision"] != "ALLOW",
              "inject": (t1["M_bits"], t1["C_bits"], t1["decision"]) == (t0["M_bits"], t0["C_bits"], t0["decision"])}[kind]
        if not ok:
            raise SystemExit(f"v0.3.0 witness {i} ({kind}) violated: {t0['decision']} -> {t1['decision']}")
        out.append({"kind": kind, "request": rq, "base": basef, "after": after,
                    "M_base_bits": t0["M_bits"], "M_after_bits": t1["M_bits"],
                    "C_base_bits": t0["C_bits"], "C_after_bits": t1["C_bits"],
                    "decision_base": t0["decision"], "decision_after": t1["decision"]})
    return out


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build():
    out, by_id = [], {}
    for c in cases():
        tr = ENG.evaluate(c["request"], c["families"], PROFILE, c["trust"])
        cid, ck = c["id"], c["checks"]
        fail = lambda m: SystemExit(f"v0.3.0 {cid}: {m}")  # noqa: E731
        if tr["decision"] != c["expect"]:
            raise fail(f"engine says {tr['decision']} {tr['reason_codes']}, declared {c['expect']}")
        if "stage" in ck and tr["stage"] != ck["stage"]:
            raise fail(f"stage {tr['stage']}")
        if "disposition" in ck and tr.get("adverse_disposition") != ck["disposition"]:
            raise fail(f"disposition {tr.get('adverse_disposition')}")
        if "same_MC_as" in ck:
            o = by_id[ck["same_MC_as"]]
            if (tr["M_bits"], tr["C_bits"]) != (o["M_bits"], o["C_bits"]):
                raise fail(f"M/C differ from {ck['same_MC_as']}: {S.f(tr['M_bits'])} vs {S.f(o['M_bits'])}")
        if "same_containment_as" in ck and tr["containment_digest"] != by_id[ck["same_containment_as"]]["containment_digest"]:
            raise fail("containment digest differs")
        if "obligations" in ck and len(tr["adverse_obligations"]) != ck["obligations"]:
            raise fail(f"obligations {len(tr['adverse_obligations'])}")
        if "occurrences" in ck and sum(len(o["occurrences"]) for o in tr["adverse_obligations"]) != ck["occurrences"]:
            raise fail("occurrences")
        if "quarantined" in ck and sum(e["event"] == "MEMBER_QUARANTINED" for e in tr["audit_events"]) != ck["quarantined"]:
            raise fail("quarantine count")
        if "family_status" in ck:
            fid, st = ck["family_status"]
            if tr["families"][fid]["status"] != st:
                raise fail(f"family {fid} status {tr['families'][fid]['status']}")
        for rsn in ck.get("reasons_include", []):
            if rsn not in tr["reason_codes"]:
                raise fail(f"missing reason {rsn}")
        if ck.get("C_equals_T") and tr["C_bits"] != tr["T_bits"]:
            raise fail("C != T")
        if "C_ulps_below_T" in ck and int(tr["T_bits"], 16) - int(tr["C_bits"], 16) != ck["C_ulps_below_T"]:
            raise fail("ulp")
        by_id[cid] = tr
        v = {"id": cid, "title": c["title"], "input": {"request": c["request"], "families": c["families"]},
             "expected_trace": tr,
             "summary": {"decision": tr["decision"], "disposition": tr.get("adverse_disposition"), "stage": tr["stage"],
                         "M": repr(S.f(tr["M_bits"])), "C": repr(S.f(tr["C_bits"])), "reasons": tr["reason_codes"]}}
        if c["trust"] is not TS:
            v["trust_state"] = c["trust"]
        if c.get("note"):
            v["note"] = c["note"]
        out.append(v)
    return {
        "vector_set": "scoring-profile",
        "scoring_profile": PROFILE["id"],
        "status": "EXPERIMENTAL — reference candidate; supersedes coverage-v0.2.1-alpha",
        "spec_version": R.SPEC_VERSION,
        "assumptions": "docs/SCORING_PROFILE_coverage-v0.3.0-alpha.md",
        "WARNING": "Test keys are derived from public seeds. Never use them outside conformance testing.",
        "scoring_profile_declaration": PROFILE, "scoring_profile_hash": TF.SCORING_PROFILE_HASH,
        "trust_state": TS, "trust_state_hash": TF.TRUST_STATE_HASH,
        "exploit_statement": "No known open exploit UNDER the declared trust state, atom registry and alias authority, "
                             "family-membership authorities, clock authorities and calibration. Each of those is an "
                             "assumption, not a result (see spec §5 and docs/CONFORMANCE_ASSUMPTIONS.md Q-1..Q-6).",
        "property_witnesses": witnesses(),
        "cases": out,
    }
