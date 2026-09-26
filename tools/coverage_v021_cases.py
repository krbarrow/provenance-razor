"""
Vectors for scoring profile `coverage-v0.2.1-alpha` (EXPERIMENTAL): P-1 verified provenance,
authenticated-contradiction defeaters, and the atom-padding exploit family as MUST-DENY cases.

Imported by tools/generate_vectors.py. Every case declares its intended decision and the
invariant it demonstrates; build() aborts if the reference engine disagrees.
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
import prc_coverage_v021 as C21  # noqa: E402
import prc_engine as ENG         # noqa: E402
import scoring_cases as J        # noqa: E402
import coverage_cases as CC      # noqa: E402

bits = J.bits
WIRE_R, REFUND_R, ANNOTATE_R = J.WIRE, J.REFUND, J.ANNOTATE
BASE_MS = 1767225600000
BASE_US = BASE_MS * 1000
DAY = 86_400_000_000
EPOCH = "epoch-2026-01"


def req(r):
    return dict(r, tau_eval=BASE_US)


WIRE, REFUND, ANNOTATE = req(WIRE_R), req(REFUND_R), req(ANNOTATE_R)

# ---------------------------------------------------------------------------
# Keys and trust state (test keys only — seeds are public)
# ---------------------------------------------------------------------------
K_AUD = R.TestKey.derive("provenance", "auditor-1")            # independent lineage auditor, all types
K_AUD_SRC = R.TestKey.derive("provenance", "auditor-src-only")  # authorised for SOURCE atoms only
K_VENDOR_A = R.TestKey.derive("provenance", "vendor-a-self")    # vendor A attesting its own evidence
K_UNREG = R.TestKey.derive("provenance", "not-registered")      # valid key, not in the registry
K_DECISION = R.TestKey.derive("decision", "k1")                 # a decision-domain key (misuse)
AUD, AUD_SRC, VENDOR_A = "org:lineage-auditor-1", "org:source-registry", "org:vendor-a"


def prov_entry(key, attester, types):
    return {"domain": "provenance", "public_key": key.public_hex, "epochs": [EPOCH],
            "attester_id": attester, "authorized_atom_types": sorted(types)}


TRUST = {
    "registry": {
        K_AUD.key_id: prov_entry(K_AUD, AUD, S.DEPENDENCY_TYPES),
        K_AUD_SRC.key_id: prov_entry(K_AUD_SRC, AUD_SRC, ["SOURCE"]),
        K_VENDOR_A.key_id: prov_entry(K_VENDOR_A, VENDOR_A, S.DEPENDENCY_TYPES),
        K_DECISION.key_id: {"domain": "decision", "public_key": K_DECISION.public_hex, "epochs": [EPOCH]},
    },
    "revoked_attestation_ids": [],
}

SHARED = J.SHARED_FEED
NONMAT = J.COMMON_NONMATERIAL
VA = ["SOURCE:vendor-a-registry", "DATABASE:vendor-a-db", "API_ENDPOINT:vendor-a/verify-v2"]
VB = ["SOURCE:vendor-b-bureau", "DATABASE:vendor-b-db", "API_ENDPOINT:vendor-b/confirm"]
VW = ["SOURCE:internal-kyc", "DATABASE:beneficiary-master", "API_ENDPOINT:internal/webhook-beneficiary"]
ALIASES = {"SOURCE:fcp-1": "SOURCE:feed-core-primary", "DATABASE:agg-master-db": "DATABASE:aggregator-master",
           "COLLECTOR:agg17": "COLLECTOR:aggregator-17", "RUNTIME:agg-rt": "RUNTIME:aggregator-rt"}
EXTRA = ["SOURCE:s1", "SOURCE:s2", "SOURCE:solo", "SOURCE:memo", "RUNTIME:m", "COLLECTOR:c-2", "COLLECTOR:c-3",
         "SOURCE:a", "SOURCE:b", "SOURCE:c", "SOURCE:reg"]
REGISTERED = sorted(set(SHARED + NONMAT + VA + VB + VW + EXTRA + CC.ATOM_POOL + [
    "API_ENDPOINT:vendor-a/verify-v2", "API_ENDPOINT:vendor-b/confirm", "API_ENDPOINT:internal/webhook-beneficiary"]),
    key=lambda s: s.encode("utf-8"))

PROFILE = {
    "id": C21.PROFILE_ID,
    "status": "experimental",
    **C21.COMPONENTS,
    "material_dependency_types": J.PROFILE["material_dependency_types"],
    "omega_bits": bits(1.0), "t_base_bits": bits(0.5), "beta_bits": bits(0.2156),
    "kappa_unknown_bits": bits(0.5), "kappa_degraded_bits": bits(0.5), "unknown_gate_t_bits": bits(0.92),
    "consequence_gamma_bits": J.PROFILE["consequence_gamma_bits"],
    "atom_registry": {"mode": "closed", "atoms": REGISTERED, "aliases": ALIASES},
    "max_atoms_per_type": {"API_ENDPOINT": 1, "CLOCK": 1, "COLLECTOR": 2, "DATABASE": 2, "NETWORK_AS": 1,
                           "RUNTIME": 2, "SOURCE": 2, "TRUST_ROOT": 1},
    "attester_independence_required": True,
}
# A naive registry: the alias names are registered as atoms in their own right (no naming authority).
PROFILE_NO_ALIASES = dict(PROFILE, atom_registry={"mode": "closed", "aliases": {},
                                                  "atoms": sorted(set(REGISTERED) | set(ALIASES),
                                                                  key=lambda s: s.encode("utf-8"))})


def attest(member, deps, key=K_AUD, attester=AUD, label=None, **kw):
    m = dict(member)
    m["provenance"] = PV.make_attestation(
        m, key, attester, deps, epoch=kw.pop("epoch", EPOCH),
        tau_issued=kw.pop("tau_issued", BASE_US - DAY), tau_expiry=kw.pop("tau_expiry", BASE_US + 30 * DAY),
        unix_ms=BASE_MS - 86_400_000,
        label=label or f"{m['evidence_id']}|{key.label}|{R.H(sorted(set(deps)))[:12]}", **kw)
    return m


def ev(eid, value, producer, parent=None, state=None, self_declared=None, **extra):
    e = {"evidence_id": eid, "parent_id": parent, "producer": producer,
         "value_bits": bits(value) if isinstance(value, float) else value}
    if state:
        e["state"] = state
    if self_declared is not None:
        e["dependencies"] = list(self_declared)
    e.update(extra)
    return e


fam = J.fam


def three(correlated: bool, partial=False, aliased_b=False):
    da = SHARED + ["API_ENDPOINT:vendor-a/verify-v2"] if (correlated or partial) else VA
    db = SHARED + ["API_ENDPOINT:vendor-b/confirm"] if (correlated or partial) else VB
    if aliased_b:
        db = [{v: k for k, v in ALIASES.items()}.get(a, a) for a in SHARED] + ["API_ENDPOINT:vendor-b/confirm"]
    dw = SHARED + ["API_ENDPOINT:internal/webhook-beneficiary"] if correlated else VW
    return [
        fam("F-vendor-a", attest(ev("ev-vendor-a", 0.95, VENDOR_A, attestation="sig:vendor-a:88192"), da + NONMAT)),
        fam("F-vendor-b", attest(ev("ev-vendor-b", 0.90, "org:vendor-b", attestation="sig:vendor-b:55120"), db + NONMAT)),
        fam("F-webhook", attest(ev("ev-internal-webhook", 0.92, "org:internal-kyc-service",
                                   attestation="sig:internal:30017"), dw + NONMAT)),
    ]


def reattest_rename(f_, new_fid):
    """Structural duplicate under fresh ids, each member re-attested by the same attester."""
    ids = {m["evidence_id"]: f"{m['evidence_id']}@{new_fid}" for m in f_["members"]}
    out = []
    for m in f_["members"]:
        n = {k: copy.deepcopy(v) for k, v in m.items() if k != "provenance"}
        n["evidence_id"] = ids[m["evidence_id"]]
        if n.get("parent_id") in ids:
            n["parent_id"] = ids[n["parent_id"]]
        if "provenance" in m:
            pl = m["provenance"]["payload"]
            key = {K_AUD.key_id: K_AUD, K_AUD_SRC.key_id: K_AUD_SRC, K_VENDOR_A.key_id: K_VENDOR_A}[pl["provenance_key_id"]]
            n = attest(n, pl["dependencies"], key=key, attester=pl["attester_id"])
        out.append(n)
    return {"family_id": new_fid, "members": out}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def cases():
    C = []

    def add(cid, title, request, families, expect, checks=None, note=None, profile=PROFILE, trust=TRUST, **extra):
        C.append(dict(id=cid, title=title, request=request, families=families, expect=expect,
                      checks=checks or {}, note=note, profile=profile, trust=trust, **extra))

    ind, cor = three(False), three(True)
    # --- headline, now over attested lineage ---------------------------------------------------
    add("c03_three_independent_pass", "Wire: three independent confirmations, lineage attested by an auditor",
        WIRE, ind, "ALLOW")
    add("c04_three_correlated_fail", "Wire: same confirmations, attested lineage shows one shared feed", WIRE,
        cor, "DENY")
    add("c05_two_of_three_correlated", "Wire: vendors A and B share the feed (attested)", WIRE, three(False, partial=True), "DENY")
    add("c06_two_independent_insufficient", "Wire: two independent attested confirmations", WIRE,
        [x for x in ind if x["family_id"] != "F-vendor-b"], "DENY")
    add("c07_mirror_added_neutral", "Attested mirror of vendor A adds nothing", WIRE,
        ind + [fam("F-mirror", attest(ev("ev-vendor-a-mirror", 0.90, "org:vendor-a-mirror"), VA))], "ALLOW",
        {"same_M_as": "c03_three_independent_pass"})
    add("c08_bridge_added_neutral", "Attested bridging item cannot merge or dilute", WIRE,
        ind + [fam("F-bridge", attest(ev("ev-bridge", 0.10, "org:bridge"),
                                       ["SOURCE:vendor-a-registry", "SOURCE:vendor-b-bureau"]))], "ALLOW",
        {"same_M_as": "c03_three_independent_pass"})
    dup = ind + [reattest_rename(ind[0], "F-vendor-a-dup")]
    add("c09_reattested_duplicate_idempotent", "Re-attested structural duplicate leaves M bit-identical", WIRE,
        dup, "ALLOW", {"same_M_as": "c03_three_independent_pass"})
    base10 = [fam("F1", attest(ev("ev-1", 0.6, "org:p1"), ["SOURCE:s1"]))]
    add("c10a_refund_attested_only", "Refund: one attested family", REFUND, base10, "DENY", {"M": 0.6})
    add("c10b_unattested_low_consequence", "Refund (T < gate): an unattested item contributes V·κ once", REFUND,
        base10 + [fam("F-u", ev("ev-u", 0.9, "org:u"))], "ALLOW", {"M": 1.05})
    add("c11_unattested_spam_single_sink", "Twenty unattested items share one UNKNOWN sink", REFUND,
        base10 + [fam(f"F-u{i}", ev(f"ev-u{i}", 0.9, f"org:u{i}")) for i in range(20)], "ALLOW",
        {"same_M_as": "c10b_unattested_low_consequence"})
    perm_base = cor + [fam("F-memo", attest(ev("ev-memo-root", 0.7, "org:memo"), ["SOURCE:memo"]),
                           attest(ev("ev-memo-derived", 0.7, "org:memo", parent="ev-memo-root", state="DEGRADED"),
                                  ["RUNTIME:m", "SOURCE:memo"]))]
    perm = copy.deepcopy(perm_base)
    rng = CC.DRng("v021-perm")
    for i in range(len(perm) - 1, 0, -1):
        j = rng.below(i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    for f_ in perm:
        f_["members"].reverse()
    add("c12_permutation_invariance", "Shuffled families and members: identical output bits", WIRE, perm, "DENY",
        {"same_trace_as": perm_base})
    eqb, belowb = boundary_values()
    add("c13_boundary_c_equals_t", "C == T exactly must ALLOW", REFUND,
        [fam("F-solo", attest(ev("ev-solo", eqb, "org:solo"), ["SOURCE:solo"]))], "ALLOW", {"C_equals_T": True})
    add("c14_boundary_one_ulp_below", "C one ulp below T must DENY", REFUND,
        [fam("F-solo", attest(ev("ev-solo", belowb, "org:solo"), ["SOURCE:solo"]))], "DENY", {"C_ulps_below_T": 1})
    add("e01_engine_guard_nan", "Engine guard still runs first (NaN value)", WIRE,
        [fam("F1", ev("ev-1", "7ff8000000000000", "org:x"))], "DENY", {"stage": "ENGINE_GUARD"})

    # --- the atom-padding family: all MUST DENY / be neutral ---------------------------------
    pads = [fam(f"F-pad-{i}", ev(f"ev-pad-{i}", 0.95, f"org:pad-{i}",
                                 self_declared=SHARED + ["API_ENDPOINT:vendor-a/verify-v2"] +
                                 [f"COLLECTOR:fabricated-{i}-{k:03d}" for k in range(200)])) for i in (1, 2)]
    add("x01_self_declared_padding", "x01 (was the open exploit): self-declared padded lineage is ignored", WIRE,
        cor + pads, "DENY", {"same_M_as": "c04_three_correlated_fail", "outcome": ("F-pad-1", "ev-pad-1", "UNATTESTED")},
        note="Under coverage-v0.2.0-alpha this input produced ALLOW (C = 0.958). P-1 maps it to UNKNOWN:*; κ = 0 on a wire.")
    fab = [f"COLLECTOR:fabricated-{k:03d}" for k in range(200)]
    add("x02_signed_padding_unregistered", "Auditor-signed attestation containing fabricated atoms", WIRE,
        cor + [fam("F-pad", attest(ev("ev-pad", 0.95, "org:pad"), SHARED + fab))], "DENY",
        {"same_M_as": "c04_three_correlated_fail", "outcome": ("F-pad", "ev-pad", "INADMISSIBLE")},
        note="The closed atom registry rejects atoms no naming authority has registered.")
    add("x03_signed_padding_cap", "Auditor-signed attestation with registered atoms above the per-type cap", WIRE,
        cor + [fam("F-pad", attest(ev("ev-pad", 0.95, "org:pad"),
                                    SHARED + ["COLLECTOR:c-2", "COLLECTOR:c-3", "API_ENDPOINT:vendor-a/verify-v2"]))],
        "DENY", {"same_M_as": "c04_three_correlated_fail", "outcome": ("F-pad", "ev-pad", "INADMISSIBLE")})
    add("x04_self_attested", "Vendor A attests its own evidence's lineage (attester = producer)", WIRE,
        [fam("F-vendor-a", attest(ev("ev-vendor-a", 0.95, VENDOR_A), VA, key=K_VENDOR_A, attester=VENDOR_A))] + ind[1:],
        "DENY", {"outcome": ("F-vendor-a", "ev-vendor-a", "INADMISSIBLE")},
        note="Signed self-declaration is accountable but not verification; with κ = 0 vendor A contributes nothing.")
    lifted = attest(ev("ev-vendor-a", 0.95, VENDOR_A, attestation="sig:vendor-a:88192"), VA + NONMAT)["provenance"]
    padded = ev("ev-pad", 0.95, "org:pad")
    padded["provenance"] = copy.deepcopy(lifted)
    add("x05_attestation_lifted", "Vendor A's valid attestation copied onto another evidence item", WIRE,
        cor + [fam("F-pad", padded)], "DENY",
        {"same_M_as": "c04_three_correlated_fail", "outcome": ("F-pad", "ev-pad", "TAMPERED"),
         "reasons_include": ["PROVENANCE_TAMPERED", "FAMILY_INVALIDATED"]})
    add("x06_decision_key_misuse", "Attestation signed with a decision-domain key", WIRE,
        cor + [fam("F-pad", attest(ev("ev-pad", 0.95, "org:pad"), VA, key=K_DECISION, attester=AUD))], "DENY",
        {"same_M_as": "c04_three_correlated_fail", "outcome": ("F-pad", "ev-pad", "TAMPERED")})
    add("x07_alias_resolves_correlation", "Vendor B names the shared feed by aliases; the alias table resolves them",
        WIRE, three(False, partial=True, aliased_b=True), "DENY", {"same_M_as": "c05_two_of_three_correlated"})
    add("x08_alias_table_absent", "Same input with a registry that has no naming authority: correlation hidden",
        WIRE, three(False, partial=True, aliased_b=True), "ALLOW", profile=PROFILE_NO_ALIASES,
        note="Why canonical atom identity matters: without the alias table the shared feed looks like two sources "
             "and the wire is ALLOWED. The vector is kept to pin the risk, not as acceptable behaviour.")
    add("x09_expired_attestation", "Attestation expired before tau_eval", WIRE,
        [fam("F-vendor-a", attest(ev("ev-vendor-a", 0.95, VENDOR_A), VA, tau_expiry=BASE_US - 1))] + ind[1:],
        "DENY", {"outcome": ("F-vendor-a", "ev-vendor-a", "INADMISSIBLE")})
    rev = attest(ev("ev-vendor-a", 0.95, VENDOR_A), VA)
    add("x10_revoked_attestation", "Attestation listed as revoked in the trust state", WIRE,
        [fam("F-vendor-a", rev)] + ind[1:], "DENY", {"outcome": ("F-vendor-a", "ev-vendor-a", "INADMISSIBLE")},
        trust=dict(TRUST, revoked_attestation_ids=[rev["provenance"]["payload"]["attestation_id"]]))
    add("x11_unregistered_attester", "Attestation from a key that is not in the registry", WIRE,
        [fam("F-vendor-a", attest(ev("ev-vendor-a", 0.95, VENDOR_A), VA, key=K_UNREG, attester="org:unknown"))] + ind[1:],
        "DENY", {"outcome": ("F-vendor-a", "ev-vendor-a", "INADMISSIBLE")})
    add("x12_attester_type_not_authorised", "SOURCE-only attester vouches for DATABASE and API atoms", WIRE,
        [fam("F-vendor-a", attest(ev("ev-vendor-a", 0.95, VENDOR_A), VA, key=K_AUD_SRC, attester=AUD_SRC))] + ind[1:],
        "DENY", {"outcome": ("F-vendor-a", "ev-vendor-a", "INADMISSIBLE")})
    add("x13_attester_id_forged", "Payload claims the auditor's identity but is signed by vendor A's key", WIRE,
        [fam("F-vendor-a", attest(ev("ev-vendor-a", 0.95, VENDOR_A), VA, key=K_VENDOR_A, attester=AUD))] + ind[1:],
        "DENY", {"outcome": ("F-vendor-a", "ev-vendor-a", "TAMPERED")})
    add("x14_value_changed_after_attestation", "Score raised after the attestation was issued", WIRE,
        cor[:2] + [fam("F-webhook", dict(cor[2]["members"][0], value_bits=bits(1.0)))], "DENY",
        {"outcome": ("F-webhook", "ev-internal-webhook", "TAMPERED")},
        note="evidence_digest covers value_bits, so the attested score cannot be edited.")

    # --- defeater channel ----------------------------------------------------------------------
    four = ind + [fam("F-registry", attest(ev("ev-registry", 0.9, "org:gov-registry"), ["SOURCE:reg"]))]
    contra = ev("ev-webhook-contra", 0.9, "org:internal-kyc-service", parent="ev-internal-webhook",
                state="CONTRADICTORY", finding="beneficiary name mismatch")
    web_with = lambda m: fam("F-webhook", ind[2]["members"][0], m)
    add("d00_four_independent_pass", "Wire: four independent attested confirmations (baseline)", WIRE, four, "ALLOW")
    add("d01_unverified_contradiction", "Unattested contradiction only zeroes its own family", WIRE,
        [f_ for f_ in four if f_["family_id"] != "F-webhook"] + [web_with(contra)], "ALLOW",
        {"defeaters": 0},
        note="§2.2 behaviour: A(F-webhook) = 0, the other three still carry C above T. Audited as UNVERIFIED_CONTRADICTION.")
    add("d02_authenticated_defeater_vetoes", "Auditor-attested contradiction vetoes an otherwise passing wire", WIRE,
        [f_ for f_ in four if f_["family_id"] != "F-webhook"] + [web_with(attest(contra, ["SOURCE:internal-kyc"]))],
        "DENY", {"defeaters": 1, "reasons_include": ["DEFEATER_PRESENT"]},
        note="Categorical veto, not a negative mass term: M and C are reported unchanged from d01.")
    bad_sig = attest(contra, ["SOURCE:internal-kyc"])
    bad_sig["provenance"]["signature"] = "00" * 64
    add("d03_tampered_defeater", "A contradiction with a forged attestation is tampering, not a veto", WIRE,
        [f_ for f_ in four if f_["family_id"] != "F-webhook"] + [web_with(bad_sig)], "ALLOW",
        {"defeaters": 0, "reasons_include": ["PROVENANCE_TAMPERED"]},
        note="The webhook family is invalidated; the remaining three families still pass.")
    return C


def boundary_values():
    def one(vb):
        return ENG.evaluate(REFUND, [fam("F-solo", attest(ev("ev-solo", vb, "org:solo"), ["SOURCE:solo"]))], PROFILE, TRUST)
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
        raise SystemExit("v0.2.1 boundary search failed")
    return f"{hib:016x}", f"{b:016x}"


# ---------------------------------------------------------------------------
# Randomised generators shared with tools/property_tests.py
# ---------------------------------------------------------------------------
POOL = CC.ATOM_POOL


def random_attested_family(rng, fid, attested_p=0.8):
    n = 1 + rng.below(4)
    deps = sorted({rng.pick(POOL) for _ in range(n)}, key=lambda s: s.encode("utf-8"))
    root = ev(f"ev-{fid}", rng.unit(), f"org:{fid}")
    members = [attest(root, deps) if rng.below(10) < attested_p * 10 else root]
    if rng.below(3) == 0:
        d = ev(f"ev-{fid}-d", rng.unit(), f"org:{fid}", parent=f"ev-{fid}",
               state=rng.pick(["VALID", "DEGRADED", "UNAVAILABLE_OR_STALE"]))
        members.append(attest(d, deps[:1]))
    return fam(fid, *members)


def random_defeater_family(rng, fid):
    root = attest(ev(f"ev-{fid}", rng.unit(), f"org:{fid}"), [rng.pick(POOL)])
    contra = attest(ev(f"ev-{fid}-x", rng.unit(), f"org:{fid}", parent=f"ev-{fid}", state="CONTRADICTORY"),
                    [rng.pick(POOL)])
    return fam(fid, root, contra)


def witnesses(n=18):
    rng = CC.DRng("v021-witness")
    out = []
    kinds = ["monotone", "idempotent", "defeater"]
    for i in range(n):
        kind = kinds[i % 3]
        base = [random_attested_family(rng, f"W{i}-{k}") for k in range(1 + rng.below(4))]
        rq = rng.pick([WIRE, REFUND, ANNOTATE])
        added = {"monotone": lambda: random_attested_family(rng, f"W{i}-new"),
                 "idempotent": lambda: reattest_rename(rng.pick(base), f"W{i}-dup"),
                 "defeater": lambda: random_defeater_family(rng, f"W{i}-def")}[kind]()
        t0 = ENG.evaluate(rq, base, PROFILE, TRUST)
        t1 = ENG.evaluate(rq, base + [added], PROFILE, TRUST)
        ok = {"monotone": S.f(t1["M_bits"]) >= S.f(t0["M_bits"]) and not (t0["decision"] == "ALLOW" and t1["decision"] == "DENY"),
              "idempotent": t1["M_bits"] == t0["M_bits"],
              "defeater": t1["decision"] == "DENY"}[kind]
        if not ok:
            raise SystemExit(f"v0.2.1 witness {i} ({kind}) violated")
        out.append({"kind": kind, "request": rq, "base": base, "added": added,
                    "M_base_bits": t0["M_bits"], "M_after_bits": t1["M_bits"],
                    "decision_base": t0["decision"], "decision_after": t1["decision"]})
    return out


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build():
    out, by_id = [], {}
    for c in cases():
        tr = ENG.evaluate(c["request"], c["families"], c["profile"], c["trust"])
        cid, ck = c["id"], c["checks"]
        if tr["decision"] != c["expect"]:
            raise SystemExit(f"v0.2.1 {cid}: engine says {tr['decision']} {tr['reason_codes']}, declared {c['expect']}")
        if "M" in ck and S.f(tr["M_bits"]) != ck["M"]:
            raise SystemExit(f"v0.2.1 {cid}: M = {S.f(tr['M_bits'])}")
        if "same_M_as" in ck and tr["M_bits"] != by_id[ck["same_M_as"]]["M_bits"]:
            raise SystemExit(f"v0.2.1 {cid}: M {S.f(tr['M_bits'])} != {ck['same_M_as']} {S.f(by_id[ck['same_M_as']]['M_bits'])}")
        if "same_trace_as" in ck and R.encode(ENG.evaluate(c["request"], ck["same_trace_as"], c["profile"], c["trust"])) != R.encode(tr):
            raise SystemExit(f"v0.2.1 {cid}: trace differs from its base")
        if "outcome" in ck:
            fid, eid, want = ck["outcome"]
            got = tr["families"][fid]["provenance"][eid]["outcome"]
            if got != want:
                raise SystemExit(f"v0.2.1 {cid}: provenance outcome {got} != {want}")
        if "defeaters" in ck and len(tr["defeaters"]) != ck["defeaters"]:
            raise SystemExit(f"v0.2.1 {cid}: defeaters {tr['defeaters']}")
        for rsn in ck.get("reasons_include", []):
            if rsn not in tr["reason_codes"]:
                raise SystemExit(f"v0.2.1 {cid}: missing reason {rsn}")
        if "stage" in ck and tr["stage"] != ck["stage"]:
            raise SystemExit(f"v0.2.1 {cid}: stage")
        if ck.get("C_equals_T") and tr["C_bits"] != tr["T_bits"]:
            raise SystemExit(f"v0.2.1 {cid}: C != T")
        if "C_ulps_below_T" in ck and int(tr["T_bits"], 16) - int(tr["C_bits"], 16) != ck["C_ulps_below_T"]:
            raise SystemExit(f"v0.2.1 {cid}: ulp")
        by_id[cid] = tr
        v = {"id": cid, "title": c["title"],
             "profile": "calibrated" if c["profile"] is PROFILE else "no-alias-registry",
             "trust": "default" if c["trust"] is TRUST else "variant",
             "input": {"request": c["request"], "families": c["families"]},
             "expected_trace": tr,
             "summary": {"decision": tr["decision"], "stage": tr["stage"], "M": repr(S.f(tr["M_bits"])),
                         "C": repr(S.f(tr["C_bits"])), "reasons": tr["reason_codes"]}}
        if c["trust"] is not TRUST:
            v["trust_state"] = c["trust"]
        if c.get("note"):
            v["note"] = c["note"]
        out.append(v)
    # the d02 veto must leave M and C exactly as in d01 (categorical, not arithmetic)
    if (by_id["d01_unverified_contradiction"]["M_bits"], by_id["d01_unverified_contradiction"]["C_bits"]) != \
            (by_id["d02_authenticated_defeater_vetoes"]["M_bits"], by_id["d02_authenticated_defeater_vetoes"]["C_bits"]):
        raise SystemExit("defeater changed M/C — it must be a categorical veto only")
    return {
        "vector_set": "scoring-profile",
        "scoring_profile": C21.PROFILE_ID,
        "status": "SUPERSEDED by coverage-v0.3.0-alpha (kept as evidence; contradictions still zero A here)",
        "spec_version": R.SPEC_VERSION,
        "assumptions": "docs/SCORING_PROFILE_coverage-v0.2.1-alpha.md",
        "WARNING": "Test keys are derived from public seeds. Never use them outside conformance testing.",
        "profiles": {"calibrated": {"declaration": PROFILE, "fingerprint": R.H(PROFILE)},
                     "no-alias-registry": {"declaration": PROFILE_NO_ALIASES, "fingerprint": R.H(PROFILE_NO_ALIASES)}},
        "trust_state": TRUST,
        "provenance_keys": [{"label": k.label, "seed": k.seed.hex(), "public_key": k.public_hex, "key_id": k.key_id,
                             "domain": k.domain} for k in (K_AUD, K_AUD_SRC, K_VENDOR_A, K_UNREG)],
        "known_exploits_open": [],
        "property_witnesses": witnesses(),
        "cases": out,
    }
