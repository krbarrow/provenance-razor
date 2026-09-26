// Independent cross-check of the conformance vectors in JavaScript (Node >= 18, no dependencies).
//
// This file shares no code with reference/prc_ref.py. It re-implements, from the spec and
// docs/CONFORMANCE_ASSUMPTIONS.md only: the PRC-LP-0 encoder and strict decoder, SHA-256 hashing,
// Ed25519 key derivation/sign/verify, DecisionBindingValid (§3.1–3.5), and the §2.3 numeric ops.
// If both implementations agree on every vector, the vectors are much less likely to encode a
// bug in either one.
//
//   node tools/xcheck.mjs
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const T = (p) => join(ROOT, "tests", p);
const fails = [];
let checks = 0;
const ok = (c, m) => { checks++; if (!c) fails.push(m); };

// ---------------- PRC-LP-0 ----------------
const TAG = { NULL: 0x00, FALSE: 0x01, TRUE: 0x02, INT: 0x10, F64: 0x11, STR: 0x20, BYTES: 0x21, LIST: 0x30, MAP: 0x31 };
const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const frame = (tag, payload) => Buffer.concat([Buffer.from([tag]), u64be(payload.length), payload]);
const cmpBytes = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

// typed-JSON value (golden primitives)
function encTJ(t) {
  switch (t.type) {
    case "null": return frame(TAG.NULL, Buffer.alloc(0));
    case "bool": return frame(t.value ? TAG.TRUE : TAG.FALSE, Buffer.alloc(0));
    case "int": { const b = Buffer.alloc(8); b.writeBigInt64BE(BigInt(t.value)); return frame(TAG.INT, b); }
    case "f64": return frame(TAG.F64, Buffer.from(t.bits, "hex"));
    case "str": return frame(TAG.STR, Buffer.from(t.value, "utf8"));
    case "bytes": return frame(TAG.BYTES, Buffer.from(t.hex, "hex"));
    case "list": return frame(TAG.LIST, Buffer.concat(t.items.map(encTJ)));
    case "map": {
      const es = [...t.entries].sort((x, y) => cmpBytes(x[0], y[0]));
      return frame(TAG.MAP, Buffer.concat(es.flatMap(([k, v]) => [encTJ({ type: "str", value: k }), encTJ(v)])));
    }
  }
  throw new Error("bad type " + t.type);
}
// plain JSON payloads: numbers must be integers (payloads contain no floats)
function enc(v) {
  if (v === null) return encTJ({ type: "null" });
  if (typeof v === "boolean") return encTJ({ type: "bool", value: v });
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("non-integer number in payload: " + v);
    return encTJ({ type: "int", value: String(v) });
  }
  if (typeof v === "string") return encTJ({ type: "str", value: v });
  if (Array.isArray(v)) return frame(TAG.LIST, Buffer.concat(v.map(enc)));
  const keys = Object.keys(v).sort(cmpBytes);
  return frame(TAG.MAP, Buffer.concat(keys.flatMap((k) => [enc(k), enc(v[k])])));
}
function decodeStrict(buf) {
  function at(b, pos, end) {
    if (pos + 9 > end) throw new Error("truncated");
    const tag = b[pos];
    const len = Number(b.readBigUInt64BE(pos + 1));
    const s = pos + 9, e = s + len;
    if (e > end) throw new Error("overrun");
    const body = b.subarray(s, e);
    switch (tag) {
      case TAG.NULL: case TAG.FALSE: case TAG.TRUE:
        if (len) throw new Error("len"); return [tag === TAG.NULL ? null : tag === TAG.TRUE, e];
      case TAG.INT: if (len !== 8) throw new Error("int len"); return [body.readBigInt64BE(0), e];
      case TAG.F64: if (len !== 8) throw new Error("f64 len"); return [{ f64: body.toString("hex") }, e];
      case TAG.STR: return [new TextDecoder("utf-8", { fatal: true }).decode(body), e];
      case TAG.BYTES: return [Buffer.from(body), e];
      case TAG.LIST: { const out = []; let p = s; while (p < e) { const [x, q] = at(b, p, e); out.push(x); p = q; } return [out, e]; }
      case TAG.MAP: {
        const out = {}; let p = s, prev = null;
        while (p < e) {
          const [k, q] = at(b, p, e);
          if (typeof k !== "string") throw new Error("key type");
          if (prev !== null && cmpBytes(k, prev) <= 0) throw new Error("key order");
          prev = k; if (q >= e) throw new Error("dangling key");
          const [v, r] = at(b, q, e); out[k] = v; p = r;
        }
        return [out, e];
      }
    }
    throw new Error("tag");
  }
  const [v, end] = at(buf, 0, buf.length);
  if (end !== buf.length) throw new Error("trailing");
  return v;
}
const sha = (b) => createHash("sha256").update(b).digest("hex");
const H = (v) => sha(enc(v));
// decoded values carry BigInt ints; convert back to JSON-ish for comparisons
const plain = (v) => typeof v === "bigint" ? Number(v) : Array.isArray(v) ? v.map(plain)
  : v && typeof v === "object" && !Buffer.isBuffer(v) && !("f64" in v) ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, plain(x)])) : v;
const same = (a, b) => { try { return enc(a).equals(enc(b)); } catch { return false; } };

// ---------------- Ed25519 ----------------
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const pubKey = (hex) => createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(hex, "hex")]), format: "der", type: "spki" });
const edVerify = (pubHex, digestHex, sigHex) => {
  try { return verify(null, Buffer.from(digestHex, "hex"), pubKey(pubHex), Buffer.from(sigHex, "hex")); } catch { return false; }
};

// ---------------- golden ----------------
const g = JSON.parse(readFileSync(T("fixtures/golden_vectors.json"), "utf8"));
const keyById = {};
for (const k of g.keys) {
  const seed = createHash("sha256").update(`PRC-TEST-KEY|${k.domain}|${k.label}`).digest();
  ok(seed.toString("hex") === k.seed, `golden key seed ${k.key_id}`);
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: "der", type: "pkcs8" });
  const pub = createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(12).toString("hex");
  ok(pub === k.public_key, `golden key pub ${k.key_id}`);
  ok(`kid:${k.domain}:${sha(Buffer.from(pub, "hex")).slice(0, 16)}` === k.key_id, `golden key id ${k.key_id}`);
  keyById[k.key_id] = { ...k, priv };
}
for (const [name, c] of Object.entries(g.constants)) {
  if (!name.startsWith("NULL_")) continue;
  ok(enc(c.preimage).toString("hex") === c.preimage_bytes && H(c.preimage) === c.value, `golden ${name}`);
}
for (const p of g.primitives) {
  const b = encTJ(p.value);
  ok(b.toString("hex") === p.expected_bytes && sha(b) === p.expected_hash, `golden primitive ${p.id}`);
}
for (const r of g.must_reject) {
  let rejected = false;
  try { decodeStrict(Buffer.from(r.bytes, "hex")); } catch { rejected = true; }
  ok(rejected, `golden reject ${r.id}`);
}
for (const o of g.objects) {
  const b = enc(o.payload), h = sha(b);
  ok(b.toString("hex") === o.expected_bytes && h === o.expected_hash, `golden object ${o.id} bytes/hash`);
  const k = keyById[o.signing_key_id];
  const sig = sign(null, Buffer.from(h, "hex"), k.priv).toString("hex");
  ok(sig === o.expected_signature, `golden object ${o.id} deterministic signature`);
  ok(edVerify(k.public_key, h, o.expected_signature), `golden object ${o.id} verify`);
}
const NULL_APPROVAL = g.constants.NULL_APPROVAL_DIGEST.value;

// ---------------- DecisionBindingValid (independent) ----------------
const auth = JSON.parse(readFileSync(T("vectors/auth_expiry_skew.json"), "utf8"));
const REASONS = JSON.parse(readFileSync(T("reason_codes.json"), "utf8")).bits.map((b) => b.name);
const glob = (s, pat) => new RegExp("^" + pat.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$").test(s);
const keyAuth = (reg, kid, epoch, domain, cls) => {
  const e = reg[kid];
  if (!e || e.domain !== domain || !e.epochs.includes(epoch)) return false;
  return cls === undefined || (e.authority_classes || []).includes(cls);
};
// ---- CanonicalObjectValid (independent re-implementation of spec 0.3.0 §1.5) ----
const MAXU = 2n ** 63n - 1n;
const isInt = (v) => typeof v === "bigint" || Number.isSafeInteger(v);
const K = {
  str: (v) => typeof v === "string" && v !== "",
  uint: (v) => (typeof v === "bigint" && v >= 0n && v <= MAXU) || (Number.isSafeInteger(v) && v >= 0),
  hex32: (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v),
  uuid7: (v) => typeof v === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v),
  semver: (v) => typeof v === "string" && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/.test(v),
  keyid: (v) => typeof v === "string" && /^kid:[a-z]+:[0-9a-f]{16}$/.test(v),
  schema_ver: (v) => v === "0.3.0-alpha",
  bool: (v) => typeof v === "boolean",
  map: (v) => v !== null && typeof v === "object" && !Array.isArray(v) && !Buffer.isBuffer(v) && !("f64" in v),
  actor: (v) => K.map(v) && Object.keys(v).sort().join() === "id,type" && K.str(v.id) && ["service", "user"].includes(v.type),
  action: (v) => K.map(v) && K.str(v.action),
  atoms: (v) => Array.isArray(v) && v.every((a) => typeof a === "string" && /^[A-Z_]+:\S+$/.test(a)),
  manifest_members: (v) => Array.isArray(v) && v.every((m) => K.map(m) && Object.keys(m).sort().join() === "evidence_digest,evidence_id,parent_id"
    && K.str(m.evidence_id) && K.hex32(m.evidence_digest) && (m.parent_id === null || K.str(m.parent_id))),
};
const KS = K;
const kind = (spec) => spec.startsWith("enum:") ? (v) => spec.slice(5).split("|").includes(v)
  : spec.startsWith("opt_") ? (v) => v === null || K[spec.slice(4)](v) : K[spec];
const SCH = {
  decision: "domain:str schema_ver:schema_ver profile_version:semver lineage_schema_version:semver capability_id:uuid7 req_id:uuid7 evidence_snapshot_id:uuid7 actor:actor auth_mode:enum:AUTOMATED|MANUAL x:action a:map target:str state_ver:uint control_profile_hash:hex32 scoring_profile_hash:hex32 trust_state_hash:hex32 evidence_hash:hex32 lineage_hash:hex32 approval_hash:hex32 adverse_disposition:enum:CLEAR|CONTAIN containment_digest:hex32 decision_key_id:keyid decision_trust_epoch:str eval_clock_id:str tau_eval:uint tau_expiry:uint decision:enum:ALLOW|DENY reason_codes:uint",
  approval: "domain:str schema_ver:schema_ver approval_id:uuid7 approval_key_id:keyid approval_trust_epoch:str authority_class:str authority_scope:str x:action a:map target:str actor:actor req_id:uuid7 capability_id:uuid7 state_ver:uint control_profile_hash:hex32 scoring_profile_hash:hex32 trust_state_hash:hex32 adverse_disposition:enum:CLEAR|CONTAIN containment_digest:hex32 tau_issued:uint tau_expiry:uint decision:enum:ALLOW|DENY",
  attestation: "domain:str schema_ver:schema_ver attestation_id:uuid7 provenance_key_id:keyid provenance_trust_epoch:str attester_id:str evidence_digest:hex32 dependencies:atoms tau_issued:uint tau_expiry:uint",
  manifest: "domain:str schema_ver:schema_ver manifest_id:uuid7 membership_key_id:keyid membership_trust_epoch:str authority_id:str family_id:str ingress_channel:str members:manifest_members tau_issued:uint tau_expiry:uint",
};
const SCHEMA = Object.fromEntries(Object.entries(SCH).map(([n, txt]) => [n, Object.fromEntries(txt.split(" ").map((t) => { const i = t.indexOf(":"); return [t.slice(0, i), kind(t.slice(i + 1))]; }))]));
function schemaValid(z, name) {
  if (!K.map(z)) return false;
  const spec = SCHEMA[name];
  const keys = Object.keys(z);
  if (keys.length !== Object.keys(spec).length || keys.some((k) => !(k in spec))) return false;
  return Object.entries(spec).every(([k, f]) => k in z && f(z[k]));
}
const envelopeOk = (env) => K.map(env) && Object.keys(env).sort().join() === "payload,signature" && typeof env.signature === "string" && /^[0-9a-f]{128}$/.test(env.signature);
const domainKey = (reg, kid, domain) => { const e = typeof kid === "string" ? reg[kid] : undefined; return e && e.domain === domain ? e : null; };
const verifyIn = (reg, kid, domain, digest, sig) => { const e = domainKey(reg, kid, domain); return !!e && typeof sig === "string" && edVerify(e.public_key, digest, sig); };
const NULL_CONTAINMENT = sha(enc("PROVENANCE-RAZOR-NO-CONTAINMENT-V0.3.0-Alpha"));
function clock(ts, evalId, ex) {
  const cl = ts.clock_authorities || {};
  const ev = cl[evalId], xa = ex && cl[ex.clock_id];
  const u = ex && Number.isSafeInteger(ex.uncertainty_us) && ex.uncertainty_us >= 0 ? ex.uncertainty_us : 0;
  const trusted = !!ev && !!xa && Number.isSafeInteger(ex.uncertainty_us) && ex.uncertainty_us >= 0 && ex.uncertainty_us <= xa.max_uncertainty_us;
  return [trusted, (ev ? ev.max_uncertainty_us : 0) + u];
}
function approvalCheck(ctx, ts, pHex, pSig, d, U) {
  const R = new Set(), reg = ts.key_registry;
  let raw, p;
  try { raw = Buffer.from(pHex, "hex"); const dec = decodeStrict(raw); if (!schemaValid(dec, "approval")) return ["APPROVAL_SCHEMA_INVALID"]; p = plain(dec); }
  catch { return ["APPROVAL_SCHEMA_INVALID"]; }
  if (!verifyIn(reg, p.approval_key_id, "approval", sha(raw), pSig)) R.add("APPROVAL_SIGNATURE_INVALID");
  if (p.domain !== "PROVENANCE-RAZOR-APPROVAL-V0.3.0-Alpha") R.add("APPROVAL_DOMAIN_MISMATCH");
  if (!keyAuth(reg, p.approval_key_id, p.approval_trust_epoch, "approval", p.authority_class)) R.add("APPROVAL_KEY_UNAUTHORIZED");
  if (!glob(`${ctx.x.action}:${p.target}`, p.authority_scope)) R.add("APPROVAL_SCOPE_DENIED");
  if (!same(p.x, ctx.x) || !same(p.a, ctx.a) || p.state_ver !== ctx.current_state_ver || p.control_profile_hash !== ctx.active_control_profile_hash
      || p.scoring_profile_hash !== d.scoring_profile_hash || p.trust_state_hash !== d.trust_state_hash) R.add("APPROVAL_BINDING_MISMATCH");
  if (p.target !== ctx.current_target || p.target !== d.target || !same(p.actor, d.actor) || p.req_id !== d.req_id || p.capability_id !== d.capability_id)
    R.add("APPROVAL_SUBJECT_MISMATCH");
  if (p.adverse_disposition !== d.adverse_disposition || p.containment_digest !== d.containment_digest) R.add("ADVERSE_DISPOSITION_MISMATCH");
  if (!(p.tau_issued <= d.tau_eval)) R.add("APPROVAL_NOT_YET_VALID");
  if (!(ctx.exec_clock.tau_exec + U <= p.tau_expiry)) R.add("APPROVAL_EXPIRED");
  const reusable = (ctx.profile.reusable_authority_classes || []).includes(p.authority_class);
  if ((ctx.consumed_approvals || []).includes(p.approval_id) && !reusable) R.add("APPROVAL_CONSUMED");
  return [...R];
}
function dbv(ctx, ts, dHex, dSig, pHex, pSig) {
  let d, raw;
  try { raw = Buffer.from(dHex, "hex"); const dec = decodeStrict(raw); if (!schemaValid(dec, "decision")) return ["OBJECT_SCHEMA_INVALID"]; d = plain(dec); }
  catch { return ["DECODE_INVALID"]; }
  const R = new Set(), reg = ts.key_registry;
  if (!verifyIn(reg, d.decision_key_id, "decision", sha(raw), dSig)) R.add("SIGNATURE_INVALID");
  if (d.domain !== "PROVENANCE-RAZOR-DECISION-V0.3.0-Alpha") R.add("DOMAIN_MISMATCH");
  if (!same(d.x, ctx.x)) R.add("ACTION_MISMATCH");
  if (!same(d.a, ctx.a)) R.add("ASSERTION_MISMATCH");
  if (d.target !== ctx.current_target) R.add("TARGET_MISMATCH");
  if (d.state_ver !== ctx.current_state_ver) R.add("STATE_VERSION_MISMATCH");
  if (d.control_profile_hash !== ctx.active_control_profile_hash) R.add("PROFILE_HASH_MISMATCH");
  if (d.scoring_profile_hash !== ctx.active_scoring_profile_hash) R.add("SCORING_PROFILE_MISMATCH");
  if (d.trust_state_hash !== ctx.trust_state_hash || d.trust_state_hash !== H(ts)) R.add("TRUST_STATE_MISMATCH");
  if (d.evidence_hash !== ctx.evidence_hash) R.add("EVIDENCE_HASH_MISMATCH");
  if (d.lineage_hash !== ctx.lineage_hash) R.add("LINEAGE_HASH_MISMATCH");
  if (d.adverse_disposition !== ctx.adverse_disposition || d.containment_digest !== ctx.containment_digest) R.add("ADVERSE_DISPOSITION_MISMATCH");
  if ((d.adverse_disposition === "CLEAR") !== (d.containment_digest === NULL_CONTAINMENT)) R.add("ADVERSE_DISPOSITION_MISMATCH");
  if (d.decision !== "ALLOW") R.add("DECISION_NOT_ALLOW");
  const [trusted, U] = clock(ts, d.eval_clock_id, ctx.exec_clock);
  if (!trusted) R.add("CLOCK_UNTRUSTED");
  const tx = ctx.exec_clock.tau_exec;
  if (!(d.tau_eval + U <= tx)) R.add("NOT_YET_VALID");
  if (!(tx + U <= d.tau_expiry)) R.add("EXPIRED_CAPABILITY");
  const skew = ctx.profile.max_eval_skew_us[ctx.x.action] ?? ctx.profile.max_eval_skew_us["*"];
  if (!(tx - d.tau_eval + U <= skew)) R.add("EVAL_SKEW_EXCEEDED");
  if (!keyAuth(reg, d.decision_key_id, d.decision_trust_epoch, "decision")) R.add("DECISION_KEY_UNAUTHORIZED");
  if ((ctx.consumed_capabilities || []).includes(d.capability_id)) R.add("CAPABILITY_UNAVAILABLE");
  const manualOnly = (ctx.profile.manual_only_actions || []).includes(ctx.x.action);
  const contained = d.adverse_disposition === "CONTAIN";
  let modeOk = false;
  if (d.auth_mode === "AUTOMATED") { modeOk = !manualOnly && !contained && d.approval_hash === NULL_APPROVAL; if (contained) R.add("ADVERSE_CONTAINMENT"); }
  else if (pHex) {
    const pr = approvalCheck(ctx, ts, pHex, pSig, d, U);
    const hashOk = d.approval_hash === sha(Buffer.from(pHex, "hex"));
    if (!hashOk) pr.push("APPROVAL_HASH_MISMATCH");
    pr.forEach((x) => R.add(x));
    modeOk = (manualOnly || contained) && hashOk && pr.length === 0;
  }
  if (!modeOk) R.add("AUTH_MODE_INVALID");
  return REASONS.filter((n) => R.has(n));
}
ok(H(auth.trust_state) === auth.trust_state_hash, "auth trust_state_hash");
for (const v of auth.vectors) {
  const i = v.input;
  const got = dbv(i.context, v.trust_state || auth.trust_state, i.decision_bytes, i.decision_signature, i.approval_bytes, i.approval_signature);
  ok(JSON.stringify(got) === JSON.stringify(v.expected_output.reason_codes), `auth ${v.test_id}: js=${got} vector=${v.expected_output.reason_codes}`);
  ok((got.length === 0) === v.expected_output.DecisionBindingValid, `auth ${v.test_id} validity`);
  const mask = got.reduce((m, n) => m | (1n << BigInt(REASONS.indexOf(n))), 0n);
  ok(mask === BigInt(v.expected_output.reason_bitfield), `auth ${v.test_id} bitfield`);
}

// ---------------- §2.3 numerics (independent) ----------------
const blob = readFileSync(T("vectors/kahan_cordic_ieee754.bin"));
const nman = JSON.parse(readFileSync(T("vectors/kahan_cordic_ieee754.json"), "utf8"));
ok(sha(blob) === nman.binary_sha256, "numeric bin sha256");
const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
const toF = (bits) => { const d = new DataView(new ArrayBuffer(8)); d.setBigUint64(0, bits, true); return d.getFloat64(0, true); };
const toB = (x) => { const d = new DataView(new ArrayBuffer(8)); d.setFloat64(0, x, true); return d.getBigUint64(0, true); };
const exceptional = (bits) => ((bits >> 52n) & 0x7ffn) === 0x7ffn;
const nz = (x) => (x === 0 ? 0 : x); // -0 -> +0
let pos = 12;
const count = dv.getUint32(8, true);
ok(blob.subarray(0, 4).toString() === "PRNV" && count === nman.cases.length, "numeric header");
for (const c of nman.cases) {
  const op = dv.getUint8(pos), flags = dv.getUint8(pos + 1), n = dv.getUint32(pos + 4, true); pos += 8;
  const ins = []; for (let k = 0; k < n; k++) { ins.push(dv.getBigUint64(pos, true)); pos += 8; }
  const out = dv.getBigUint64(pos, true); pos += 8;
  let res = false, lock = false, bits = 0n;
  if (op === 1) {
    if (exceptional(ins[0]) || exceptional(ins[1])) lock = true;
    else { const C = nz(toF(ins[0])), Tt = nz(toF(ins[1])); res = C >= Tt; bits = toB(C); }
  } else {
    if (ins.some(exceptional)) lock = true;
    else {
      let s = 0, comp = 0;
      for (const b of ins) {
        const y = toF(b) - comp, t = s + y; comp = (t - s) - y; s = t;
        if (!Number.isFinite(s) || !Number.isFinite(comp)) { lock = true; break; }
      }
      if (!lock) bits = toB(nz(s));
    }
  }
  ok(bits === out && lock === Boolean(flags & 2) && (op !== 1 || res === Boolean(flags & 1)), `numeric ${c.id}`);
}

// ---------------- scoring profile jaccard-v0.1.0-alpha (independent) ----------------
{
  const sc = JSON.parse(readFileSync(T("vectors/scoring_jaccard_v0.1.0-alpha.json"), "utf8"));
  const fb = (h) => Buffer.from(h, "hex").readDoubleBE(0);
  const hb = (x) => { const b = Buffer.alloc(8); b.writeDoubleBE(x); return b.toString("hex"); };
  const bitsBig = (h) => BigInt("0x" + h);
  const K = sc.prc_exp_v1.constants_bits;
  const INV_LN2 = fb(K.INV_LN2), LN2_HI = fb(K.LN2_HI), LN2_LO = fb(K.LN2_LO);
  // coefficients recomputed here (1/n!), then checked against the published bits
  const COEF = []; { let fct = 1; for (let n = 0; n < 14; n++) { if (n) fct *= n; COEF.push(1 / fct); } }
  ok(COEF.map(hb).join() === K["C0..C13"].join(), "prc_exp coefficients");
  const pow2 = (k) => { const b = Buffer.alloc(8);
    if (k >= -1022) b.writeBigUInt64BE(BigInt(k + 1023) << 52n); else b.writeBigUInt64BE(1n << BigInt(k + 1074));
    return b.readDoubleBE(0); };
  const pexp = (x) => {
    if (Number.isNaN(x)) return x; if (x > 709) return Infinity; if (x < -745) return 0;
    const k = Math.floor(x * INV_LN2 + 0.5);
    const r = (x - k * LN2_HI) - k * LN2_LO;
    let p = COEF[13]; for (let n = 12; n >= 0; n--) p = p * r + COEF[n];
    if (k < -1022) return (p * pow2(-1022)) * pow2(k + 1022);
    if (k > 1023) return (p * pow2(1023)) * pow2(k - 1023);
    return p * pow2(k);
  };
  let expMismatchLibm = 0;
  for (const v of sc.prc_exp_v1.vectors) {
    ok(hb(pexp(fb(v.input_bits))) === v.expected_bits, `prc_exp ${v.input_repr}`);
    if (hb(Math.exp(fb(v.input_bits))) !== v.libm_exp_bits_informative) expMismatchLibm++;
  }
  const TYPES = ["SOURCE","DATABASE","COLLECTOR","RUNTIME","CLOCK","NETWORK_AS","TRUST_ROOT","API_ENDPOINT"];
  const utf8sort = (a) => [...a].sort(cmpBytes);
  const digest = (e) => { const n = { ...e, dependencies: utf8sort(new Set(e.dependencies || [])) }; return H(n); };
  const exceptional = (x) => !Number.isFinite(x);
  function evaluate(req, families, prof) {
    const omega = fb(prof.omega_bits), tb = fb(prof.t_base_bits), beta = fb(prof.beta_bits);
    const kU = fb(prof.kappa_unknown_bits), kD = fb(prof.kappa_degraded_bits);
    const material = new Set(prof.material_dependency_types);
    const R = new Set(); const out = { families: {} }; const elig = [];
    for (const fam of [...families].sort((a, b) => cmpBytes(a.family_id, b.family_id))) {
      const ids = fam.members.map((m) => m.evidence_id), byId = Object.fromEntries(fam.members.map((m) => [m.evidence_id, m]));
      let bad = new Set(ids).size !== ids.length;
      const roots = fam.members.filter((m) => m.parent_id === null || !(m.parent_id in byId));
      bad = bad || roots.length !== 1;
      const depth = {};
      if (!bad) for (const m of fam.members) {
        let cur = m, d = 0; const seen = new Set();
        while (cur.evidence_id !== roots[0].evidence_id) { if (seen.has(cur.evidence_id)) { bad = true; break; }
          seen.add(cur.evidence_id); cur = byId[cur.parent_id]; d++; }
        depth[m.evidence_id] = d;
      }
      bad = bad || fam.members.some((m) => (m.dependencies || []).some((a) => { const mm = /^([A-Z_]+):(\S+)$/.exec(a); return !mm || !TYPES.includes(mm[1]); }));
      if (bad) { out.families[fam.family_id] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const root = roots[0], opt = fam.members.filter((m) => m !== root);
      const states = opt.map((m) => m.state || "VALID"), rs = root.state || "VALID";
      if (states.includes("INVALID") || rs === "INVALID") { out.families[fam.family_id] = { status: "INVALIDATED" }; R.add("FAMILY_INVALIDATED"); continue; }
      if (rs !== "VALID") { out.families[fam.family_id] = { status: "REPRESENTATIVE_" + rs }; continue; }
      const fac = states.filter((s) => s !== "UNAVAILABLE_OR_STALE").map((s) => s === "DEGRADED" ? kD : s === "VALID" ? 1 : 0);
      const A = fac.length ? Math.min(...fac) : 1;
      const Vr = fb(root.value_bits);
      if (Number.isFinite(Vr) && !(Vr >= 0 && Vr <= 1)) { out.families[fam.family_id] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const V = Vr * A;
      const mat = new Set((root.dependencies || []).filter((a) => material.has(a.split(":")[0])));
      out.families[fam.family_id] = { status: "ELIGIBLE", representative: root.evidence_id, representative_digest: digest(root), A_bits: hb(A), V_bits: hb(V), depth };
      elig.push({ rep: root.evidence_id, fid: fam.family_id, V, mat });
    }
    elig.sort((a, b) => cmpBytes(a.rep, b.rep));
    const pair = {}; let unknown = false;
    for (const k of elig) {
      if (elig.length === 1) { k.I = 1; break; }
      let mn = Infinity;
      for (const j of elig) { if (j === k) continue;
        let i; if (!k.mat.size || !j.mat.size) { i = kU; unknown = true; }
        else { let inter = 0; for (const a of k.mat) if (j.mat.has(a)) inter++; const uni = k.mat.size + j.mat.size - inter; i = 1 - inter / uni; }
        pair[`${k.fid}|${j.fid}`] = hb(i); mn = Math.min(mn, i); }
      k.I = mn;
    }
    let M = 0; for (const e of elig) { M = M + e.V * e.I; out.families[e.fid].I_bits = hb(e.I); }
    let C = Number.isFinite(M) ? 1 - pexp(-(M / omega)) : NaN;
    const g = prof.consequence_gamma_bits[req.action];
    let Tt = NaN; if (g !== undefined) Tt = 1 - (1 - tb) * pexp(-(fb(g) * beta)); else R.add("CONSEQUENCE_CLASS_UNDEFINED");
    if (!elig.length) { R.add("NO_ELIGIBLE_EVIDENCE"); M = 0; C = 0; }
    let lock = false, res = false;
    if (exceptional(C) || exceptional(Tt)) { lock = true; C = 0; R.add("SAFE_STATE_LOCK"); }
    else { C = C === 0 ? 0 : C; res = C >= (Tt === 0 ? 0 : Tt); if (!res) R.add("THRESHOLD_NOT_MET"); }
    const allow = res && !R.has("CONSEQUENCE_CLASS_UNDEFINED");
    return { ...out, pair, unknown, M: hb(M), C: hb(C), T: hb(Tt), lock, decision: allow ? "ALLOW" : "DENY",
             reasons: REASONS.filter((n) => R.has(n)), eligible: elig.map((e) => e.fid) };
  }
  const sortObj = (o) => JSON.stringify(Object.fromEntries(Object.entries(o).sort((a, b) => cmpBytes(a[0], b[0]))));
  for (const c of sc.cases) {
    const prof = sc.profiles[c.profile].declaration, e = c.expected_trace;
    ok(H(prof) === sc.profiles[c.profile].fingerprint, `scoring ${c.id} profile fingerprint`);
    const g = evaluate(c.input.request, c.input.families, prof);
    const tag = `scoring ${c.id}`;
    ok(g.decision === e.decision, `${tag} decision js=${g.decision}`);
    ok(JSON.stringify(g.reasons) === JSON.stringify(e.reason_codes), `${tag} reasons js=${g.reasons}`);
    ok(g.M === e.M_bits && g.C === e.C_bits && g.T === e.T_bits, `${tag} M/C/T bits js=${g.M},${g.C},${g.T}`);
    ok(g.lock === e.safe_state_lock && g.unknown === e.unknown_lineage_fallback_used, `${tag} flags`);
    ok(JSON.stringify(g.eligible) === JSON.stringify(e.eligible_families), `${tag} eligible`);
    ok(sortObj(g.pair) === sortObj(e.pairwise_independence_bits), `${tag} pairwise`);
    for (const [fid, ef] of Object.entries(e.families)) {
      const gf = g.families[fid] || {};
      ok(gf.status === ef.status, `${tag} ${fid} status`);
      if (ef.status === "ELIGIBLE")
        ok(gf.representative === ef.representative && gf.representative_digest === ef.representative_digest &&
           gf.A_bits === ef.A_bits && gf.V_bits === ef.V_bits && gf.I_bits === ef.I_bits &&
           sortObj(gf.depth) === sortObj(ef.lineage_depth), `${tag} ${fid} values`);
    }
  }
  const h = sc.headline;
  const byId = Object.fromEntries(sc.cases.map((c) => [c.id, c]));
  const strip = (fs) => enc(fs.map((f_) => ({ ...f_, members: f_.members.map((m) => ({ ...m, dependencies: [] })) })));
  ok(strip(byId[h.allow_case].input.families).equals(strip(byId[h.deny_case].input.families)), "headline inputs identical except lineage");
  // ---------- coverage-v0.2.0-alpha + engine guard E-1 (independent) ----------
  const cv = JSON.parse(readFileSync(T("vectors/scoring_coverage_v0.2.0-alpha.json"), "utf8"));
  const nonfinite = (h) => !Number.isFinite(fb(h));
  function engine(req, families, prof) {
    const bad = [];
    for (const k of Object.keys(prof).sort(cmpBytes)) if (k.endsWith("_bits") && typeof prof[k] === "string" && nonfinite(prof[k])) bad.push(`profile.${k}`);
    for (const a of Object.keys(prof.consequence_gamma_bits || {}).sort(cmpBytes)) if (nonfinite(prof.consequence_gamma_bits[a])) bad.push(`profile.consequence_gamma_bits.${a}`);
    for (const fm of [...families].sort((a, b) => cmpBytes(a.family_id, b.family_id)))
      for (const m of [...fm.members].sort((a, b) => cmpBytes(a.evidence_id, b.evidence_id)))
        if (m.value_bits !== undefined && nonfinite(m.value_bits)) bad.push(`${fm.family_id}/${m.evidence_id}.value_bits`);
    if (bad.length) return { stage: "ENGINE_GUARD", bad, M: hb(0), C: hb(0), T: null, lock: true, decision: "DENY", reasons: ["SAFE_STATE_LOCK", "NONFINITE_INPUT"] };
    return coverage(req, families, prof);
  }
  function coverage(req, families, prof) {
    const omega = fb(prof.omega_bits), tb = fb(prof.t_base_bits), beta = fb(prof.beta_bits);
    const kU = fb(prof.kappa_unknown_bits), kD = fb(prof.kappa_degraded_bits), gate = fb(prof.unknown_gate_t_bits);
    const material = new Set(prof.material_dependency_types);
    const R = new Set(); const fams = {}; const elig = [];
    const g = prof.consequence_gamma_bits[req.action];
    let Tt = NaN; if (g !== undefined) Tt = 1 - (1 - tb) * pexp(-(fb(g) * beta)); else R.add("CONSEQUENCE_CLASS_UNDEFINED");
    const kEff = (Tt === Tt && Tt >= gate) ? 0 : kU;
    for (const fam of [...families].sort((a, b) => cmpBytes(a.family_id, b.family_id))) {
      const byId = Object.fromEntries(fam.members.map((m) => [m.evidence_id, m]));
      let bad = new Set(fam.members.map((m) => m.evidence_id)).size !== fam.members.length;
      const roots = fam.members.filter((m) => m.parent_id === null || !(m.parent_id in byId));
      bad = bad || roots.length !== 1;
      if (!bad) for (const m of fam.members) { let cur = m; const seen = new Set();
        while (cur.evidence_id !== roots[0].evidence_id) { if (seen.has(cur.evidence_id)) { bad = true; break; } seen.add(cur.evidence_id); cur = byId[cur.parent_id]; } }
      bad = bad || fam.members.some((m) => (m.dependencies || []).some((a) => { const mm = /^([A-Z_]+):(\S+)$/.exec(a); return !mm || !TYPES.includes(mm[1]); }));
      if (bad) { fams[fam.family_id] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const root = roots[0], states = fam.members.filter((m) => m !== root).map((m) => m.state || "VALID"), rs = root.state || "VALID";
      if (states.includes("INVALID") || rs === "INVALID") { fams[fam.family_id] = { status: "INVALIDATED" }; R.add("FAMILY_INVALIDATED"); continue; }
      if (rs !== "VALID") { fams[fam.family_id] = { status: "REPRESENTATIVE_" + rs }; continue; }
      const Vr = fb(root.value_bits);
      if (!(Vr >= 0 && Vr <= 1)) { fams[fam.family_id] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const fac = states.filter((x) => x !== "UNAVAILABLE_OR_STALE").map((x) => x === "DEGRADED" ? kD : x === "VALID" ? 1 : 0);
      let V = Vr * (fac.length ? Math.min(...fac) : 1);
      let atoms = [...new Set((root.dependencies || []).filter((a) => material.has(a.split(":")[0])))];
      if (!atoms.length) { V = V * kEff; atoms = ["UNKNOWN:*"]; }
      const w = V / atoms.length;
      fams[fam.family_id] = { status: "ELIGIBLE", V_bits: hb(V), share: hb(w), atoms: [...atoms].sort(cmpBytes) };
      elig.push({ fid: fam.family_id, atoms, w });
    }
    const best = new Map();
    for (const e of elig) for (const a of e.atoms) if (!best.has(a) || e.w > best.get(a)) best.set(a, e.w);
    let M = 0; for (const a of [...best.keys()].sort(cmpBytes)) M = M + best.get(a);
    let C = 1 - pexp(-(M / omega));
    if (!elig.length) { R.add("NO_ELIGIBLE_EVIDENCE"); M = 0; C = 0; }
    let lock = false, res = false;
    if (!Number.isFinite(C) || !Number.isFinite(Tt)) { lock = true; C = 0; R.add("SAFE_STATE_LOCK"); }
    else { C = C === 0 ? 0 : C; res = C >= Tt; if (!res) R.add("THRESHOLD_NOT_MET"); }
    return { stage: "PROFILE", fams, eligible: elig.map((e) => e.fid), kEff: hb(kEff), M: hb(M), C: hb(C), T: hb(Tt), lock,
             decision: res && !R.has("CONSEQUENCE_CLASS_UNDEFINED") ? "ALLOW" : "DENY", reasons: REASONS.filter((n) => R.has(n)) };
  }
  const cvBase = cv.profiles.calibrated.declaration;
  ok(H(cvBase) === cv.profiles.calibrated.fingerprint, "coverage profile fingerprint");
  const cvById = {};
  let xfail = 0;
  for (const c of cv.cases) {
    const e = c.expected_trace, tag = `coverage ${c.id}`;
    const g = engine(c.input.request, c.input.families, c.profile_declaration || cvBase);
    cvById[c.id] = e;
    ok(g.stage === e.stage && g.decision === e.decision, `${tag} stage/decision js=${g.stage}/${g.decision}`);
    ok(JSON.stringify(g.reasons) === JSON.stringify(e.reason_codes), `${tag} reasons js=${g.reasons}`);
    ok(g.M === e.M_bits && g.C === e.C_bits && (e.T_bits === null ? g.T === null : g.T === e.T_bits), `${tag} M/C/T bits`);
    if (e.stage === "ENGINE_GUARD") { ok(JSON.stringify(g.bad) === JSON.stringify(e.nonfinite_inputs), `${tag} guard locations`); continue; }
    ok(g.kEff === e.kappa_unknown_effective_bits && JSON.stringify(g.eligible) === JSON.stringify(e.eligible_families), `${tag} kappa/eligible`);
    for (const [fid, ef] of Object.entries(e.families)) {
      const gf = g.fams[fid] || {};
      ok(gf.status === ef.status, `${tag} ${fid} status`);
      if (ef.status === "ELIGIBLE") ok(gf.V_bits === ef.V_bits && gf.share === ef.per_atom_share_bits && JSON.stringify(gf.atoms) === JSON.stringify(ef.atoms), `${tag} ${fid} values`);
    }
  }
  for (const c of cv.cases) if (c.known_exploit) {
    const s = c.known_exploit.security_expectation;
    const meets = c.expected_trace.decision === s.decision && c.expected_trace.M_bits === cvById[s.same_M_as].M_bits;
    ok(!meets, `coverage ${c.id} exploit no longer reproduces`); xfail++;
  }
  cv.property_witnesses.forEach((w, i) => {
    const t0 = engine(w.request, w.base, cvBase), t1 = engine(w.request, [...w.base, w.added], cvBase);
    ok(t0.M === w.M_base_bits && t1.M === w.M_after_bits, `coverage witness ${i} bits`);
    const prop = w.kind === "idempotent" ? t1.M === t0.M : fb(t1.M) >= fb(t0.M);
    ok(prop && !(t0.decision === "ALLOW" && t1.decision === "DENY"), `coverage witness ${i} (${w.kind}) property`);
  });
  console.log(`coverage-v0.2.0 (superseded): ${cv.cases.length} cases, ${cv.property_witnesses.length} witnesses, ${xfail} exploit reproduced by design (closed in v0.2.1)`);
  // ---------- coverage-v0.2.1-alpha: P-1 provenance admissibility + defeater veto (independent) ----------
  const c21 = JSON.parse(readFileSync(T("vectors/scoring_coverage_v0.2.1-alpha.json"), "utf8"));
  const PROV_DOMAIN = "PROVENANCE-RAZOR-PROVENANCE-V0.3.0-Alpha";
  const REQ = ["domain","schema_ver","attestation_id","provenance_key_id","provenance_trust_epoch","attester_id","evidence_digest","dependencies","tau_issued","tau_expiry"];
  const core = (m) => Object.fromEntries(Object.entries(m).filter(([k]) => k !== "provenance" && k !== "dependencies"));
  function admit(m, trust, prof, tauEval) {
    const env = m.provenance;
    if (env === undefined) return ["UNATTESTED", null];
    if (!envelopeOk(env)) return ["TAMPERED", null];
    const p = env.payload;
    if (!schemaValid(p, "attestation")) return ["TAMPERED", null];
    if (p.domain !== PROV_DOMAIN) return ["TAMPERED", null];
    const e = (trust.key_registry || trust.registry)[p.provenance_key_id];
    if (!e) return ["INADMISSIBLE", null];
    if (e.domain !== "provenance") return ["TAMPERED", null];
    if (!edVerify(e.public_key, H(p), env.signature)) return ["TAMPERED", null];
    if (p.attester_id !== (e.owner ?? e.attester_id)) return ["TAMPERED", null];
    if (p.evidence_digest !== H(core(m))) return ["TAMPERED", null];
    if (!e.epochs.includes(p.provenance_trust_epoch)) return ["INADMISSIBLE", null];
    if ((trust.revoked_attestation_ids || []).includes(p.attestation_id)) return ["INADMISSIBLE", null];
    if (!(p.tau_issued <= tauEval && tauEval <= p.tau_expiry)) return ["INADMISSIBLE", null];
    if (prof.attester_independence_required && p.attester_id === m.producer) return ["INADMISSIBLE", null];
    if (JSON.stringify(p.dependencies) !== JSON.stringify(utf8sort(new Set(p.dependencies)))) return ["INADMISSIBLE", null];
    const reg = new Set(prof.atom_registry.atoms), al = prof.atom_registry.aliases || {};
    const res = new Set();
    for (const a of p.dependencies) {
      const mm = typeof a === "string" ? /^([A-Z_]+):(\S+)$/.exec(a) : null;
      if (!mm || !TYPES.includes(mm[1])) return ["INADMISSIBLE", null];
      if (!(e.authorized_atom_types || []).includes(mm[1])) return ["INADMISSIBLE", null];
      const c = al[a] ?? a; if (!reg.has(c)) return ["INADMISSIBLE", null];
      res.add(c);
    }
    const cnt = {}; for (const c of res) { const t = c.split(":")[0]; cnt[t] = (cnt[t] || 0) + 1; }
    for (const [t, n] of Object.entries(cnt)) if (n > (prof.max_atoms_per_type[t] ?? 0)) return ["INADMISSIBLE", null];
    return ["ADMITTED", res];
  }
  function cov21(req, families, prof, trust) {
    const g0 = engine(req, families, prof);  // reuse the E-1 guard only
    if (g0.stage === "ENGINE_GUARD") return g0;
    const omega = fb(prof.omega_bits), tb = fb(prof.t_base_bits), beta = fb(prof.beta_bits);
    const kU = fb(prof.kappa_unknown_bits), kD = fb(prof.kappa_degraded_bits), gate = fb(prof.unknown_gate_t_bits);
    const material = new Set(prof.material_dependency_types);
    const R = new Set(), fams = {}, elig = [], defeaters = [];
    const g = prof.consequence_gamma_bits[req.action];
    let Tt = NaN; if (g !== undefined) Tt = 1 - (1 - tb) * pexp(-(fb(g) * beta)); else R.add("CONSEQUENCE_CLASS_UNDEFINED");
    const kEff = (Tt === Tt && Tt >= gate) ? 0 : kU;
    for (const fam of [...families].sort((a, b) => cmpBytes(a.family_id, b.family_id))) {
      const byId = Object.fromEntries(fam.members.map((m) => [m.evidence_id, m]));
      let bad = new Set(fam.members.map((m) => m.evidence_id)).size !== fam.members.length;
      const roots = fam.members.filter((m) => m.parent_id === null || !(m.parent_id in byId));
      bad = bad || roots.length !== 1;
      if (!bad) for (const m of fam.members) { let cur = m; const seen = new Set();
        while (cur.evidence_id !== roots[0].evidence_id) { if (seen.has(cur.evidence_id)) { bad = true; break; } seen.add(cur.evidence_id); cur = byId[cur.parent_id]; } }
      if (bad) { fams[fam.family_id] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const prov = Object.fromEntries(fam.members.map((m) => [m.evidence_id, admit(m, trust, prof, req.tau_eval)]));
      const root = roots[0], opt = fam.members.filter((m) => m !== root);
      const outcomes = Object.fromEntries(Object.entries(prov).map(([k, v]) => [k, v[0]]));
      if (Object.values(outcomes).includes("TAMPERED")) { fams[fam.family_id] = { status: "INVALIDATED", outcomes }; R.add("PROVENANCE_TAMPERED"); R.add("FAMILY_INVALIDATED"); continue; }
      const states = opt.map((m) => m.state || "VALID"), rs = root.state || "VALID";
      if (states.includes("INVALID") || rs === "INVALID") { fams[fam.family_id] = { status: "INVALIDATED", outcomes }; R.add("FAMILY_INVALIDATED"); continue; }
      for (const m of opt) if (m.state === "CONTRADICTORY" && prov[m.evidence_id][0] === "ADMITTED") defeaters.push(m.evidence_id);
      if (rs !== "VALID") { fams[fam.family_id] = { status: "REPRESENTATIVE_" + rs, outcomes }; continue; }
      const Vr = fb(root.value_bits);
      if (!(Vr >= 0 && Vr <= 1)) { fams[fam.family_id] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const fac = states.filter((x) => x !== "UNAVAILABLE_OR_STALE").map((x) => x === "DEGRADED" ? kD : x === "VALID" ? 1 : 0);
      let V = Vr * (fac.length ? Math.min(...fac) : 1);
      const [o, atoms] = prov[root.evidence_id];
      let mat = o === "ADMITTED" ? [...atoms].filter((a) => material.has(a.split(":")[0])) : [];
      if (!mat.length) { V = V * kEff; mat = ["UNKNOWN:*"]; }
      const w = V / mat.length;
      fams[fam.family_id] = { status: "ELIGIBLE", outcomes, V_bits: hb(V), share: hb(w), atoms: utf8sort(mat) };
      elig.push({ fid: fam.family_id, mat, w });
    }
    const best = new Map();
    for (const e of elig) for (const a of e.mat) if (!best.has(a) || e.w > best.get(a)) best.set(a, e.w);
    let M = 0; for (const a of [...best.keys()].sort(cmpBytes)) M = M + best.get(a);
    let C = 1 - pexp(-(M / omega));
    if (!elig.length) { R.add("NO_ELIGIBLE_EVIDENCE"); M = 0; C = 0; }
    let res = false;
    if (!Number.isFinite(C) || !Number.isFinite(Tt)) { C = 0; R.add("SAFE_STATE_LOCK"); }
    else { res = C >= Tt; if (!res) R.add("THRESHOLD_NOT_MET"); }
    if (defeaters.length) R.add("DEFEATER_PRESENT");
    return { stage: "PROFILE", fams, eligible: elig.map((e) => e.fid), defeaters: defeaters.length, M: hb(M), C: hb(C), T: hb(Tt),
             decision: res && !defeaters.length && !R.has("CONSEQUENCE_CLASS_UNDEFINED") ? "ALLOW" : "DENY", reasons: REASONS.filter((n) => R.has(n)) };
  }
  const c21p = Object.fromEntries(Object.entries(c21.profiles).map(([k, v]) => [k, v.declaration]));
  for (const [k, v] of Object.entries(c21.profiles)) ok(H(v.declaration) === v.fingerprint, `v0.2.1 profile ${k} fingerprint`);
  for (const c of c21.cases) {
    const e = c.expected_trace, tag = `v0.2.1 ${c.id}`;
    const g = cov21(c.input.request, c.input.families, c21p[c.profile], c.trust_state || c21.trust_state);
    ok(g.decision === e.decision && g.stage === e.stage, `${tag} decision js=${g.decision}`);
    ok(JSON.stringify(g.reasons) === JSON.stringify(e.reason_codes), `${tag} reasons js=${g.reasons}`);
    ok(g.M === e.M_bits && g.C === e.C_bits, `${tag} M/C bits`);
    if (e.stage !== "PROFILE") continue;
    ok(g.defeaters === e.defeaters.length && JSON.stringify(g.eligible) === JSON.stringify(e.eligible_families), `${tag} defeaters/eligible`);
    for (const [fid, ef] of Object.entries(e.families)) {
      const gf = g.fams[fid] || {};
      ok(gf.status === ef.status, `${tag} ${fid} status js=${gf.status}`);
      if (ef.provenance) for (const [eid, po] of Object.entries(ef.provenance)) ok(gf.outcomes && gf.outcomes[eid] === po.outcome, `${tag} ${eid} provenance js=${gf.outcomes && gf.outcomes[eid]} py=${po.outcome}`);
      if (ef.status === "ELIGIBLE") ok(gf.V_bits === ef.V_bits && gf.share === ef.per_atom_share_bits && JSON.stringify(gf.atoms) === JSON.stringify(ef.atoms), `${tag} ${fid} values`);
    }
  }
  c21.property_witnesses.forEach((w, i) => {
    const t0 = cov21(w.request, w.base, c21p.calibrated, c21.trust_state), t1 = cov21(w.request, [...w.base, w.added], c21p.calibrated, c21.trust_state);
    ok(t0.M === w.M_base_bits && t1.M === w.M_after_bits, `v0.2.1 witness ${i} bits`);
    const prop = { monotone: fb(t1.M) >= fb(t0.M) && !(t0.decision === "ALLOW" && t1.decision === "DENY"), idempotent: t1.M === t0.M, defeater: t1.decision === "DENY" }[w.kind];
    ok(prop, `v0.2.1 witness ${i} (${w.kind})`);
  });
  ok(c21.known_exploits_open.length === 0, "v0.2.1 has no open exploits");
  console.log(`coverage-v0.2.1: ${c21.cases.length} cases, ${c21.property_witnesses.length} witnesses, provenance admissibility re-derived independently`);
  // ---------- coverage-v0.3.0-alpha: M-1 membership manifests + A-1 adverse disposition (independent) ----------
  const c30 = JSON.parse(readFileSync(T("vectors/scoring_coverage_v0.3.0-alpha.json"), "utf8"));
  const MEMB_DOMAIN = "PROVENANCE-RAZOR-MEMBERSHIP-V0.3.0-Alpha";
  const memberOk = (m) => KS.map(m) && KS.str(m.evidence_id) && "parent_id" in m && (m.parent_id === null || KS.str(m.parent_id))
    && KS.str(m.producer) && typeof m.value_bits === "string" && /^[0-9a-f]{16}$/.test(m.value_bits)
    && (!("state" in m) || ["VALID", "UNAVAILABLE_OR_STALE", "DEGRADED", "CONTRADICTORY", "INVALID"].includes(m.state))
    && (!("dependencies" in m) || Array.isArray(m.dependencies));
  function membership(fam, ts, tauEval) {
    const env = fam.manifest;
    if (env === undefined) return ["UNVERIFIED", [], 0, ""];
    if (!envelopeOk(env) || !schemaValid(env.payload, "manifest")) return ["TAMPERED", [], 0, ""];
    const p = env.payload;
    if (p.domain !== MEMB_DOMAIN) return ["TAMPERED", [], 0, ""];
    const e = ts.key_registry[p.membership_key_id];
    if (!e) return ["UNVERIFIED", [], 0, ""];
    if (e.domain !== "membership" || !edVerify(e.public_key, H(p), env.signature) || p.authority_id !== e.owner || p.family_id !== fam.family_id)
      return ["TAMPERED", [], 0, ""];
    const ids = p.members.map((m) => m.evidence_id);
    if (JSON.stringify(ids) !== JSON.stringify(utf8sort(new Set(ids)))) return ["TAMPERED", [], 0, ""];
    if (!e.epochs.includes(p.membership_trust_epoch) || (ts.revoked_manifest_ids || []).includes(p.manifest_id)
        || !(p.tau_issued <= tauEval && tauEval <= p.tau_expiry) || !(e.membership_scopes || []).some((pat) => glob(fam.family_id, pat)))
      return ["UNVERIFIED", [], 0, ""];
    const listed = Object.fromEntries(p.members.map((m) => [m.evidence_id, m]));
    const groups = new Map();
    for (const m of fam.members) groups.set(m.evidence_id, [...(groups.get(m.evidence_id) || []), m]);
    const admitted = []; let quarantined = 0, altered = false;
    for (const [eid, cands] of groups) {
      if (!(eid in listed)) { quarantined += cands.length; continue; }
      const match = cands.filter((m) => H(core(m)) === listed[eid].evidence_digest && m.parent_id === listed[eid].parent_id);
      if (match.length) { admitted.push(match[0]); quarantined += cands.length - 1; } else altered = true;
    }
    if (altered) return ["TAMPERED", [], quarantined, p.ingress_channel];
    if (Object.keys(listed).some((eid) => !groups.has(eid))) return ["UNVERIFIED", [], quarantined, p.ingress_channel];
    return ["VERIFIED", admitted, quarantined, p.ingress_channel];
  }
  const PREC = { CLEAR: 0, CONTAIN: 1, DEFEAT: 2, LOCK: 3 };
  function cov30(req, families, prof, ts) {
    // E-1 guard (independent): any non-finite binary64 input anywhere -> DENY before profile logic
    const hexOk = (h) => typeof h === "string" && /^[0-9a-f]{16}$/.test(h);
    const nonfin = [...Object.entries(prof).filter(([k, v]) => k.endsWith("_bits") && typeof v === "string").map(([, v]) => v),
      ...Object.values(prof.consequence_gamma_bits || {}),
      ...families.filter((f) => KS.map(f) && Array.isArray(f.members)).flatMap((f) => f.members.filter((m) => KS.map(m) && hexOk(m.value_bits)).map((m) => m.value_bits))]
      .some((h) => !Number.isFinite(fb(h)));
    if (nonfin) return { stage: "ENGINE_GUARD", M: hb(0), C: hb(0), decision: "DENY", reasons: ["SAFE_STATE_LOCK", "NONFINITE_INPUT"] };
    const f64 = (h) => fb(h);
    const omega = f64(prof.omega_bits), tb = f64(prof.t_base_bits), tbm = f64(prof.t_base_manual_bits), beta = f64(prof.beta_bits);
    const kU = f64(prof.kappa_unknown_bits), kD = f64(prof.kappa_degraded_bits), gate = f64(prof.unknown_gate_t_bits);
    const material = new Set(prof.material_dependency_types);
    const R = new Set(), fams = {}, elig = []; let disp = "CLEAR", quarantined = 0; const obl = new Map();
    const raise = (l) => { if (PREC[l] > PREC[disp]) disp = l; };
    const g = prof.consequence_gamma_bits[req.action];
    let Tt = NaN, Tm = NaN;
    if (g !== undefined) { Tt = 1 - (1 - tb) * pexp(-(f64(g) * beta)); Tm = 1 - (1 - tbm) * pexp(-(f64(g) * beta)); } else R.add("CONSEQUENCE_CLASS_UNDEFINED");
    const kEff = (Tt === Tt && Tt >= gate) ? 0 : kU;
    const bind = { action: req.action, assertion: req.assertion, target: req.target, evidence_snapshot_id: req.evidence_snapshot_id };
    const good = [];
    for (const f of families) { if (KS.map(f) && KS.str(f.family_id) && Array.isArray(f.members)) good.push(f); else R.add("LINEAGE_CLASS_MALFORMED"); }
    for (const fam0 of good.sort((a, b) => cmpBytes(a.family_id, b.family_id))) {
      const fid = fam0.family_id;
      quarantined += fam0.members.filter((m) => !memberOk(m)).length;
      const fam = { ...fam0, members: fam0.members.filter(memberOk) };
      const [mo, members, q, ingress] = membership(fam, ts, req.tau_eval);
      quarantined += q;
      if (mo === "UNVERIFIED") { fams[fid] = { status: "MEMBERSHIP_UNVERIFIED" }; R.add("MEMBERSHIP_UNVERIFIED"); continue; }
      if (mo === "TAMPERED") { fams[fid] = { status: "INVALIDATED" }; R.add("MEMBERSHIP_TAMPERED"); R.add("FAMILY_INVALIDATED"); continue; }
      const byId = Object.fromEntries(members.map((m) => [m.evidence_id, m]));
      const roots = members.filter((m) => m.parent_id === null || !(m.parent_id in byId));
      let bad = roots.length !== 1;
      if (!bad) for (const m of members) { let cur = m; const seen = new Set();
        while (cur.evidence_id !== roots[0].evidence_id) { if (seen.has(cur.evidence_id)) { bad = true; break; } seen.add(cur.evidence_id); cur = byId[cur.parent_id]; } }
      if (bad) { fams[fid] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const prov = Object.fromEntries(members.map((m) => [m.evidence_id, admit(m, ts, ts, req.tau_eval)]));
      for (const m of members) {
        if (m.state !== "CONTRADICTORY") continue;
        const o = prov[m.evidence_id][0];
        if (o === "TAMPERED") { raise("LOCK"); continue; }
        if (!(ts.conflict_types || []).includes(m.conflict_type) || !same(m.contradicts, bind)) continue;
        const lvl = o === "ADMITTED" ? "DEFEAT" : "CONTAIN";
        raise(lvl);
        const dg = H({ conflict_type: m.conflict_type ?? null, contradicts: m.contradicts ?? null, claim: m.claim ?? null });
        const rec = obl.get(dg) || { lvl, n: 0 };
        if (PREC[lvl] > PREC[rec.lvl]) rec.lvl = lvl;
        rec.n++; obl.set(dg, rec);
      }
      if (Object.values(prov).some((v) => v[0] === "TAMPERED")) { fams[fid] = { status: "INVALIDATED" }; R.add("PROVENANCE_TAMPERED"); R.add("FAMILY_INVALIDATED"); continue; }
      const root = roots[0], states = members.filter((m) => m !== root).map((m) => m.state || "VALID"), rs = root.state || "VALID";
      if (states.includes("INVALID") || rs === "INVALID") { fams[fid] = { status: "INVALIDATED" }; R.add("FAMILY_INVALIDATED"); continue; }
      if (rs !== "VALID") { fams[fid] = { status: "REPRESENTATIVE_" + rs }; continue; }
      const Vr = f64(root.value_bits);
      if (!(Vr >= 0 && Vr <= 1)) { fams[fid] = { status: "MALFORMED" }; R.add("LINEAGE_CLASS_MALFORMED"); continue; }
      const fac = states.filter((x) => x !== "UNAVAILABLE_OR_STALE" && x !== "CONTRADICTORY").map((x) => x === "DEGRADED" ? kD : 1);
      let V = Vr * (fac.length ? Math.min(...fac) : 1);
      const [o, atoms] = prov[root.evidence_id];
      let mat = o === "ADMITTED" ? [...atoms].filter((a) => material.has(a.split(":")[0])) : [];
      if (!mat.length) { V = V * kEff; mat = ["UNKNOWN:*"]; }
      fams[fid] = { status: "ELIGIBLE", V_bits: hb(V), atoms: utf8sort(mat) };
      elig.push({ fid, mat, w: V / mat.length });
    }
    const best = new Map();
    for (const e of elig) for (const a of e.mat) if (!best.has(a) || e.w > best.get(a)) best.set(a, e.w);
    let M = 0; for (const a of [...best.keys()].sort(cmpBytes)) M = M + best.get(a);
    let C = 1 - pexp(-(M / omega));
    if (!elig.length) { R.add("NO_ELIGIBLE_EVIDENCE"); M = 0; C = 0; }
    const excep = !Number.isFinite(C) || !Number.isFinite(Tt);
    if (excep) { raise("LOCK"); C = 0; }
    let decision;
    if (disp === "LOCK") { decision = "DENY"; R.add("SAFE_STATE_LOCK"); }
    else if (disp === "DEFEAT") { decision = "DENY"; R.add("DEFEATER_PRESENT"); }
    else if (disp === "CONTAIN") { R.add("ADVERSE_CONTAINMENT"); if (C >= Tm) decision = "MANUAL_REQUIRED"; else { decision = "DENY"; R.add("THRESHOLD_NOT_MET"); } }
    else { if (C >= Tt) decision = "ALLOW"; else { decision = "DENY"; R.add("THRESHOLD_NOT_MET"); } }
    if (R.has("CONSEQUENCE_CLASS_UNDEFINED")) decision = "DENY";
    const cont = [...obl.entries()].filter(([, r]) => r.lvl === "CONTAIN").map(([d]) => d).sort();
    return { stage: "PROFILE", fams, disp, M: hb(M), C: hb(C), decision, reasons: REASONS.filter((n) => R.has(n)), quarantined,
             obligations: obl.size, occurrences: [...obl.values()].reduce((a, r) => a + r.n, 0),
             containment: cont.length ? H(cont) : NULL_CONTAINMENT, eligible: elig.map((e) => e.fid) };
  }
  ok(H(c30.scoring_profile_declaration) === c30.scoring_profile_hash && H(c30.trust_state) === c30.trust_state_hash, "v0.3.0 hashes");
  for (const c of c30.cases) {
    const e = c.expected_trace, tag = `v0.3.0 ${c.id}`;
    if (e.stage === "VERIFIER_FAULT") continue;
    const gt = cov30(c.input.request, c.input.families, c30.scoring_profile_declaration, c.trust_state || c30.trust_state);
    ok(gt.decision === e.decision && gt.stage === e.stage, `${tag} decision js=${gt.decision} py=${e.decision}`);
    ok(JSON.stringify(gt.reasons) === JSON.stringify(e.reason_codes), `${tag} reasons js=${gt.reasons} py=${e.reason_codes}`);
    ok(gt.M === e.M_bits && gt.C === e.C_bits, `${tag} M/C bits`);
    if (e.stage !== "PROFILE") continue;
    ok(gt.disp === e.adverse_disposition && gt.containment === e.containment_digest, `${tag} disposition js=${gt.disp}`);
    ok(gt.obligations === e.adverse_obligations.length && gt.occurrences === e.adverse_obligations.reduce((a, o) => a + o.occurrences.length, 0), `${tag} obligations`);
    ok(gt.quarantined === e.audit_events.filter((a) => a.event === "MEMBER_QUARANTINED").length, `${tag} quarantine count js=${gt.quarantined}`);
    ok(JSON.stringify(gt.eligible) === JSON.stringify(e.eligible_families), `${tag} eligible`);
    for (const [fid, ef] of Object.entries(e.families)) {
      const gf = gt.fams[fid] || {};
      ok(gf.status === ef.status, `${tag} ${fid} status js=${gf.status} py=${ef.status}`);
      if (ef.status === "ELIGIBLE") ok(gf.V_bits === ef.V_bits && JSON.stringify(gf.atoms) === JSON.stringify(ef.atoms), `${tag} ${fid} values`);
    }
  }
  c30.property_witnesses.forEach((w, i) => {
    const t0 = cov30(w.request, w.base, c30.scoring_profile_declaration, c30.trust_state);
    const t1 = cov30(w.request, w.after, c30.scoring_profile_declaration, c30.trust_state);
    ok(t0.M === w.M_base_bits && t1.M === w.M_after_bits && t0.C === w.C_base_bits && t1.C === w.C_after_bits, `v0.3.0 witness ${i} bits`);
    ok(t0.decision === w.decision_base && t1.decision === w.decision_after, `v0.3.0 witness ${i} decisions`);
  });
  console.log(`coverage-v0.3.0: ${c30.cases.length} cases, ${c30.property_witnesses.length} witnesses; membership, containment and defeat re-derived independently`);
  console.log(`scoring: prc_exp matches published bits on every input; platform Math.exp differs from the published libm reference on ${expMismatchLibm} of ${sc.prc_exp_v1.vectors.length} inputs`);
}

console.log(`xcheck (JavaScript, independent): ${checks} checks, ${fails.length} failures`);
for (const f of fails) console.log("  FAIL", f);
process.exit(fails.length ? 1 : 0);
