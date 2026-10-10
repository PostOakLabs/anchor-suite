// gate-escalation-closure.mjs — OCG SPEC.md §22.8.4 closure verification gate.
//
// Verifies verify_escalation_closure against a real passkey closure envelope (the demo
// dora-escalation-demo escalation record, closed via Anchorproof). Asserts:
//   1. the genuine closure verifies (valid === true, all checks pass, verdict 'valid',
//      canonicalization 'rfc8785');
//   2. tamper-evidence: mutating the halted steps, the decision object, or the
//      record_hash makes the recomputed hash diverge and the closure INVALID;
//   3. a non-approve/reject decision is rejected;
//   4. ANCHOR-CANON-ALIGN-1: a synthetic record with array-index member names
//      (decision.observed_value {"9":1,"10":2}) closed over its LEGACY
//      (pre-2026-09-30 enumeration order) hash returns valid:false with the distinct
//      verdict 'valid-legacy-order' (fail-closed), and the same record with one halted
//      step changed returns verdict 'invalid';
//   5. the six RFC 8785 probe vectors (copied from the site repo, see the fixture's
//      _provenance line) serialize through the vendored jcsStringify to their
//      hand-written expected strings.
// Runs offline (WebAuthn assertion verify is pure WebCrypto; anchor-binding checks do not
// gate signature validity).
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toolVerifyEscalationClosure } from '../src/worker.mjs';
import { buildAssertion } from './gate-verify-assertion.mjs';
import { bytesToBase64 } from '../public/lib/anchorproof.mjs';
import { jcsStringify } from '../public/vendor/ocg/lib/_hash.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(HERE, '..', 'tests', 'fixtures', 'escalation-closure.fixture.json'), 'utf8'),
);

let failed = 0;
function check(name, cond) {
  console.log(`  ${cond ? 'OK  ' : 'FAIL'} ${name}`);
  if (!cond) failed++;
}
const clone = (o) => JSON.parse(JSON.stringify(o));

// 1) Genuine closure verifies.
const good = await toolVerifyEscalationClosure({
  escalation_record: fixture.escalation_record,
  closure: fixture.closure,
});
check('genuine closure valid', good.valid === true);
check('record_hash_recompute ok', good.checks.find((c) => c.name === 'record_hash_recompute')?.ok === true);
check('envelope_binds_record_hash ok', good.checks.find((c) => c.name === 'envelope_binds_record_hash')?.ok === true);
check('signature_valid ok', good.checks.find((c) => c.name === 'signature_valid')?.ok === true);
check('decision_valid ok', good.checks.find((c) => c.name === 'decision_valid')?.ok === true);
check('recomputed record_hash matches fixture', good.record_hash === fixture.closure.record_hash);
// (a) ANCHOR-CANON-ALIGN-1: the genuine demo record carries no array-index member names,
// so both orders agree and the RFC 8785 hash must match directly.
check('genuine closure verdict valid', good.verdict === 'valid');
check('genuine closure canonicalization rfc8785', good.canonicalization === 'rfc8785');

// 2a) Tamper the halted steps → record hash diverges → invalid.
const t1 = clone(fixture);
t1.escalation_record.halted_steps = [...t1.escalation_record.halted_steps, 'art-99-injected'];
const tamperedSteps = await toolVerifyEscalationClosure({ escalation_record: t1.escalation_record, closure: t1.closure });
check('tampered halted_steps → invalid', tamperedSteps.valid === false);
check('tampered halted_steps → record_hash check fails', tamperedSteps.checks.find((c) => c.name === 'record_hash_recompute')?.ok === false);

// 2b) Tamper the decision object → record hash diverges → invalid.
const t2 = clone(fixture);
t2.escalation_record.decision.observed_value = 'A';
const tamperedDecision = await toolVerifyEscalationClosure({ escalation_record: t2.escalation_record, closure: t2.closure });
check('tampered decision → invalid', tamperedDecision.valid === false);

// 2c) Tamper the closure record_hash → binding + recompute fail → invalid.
const t3 = clone(fixture);
t3.closure.record_hash = '0'.repeat(64);
const tamperedHash = await toolVerifyEscalationClosure({ escalation_record: t3.escalation_record, closure: t3.closure });
check('tampered closure record_hash → invalid', tamperedHash.valid === false);

// 3) Non-approve/reject decision rejected.
const t4 = clone(fixture);
t4.closure.decision = 'maybe';
const badDecision = await toolVerifyEscalationClosure({ escalation_record: t4.escalation_record, closure: t4.closure });
check('invalid decision value → invalid', badDecision.valid === false);
check('invalid decision → decision check fails', badDecision.checks.find((c) => c.name === 'decision_valid')?.ok === false);

// 4) ANCHOR-CANON-ALIGN-1 — legacy-order retry, reported as a distinct verdict.
//
// (b) A synthetic record whose decision.observed_value is {"9":1,"10":2} (array-index
//     member names). RFC 8785 sorts them by UTF-16 code unit ("10" before "9"); the
//     pre-2026-09-30 canonicalizer rebuilt an object whose engine enumeration is
//     numeric ("9" before "10"), so the two hashes disagree. Closing over the LEGACY
//     hash must produce valid:false (fail-closed) with verdict 'valid-legacy-order'.
//     The test-local legacy canonicalizer is deliberate: worker.mjs keeps its legacy
//     helper private, and pinning the legacy order is exactly what this case is for.
const legacyCanon = (v) =>
  Array.isArray(v) ? v.map(legacyCanon)
  : (v && typeof v === 'object')
    ? Object.keys(v).sort().reduce((o, k) => (o[k] = legacyCanon(v[k]), o), {})
    : v;
async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const legacyRecord = {
  decision: {
    input_pointer: '/grade',
    matched_rule_index: 0,
    next: 'escalate',
    observed_value: { '9': 1, '10': 2 },
    op: 'eq',
    step_id: 'art-29-dora-readiness-diagnostic',
    value: 'F',
  },
  halted_steps: ['art-09-dora-incident-classifier'],
};
const legacyPreimage = { decision: legacyRecord.decision, halted_steps: legacyRecord.halted_steps };
const legacyHash = await sha256Hex(JSON.stringify(legacyCanon(legacyPreimage)));

// Fresh P-256 key, and the signing message formed exactly the way gate-verify-assertion
// forms it for a doc_digest (JSON with doc_digest/envelope_id/role/signed_at).
const legacyKp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const legacySpkiB64 = bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', legacyKp.publicKey)));
const legacySigningMessage = JSON.stringify({
  doc_digest: 'sha256:' + legacyHash,
  envelope_id: 'esc-legacy-order-1',
  role: 'signer',
  signed_at: '2026-10-07T00:00:00Z',
});
const legacyBuilt = await buildAssertion(legacyKp.privateKey, legacySigningMessage);
const legacyClosure = {
  record_hash: legacyHash,
  decision: 'approve',
  envelope: {
    version: '1',
    envelope_id: 'esc-legacy-order-1',
    doc_digest: 'sha256:' + legacyHash,
    role: 'Signer',
    signed_at: '2026-10-07T00:00:00Z',
    credential_pubkey: legacySpkiB64,
    assertion: legacyBuilt.assertionDer,
  },
};

const legacyRes = await toolVerifyEscalationClosure({ escalation_record: legacyRecord, closure: legacyClosure });
check('legacy-order closure valid: false (fail-closed)', legacyRes.valid === false);
check('legacy-order closure verdict valid-legacy-order', legacyRes.verdict === 'valid-legacy-order');
check('legacy-order closure canonicalization legacy-pre-2026-09-30', legacyRes.canonicalization === 'legacy-pre-2026-09-30');
check('legacy-order record_hash_recompute ok (legacy order matched)', legacyRes.checks.find((c) => c.name === 'record_hash_recompute')?.ok === true);
check('legacy-order record-hash detail names the legacy canonicalization', /pre-2026-09-30 canonicalization/.test(legacyRes.checks.find((c) => c.name === 'record_hash_recompute')?.detail || ''));
check('legacy-order record_hash is the matched (legacy) hash', legacyRes.record_hash === legacyHash);
check('legacy-order record_hash_rfc8785 differs from the legacy hash', legacyRes.record_hash_rfc8785 !== legacyHash);

// (c) Same legacy case with one halted step changed: neither order matches → 'invalid'.
const tamperedLegacyRecord = clone(legacyRecord);
tamperedLegacyRecord.halted_steps = [...tamperedLegacyRecord.halted_steps, 'art-99-injected'];
const tamperedLegacyRes = await toolVerifyEscalationClosure({ escalation_record: tamperedLegacyRecord, closure: legacyClosure });
check('legacy-order tampered halted_steps → invalid', tamperedLegacyRes.valid === false);
check('legacy-order tampered halted_steps → verdict invalid', tamperedLegacyRes.verdict === 'invalid');
check('legacy-order tampered halted_steps → canonicalization none', tamperedLegacyRes.canonicalization === 'none');

// 5) (d) RFC 8785 probe vectors (site repo origin; see the fixture's _provenance line).
const probes = JSON.parse(
  readFileSync(join(HERE, '..', 'tests', 'fixtures', 'jcs-ocg-probes.json'), 'utf8'),
);
check('probe fixture carries the six RFC 8785 cases', Array.isArray(probes.probes) && probes.probes.length === 6);
for (const p of probes.probes) {
  let ok = false;
  try { ok = jcsStringify(JSON.parse(p.input)) === p.expected; } catch { ok = false; }
  check(`probe ${p.id}: jcsStringify matches expected`, ok);
}

if (failed) {
  console.error(`\ngate-escalation-closure: ${failed} check(s) failed`);
  process.exit(1);
}
console.log('\ngate-escalation-closure: all checks green');
