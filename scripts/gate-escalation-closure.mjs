// gate-escalation-closure.mjs — OCG SPEC.md §22.8.4 closure verification gate.
//
// Verifies verify_escalation_closure against a real passkey closure envelope (the demo
// dora-escalation-demo escalation record, closed via Anchorproof). Asserts:
//   1. the genuine closure verifies (valid === true, all checks pass);
//   2. tamper-evidence: mutating the halted steps, the decision object, or the
//      record_hash makes the recomputed hash diverge and the closure INVALID;
//   3. a non-approve/reject decision is rejected.
// Runs offline (WebAuthn assertion verify is pure WebCrypto; anchor-binding checks do not
// gate signature validity).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toolVerifyEscalationClosure } from '../src/worker.mjs';

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

if (failed) {
  console.error(`\ngate-escalation-closure: ${failed} check(s) failed`);
  process.exit(1);
}
console.log('\ngate-escalation-closure: all checks green');
