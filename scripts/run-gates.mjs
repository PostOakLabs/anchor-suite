// run-gates.mjs — run every deterministic CI gate locally, in order, and fail
// on the first red. The TSA smoke harness is separate (scripts/smoke-tsa.mjs)
// because it talks to third parties.

import { spawnSync } from 'child_process';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const GATES = [
  'check-dead-links.mjs',
  'check-no-inline-scripts.mjs',
  'check-copy.mjs',
  'check-root-freshness.mjs',
  'check-vendor-freshness.mjs',
  { file: 'check-credits-coverage.mjs', args: ['anchor-suite'] },
  { file: 'gen-credits.mjs', args: ['anchor-suite', '--check'] },
  'check-secrets.mjs',
  'gate-tst-verify.mjs',
  'gate-verify-assertion.mjs',
  'gate-merkle-batch.mjs',
  'gate-batch-inclusion-roundtrip.mjs',
  'gate-escalation-closure.mjs',
  'gate-mcp-era.mjs',
  'gate-sigsum-budget-counter.mjs',
  'gate-sigsum-session-token.mjs',
  'gate-sigsum-quorum-lifecycle.mjs',
  'gate-ots-calendar-allowlist.mjs',
];

let failed = 0;
for (const entry of GATES) {
  const file = typeof entry === 'string' ? entry : entry.file;
  const args = typeof entry === 'string' ? [] : entry.args;
  console.log(`\n=== ${file}${args.length ? ' ' + args.join(' ') : ''} ===`);
  const r = spawnSync(process.execPath, [join(HERE, file), ...args], { stdio: 'inherit' });
  if (r.status !== 0) failed++;
}

if (failed) {
  console.error(`\n${failed} gate(s) red`);
  process.exit(1);
}
console.log('\nall gates green');
