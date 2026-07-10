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
  'check-secrets.mjs',
  'gate-tst-verify.mjs',
  'gate-verify-assertion.mjs',
  'gate-merkle-batch.mjs',
  'gate-batch-inclusion-roundtrip.mjs',
  'gate-escalation-closure.mjs',
];

let failed = 0;
for (const gate of GATES) {
  console.log(`\n=== ${gate} ===`);
  const r = spawnSync(process.execPath, [join(HERE, gate)], { stdio: 'inherit' });
  if (r.status !== 0) failed++;
}

if (failed) {
  console.error(`\n${failed} gate(s) red`);
  process.exit(1);
}
console.log('\nall gates green');
