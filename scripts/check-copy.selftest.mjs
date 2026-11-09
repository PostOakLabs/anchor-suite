// check-copy.selftest.mjs — ANCHOR-COPY-GATE-1. Runs check-copy.mjs against
// throwaway fixture trees (--root) and asserts the exit code: the passing
// fixture exits 0, every failing fixture exits nonzero with its expected line.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const GATE = join(dirname(fileURLToPath(import.meta.url)), 'check-copy.mjs');

const GOOD_SECTION = `<h2>Anchor on your own chain</h2>
<p>Record the receipt hash on Base yourself; your wallet signs and pays. The page names the chain (Base) and checks the finalized level.
This is ledger ordering, first writer wins, and the verifier picks the RPC. The chosen RPC operator sees the queried hash.
This is not legal advice and it is not a qualified timestamp.</p>`;

const CASES = [
  { name: 'passing: full caveat set, negated banned phrase', pass: true, html: GOOD_SECTION },
  { name: 'passing: Base record stated as not independent', pass: true, html: GOOD_SECTION + '<p>A Base record is not independent of the Coinbase sequencer.</p>' },
  { name: 'passing: page with no anchor scope is ignored', pass: true, html: '<p>This receipt is certified by nobody and tamper-proof marketing words stay out of scope.</p>' },
  { name: 'failing: tamper-proof', pass: false, expect: 'tamper-proof', html: GOOD_SECTION + '<p>A tamper-proof record on Base.</p>' },
  { name: 'failing: gasless', pass: false, expect: 'gasless', html: GOOD_SECTION + '<p>Gasless anchoring on Base.</p>' },
  { name: 'failing: we anchor it for you', pass: false, expect: 'we anchor it for you', html: GOOD_SECTION + '<p>We anchor it for you on Base.</p>' },
  { name: 'failing: Base independent of sequencer', pass: false, expect: 'Base independent', html: GOOD_SECTION + '<p>The Base leg is an independent witness.</p>' },
  { name: 'failing: implied signer', pass: false, expect: 'implied signer', html: GOOD_SECTION + '<p>The EAS timestamp identifies the committer.</p>' },
  { name: 'failing: missing not-legal-advice', pass: false, expect: '"not legal advice"', html: GOOD_SECTION.replace('This is not legal advice and it', 'It') },
  { name: 'failing: missing RPC operator caveat', pass: false, expect: 'RPC operator sees', html: GOOD_SECTION.replace('The chosen RPC operator sees the queried hash.', '') },
  { name: 'failing: missing finalized level', pass: false, expect: 'finalized level', html: GOOD_SECTION.replace('checks the finalized level', 'checks the block') },
];

let bad = 0;
for (const c of CASES) {
  const root = mkdtempSync(join(tmpdir(), 'copy-selftest-'));
  try {
    mkdirSync(join(root, 'public'));
    writeFileSync(join(root, 'public', 'page.html'), `<html><body>${c.html}</body></html>`);
    const r = spawnSync(process.execPath, [GATE, '--root', root], { encoding: 'utf8' });
    const out = (r.stdout || '') + (r.stderr || '');
    const ok = c.pass ? r.status === 0 : r.status !== 0 && out.includes(c.expect);
    console.log(`${ok ? '✓' : '✗'} ${c.name}`);
    if (!ok) { bad++; console.log('  exit ' + r.status + ': ' + out.slice(0, 400)); }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
if (bad) { console.error(`${bad} selftest case(s) failed`); process.exit(1); }
console.log(`check-copy selftest: ${CASES.length} cases ok`);
