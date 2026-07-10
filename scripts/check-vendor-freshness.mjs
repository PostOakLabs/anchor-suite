// check-vendor-freshness.mjs — pin every vendored OCG file to its recorded
// SHA-256 in VENDORED.md. VENDORED.md's own text asserts these files are
// "byte-identical" copies of the upstream OCG bundle; this gate makes that
// claim enforceable, so a silent local edit (or a partial re-vendor) to a
// verify-path file under public/vendor/ocg/ can never land unnoticed.
//
// AUD-C3 (concern 3/4): the vendored public/vendor/ocg/lib/_proof.mjs is a
// SNAPSHOT of the canonical §16 signer/verifier. Its single-proof `verify`
// remains behaviourally identical to source (shared-vector bakeoff: valid
// ACCEPT + tampered REJECT on both), but the snapshot predates §16.5 proof
// sets, so it lacks `verifyProofs`/`addProof`. anchor's verify.mjs only calls
// the single `verify`, so there is no accept/reject divergence on the path
// anchor actually uses — the gap is staleness, not a security hole. This gate
// locks the vendored bytes to their audited hashes; a source-sync refresh is
// tracked separately (see VENDORED.md update procedure).

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const VENDORED_MD = join(REPO, 'VENDORED.md');

// Parse the VENDORED.md table: rows of | `path` | ... | `sha256hex` |
function parseRecorded(md) {
  const map = new Map();
  const rowRe = /^\|\s*`([^`]+)`\s*\|.*\|\s*`([0-9a-f]{64})`\s*\|\s*$/gm;
  let m;
  while ((m = rowRe.exec(md))) map.set(m[1].trim(), m[2].trim());
  return map;
}

const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

const recorded = parseRecorded(readFileSync(VENDORED_MD, 'utf8'));

// Every vendored OCG verify-path file the pages load. Must appear in VENDORED.md.
const REQUIRED = [
  'public/vendor/ocg/verify.mjs',
  'public/vendor/ocg/lib/_hash.mjs',
  'public/vendor/ocg/lib/_proof.mjs',
  'public/vendor/ocg/lib/_computeproof.mjs',
  'public/vendor/ocg/lib/_noble-bn254.bundle.mjs',
];

let failures = 0;
const ok = (cond, msg) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${msg}`); if (!cond) failures++; };

console.log('— AUD-C3: vendored OCG freshness (bytes ≡ VENDORED.md hash) —\n');

for (const rel of REQUIRED) {
  const want = recorded.get(rel);
  if (!want) { ok(false, `${rel} — no SHA-256 recorded in VENDORED.md`); continue; }
  let got;
  try { got = sha256Hex(readFileSync(join(REPO, rel))); }
  catch { ok(false, `${rel} — file missing on disk`); continue; }
  ok(got === want, `${rel} — ${got === want ? 'matches recorded hash' : `DRIFT: on-disk ${got.slice(0, 16)}… ≠ recorded ${want.slice(0, 16)}…`}`);
}

// self-proving: a one-byte-mutated buffer MUST hash differently (guards the comparator).
const sample = readFileSync(join(REPO, 'public/vendor/ocg/lib/_proof.mjs'));
const mutated = Buffer.concat([sample, Buffer.from('\n')]);
ok(sha256Hex(sample) !== sha256Hex(mutated), 'self-test: a mutated copy hashes differently (comparator is live)');

console.log(`\n${failures === 0 ? '✅ ALL VENDORED FILES FRESH' : `❌ ${failures} vendored file(s) drifted`}`);
process.exit(failures === 0 ? 0 : 1);
