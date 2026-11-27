// gate-dual-verifier.mjs — the vendored risc0 seal verifier carries BOTH parameter sets
// (RISC0-310-R4-VENDOR-ANCHOR-1; mirrors the site's scripts/dual-verifier.test.mjs).
// current = risc0 3.1.0 set (art-313 pilot receipt), legacy = risc0 3.0.x set (art-503 receipt),
// invalid = tampered journal, or an imageId in neither closed allowlist.
// Run: node scripts/gate-dual-verifier.mjs   (exit 0 = all cases pass)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  verifySeal, verifySealReport, sealParameterSet, LEGACY_IMAGE_IDS, CURRENT_IMAGE_IDS,
} from '../public/vendor/ocg/lib/_computeproof.mjs';

const FIX = resolve(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'dual-verifier');
const read = (f) => JSON.parse(readFileSync(resolve(FIX, f), 'utf8'));

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.error('  ✗ ' + m); } else console.log('  ✓ ' + m); };

const NEW = read('art-313-current.receipt.json');
const OLD = read('art-503-legacy.receipt.json');
const tamperJournal = (cp) => { const t = structuredClone(cp); t.journal.output = { ...t.journal.output, __tamper_probe: true }; return t; };

ok(LEGACY_IMAGE_IDS.length === 7 && CURRENT_IMAGE_IDS.length === 8, 'allowlists hold 7 legacy and 8 current image ids');
ok(!LEGACY_IMAGE_IDS.some((id) => CURRENT_IMAGE_IDS.includes(id)), 'allowlists are disjoint');
ok(sealParameterSet(NEW.imageId) === 'current' && sealParameterSet(OLD.imageId) === 'legacy', 'fixtures carry one id from each list');

ok(verifySealReport(NEW) === 'current' && verifySeal(NEW) === true, 'art-313 pilot receipt reads current');
ok(verifySealReport(OLD) === 'legacy' && verifySeal(OLD) === true, 'old receipt reads legacy');
ok(verifySealReport(tamperJournal(NEW)) === 'invalid' && verifySeal(tamperJournal(NEW)) === false, 'tampered journal (current set) reads invalid');
ok(verifySealReport(tamperJournal(OLD)) === 'invalid', 'tampered journal (legacy set) reads invalid');
ok(verifySealReport({ ...NEW, imageId: OLD.imageId }) === 'invalid', 'new seal under an old id reads invalid (crossed set)');
ok(verifySealReport({ ...OLD, imageId: NEW.imageId }) === 'invalid', 'old seal under a new id reads invalid (crossed set)');
for (const id of ['sha256:d022c4822d2fee377994fcc2aa06d8b004c2c2709cc128a6428b8f9bcfa07988', 'sha256:' + 'b'.repeat(64)]) {
  ok(sealParameterSet(id) === null && verifySealReport({ ...NEW, imageId: id }) === 'invalid' && verifySeal({ ...NEW, imageId: id }) === false,
    `imageId ${id.slice(0, 15)}… in neither list reads invalid`);
}

console.log(fail ? `\n✗ ${fail} FAILED` : '\n✓ dual-verifier gate passed');
process.exit(fail ? 1 : 0);
