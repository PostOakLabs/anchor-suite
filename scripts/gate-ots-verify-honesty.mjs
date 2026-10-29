// gate-ots-verify-honesty.mjs — honesty regression gate for the browser OTS
// verifier (public/lib/verify-runner.mjs verifyOts/parseOtsDigest, plus the
// bare-.ots contract of public/js/verify.js).
//
// WHY THIS GATE EXISTS
// --------------------
// Three measured defects (research/borrow-triage-2026-10-29/ots-selfmade-check.md,
// row ANCHOR-VERIFY-OTS-HONESTY-FIX-1), all reproduced on origin/main 2dfa751:
//
// 1. A bare .ots dropped on verify.html was verified against a synthetic
//    all-zero hash, so the library threw "File does not match original!" and
//    EVERY standalone proof read FAIL. The page must check the digest embedded
//    in the proof (or a user-supplied original/hash), never a made-up hash.
// 2. verifyOts treated ANY non-null OT.verify result as complete. A pending
//    proof makes OT.verify resolve {} (an object, therefore non-null), so a
//    pending proof could render as Bitcoin-anchored. Complete now requires at
//    least one verified chain attestation carrying a time.
// 3. README/page copy called verification offline while OT.verify contacts the
//    calendars named in the proof and a block explorer. The copy now says what
//    is contacted and that the file and its hash never leave the browser.
//
// DETERMINISM
// -----------
// Runs the REAL vendored javascript-opentimestamps for parse/digest/mismatch
// cases. Its node HTTP layer fails fast without the (absent) `request` module,
// so no network is attempted and a pending proof deterministically yields {}.
// A genuine Bitcoin-confirmed attestation additionally needs a block-explorer
// header fetch, which cannot run offline, so the complete/error CLASSIFICATION
// is exercised by stubbing only OT.verify's RETURN SHAPE (the shapes are the
// library's documented contract: {bitcoin:{timestamp,height}}, {}, throws).

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const FIX = join(REPO, 'tests', 'fixtures');

let _failed = 0;
function pass(label) { console.log(`  PASS  ${label}`); }
function fail(label, reason) { console.error(`  FAIL  ${label}: ${reason || '?'}`); _failed++; }
function section(s) { console.log(`\n${s}`); }

// Load the vendored library exactly as verify.html loads it (a plain <script>
// setting window.OpenTimestamps); node needs window/self shims first. The
// vendor bundle prints a "request is not installed" notice on load in node;
// silence it so gate output stays clean (the absence of `request` is what
// makes the pending cases network-free).
globalThis.window = globalThis;
globalThis.self = globalThis;
{
  const origErr = console.error;
  console.error = () => {};
  try { (0, eval)(readFileSync(join(REPO, 'public', 'vendor', 'opentimestamps.min.js'), 'utf8')); }
  finally { console.error = origErr; }
}
const REAL_OT = globalThis.OpenTimestamps;
if (!REAL_OT) { console.error('gate-ots-verify-honesty: vendored library did not load'); process.exit(1); }

const { verifyOts, parseOtsDigest } = await import(pathToFileURL(join(REPO, 'public', 'lib', 'verify-runner.mjs')).href);

// ---- fixtures (row step 5: the self-made proof, synthetic file only) --------
// Stamped 2026-10-29 ~13:45 UTC via alice+bob calendars (see the research
// note); sha256 of the files pinned there and re-derived below (SO #34: the
// gate recomputes the digest from the source bytes, it never trusts the
// proof's own claim of it for the source-side assertion). The pending proof
// confirmed on Bitcoin at 2026-10-29T14:24:48Z; the upgraded fixture is the
// same proof after OT.upgrade merged the calendar's Bitcoin attestations
// (captured in-browser, SHA-256 pinned below).
const PROOF = new Uint8Array(readFileSync(join(FIX, 'ots-selfmade-pending.ots')));
const UPGRADED = new Uint8Array(readFileSync(join(FIX, 'ots-selfmade-upgraded.ots')));
const SOURCE = new Uint8Array(readFileSync(join(FIX, 'ots-selfmade-source.txt')));
const PINNED_PROOF_SHA = '494f344f7492a4d0e289dad250641f58c8f873fbdd873fba8d58c306d20781ca';
const PINNED_UPGRADED_SHA = '12517dfef2758229f1a0d0d451de60fa92f591b2c1801a93fbb2c7b95c321e19';
const PINNED_SOURCE_SHA = 'da5c8e2f4f74f23eb271aba00f67e25f37c957237a2bab857aef8db2eb1717b2';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function indexOfBytes(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}

// Stub OT.verify's return/throw while keeping every other real API in place.
function withStubbedVerify(fn, verifyImpl) {
  const stub = Object.assign(Object.create(REAL_OT), { verify: verifyImpl });
  globalThis.OpenTimestamps = stub;
  try {
    return fn();
  } finally {
    globalThis.OpenTimestamps = REAL_OT;
  }
}

// Run a promise with console.log/error from the vendored library's internals
// silenced (it narrates calendar attempts and mismatch throws); failures are
// captured by the assertions, not the narration.
async function quiet(p) {
  const origLog = console.log, origErr = console.error;
  console.log = () => {}; console.error = () => {};
  try { return await p; } finally { console.log = origLog; console.error = origErr; }
}

async function run() {
  section('0. FIXTURE INTEGRITY — fixtures match the pinned reference snapshot');
  {
    const okProof = sha256(PROOF) === PINNED_PROOF_SHA;
    const okUpgraded = sha256(UPGRADED) === PINNED_UPGRADED_SHA;
    const okSource = sha256(SOURCE) === PINNED_SOURCE_SHA;
    if (okProof && okSource && okUpgraded) pass(`pending ${PINNED_PROOF_SHA.slice(0, 12)}..., upgraded ${PINNED_UPGRADED_SHA.slice(0, 12)}..., source ${PINNED_SOURCE_SHA.slice(0, 12)}...`);
    else fail('fixture digest mismatch', JSON.stringify({ proof: sha256(PROOF), upgraded: sha256(UPGRADED), source: sha256(SOURCE) }));
  }

  section('1. EMBEDDED DIGEST — parseOtsDigest names the digest the proof commits to');
  {
    const r = parseOtsDigest(PROOF);
    if (r.ok && r.digestHex === sha256(SOURCE)) pass(`digest ${r.digestHex.slice(0, 16)}... equals sha256(source)`);
    else fail('parseOtsDigest did not return the source digest', JSON.stringify(r));
    // The Bitcoin-upgraded proof must commit to the SAME digest: an upgrade
    // merges attestations, it never rewrites the commitment. No verifyOts
    // status is asserted on the upgraded fixture on purpose: with the network
    // present the library's block-explorer check can confirm the attestation
    // and read complete (observed live in the browser at 2026-10-29T14:24:48Z,
    // see the row's screenshot); offline it reads pending. The
    // complete/pending CLASSIFICATION is pinned deterministically in section 6.
    const u = parseOtsDigest(UPGRADED);
    if (u.ok && u.digestHex === sha256(SOURCE)) pass('upgraded proof commits to the same digest');
    else fail('upgraded proof digest changed', JSON.stringify(u));
  }

  section('2. BARE .ots, REAL LIBRARY, proof with its true source never reads fail (defect 2 regression)');
  {
    // Old code: any non-null OT.verify result -> "complete", genTime
    // String({}) = "[object Object]". OT.verify resolves {} while the proof is
    // pending (observed offline), so the old code read a pending proof as
    // COMPLETE with a garbage time. With the network present the same call
    // upgrades the proof via the proof's calendars and can legitimately read
    // complete (observed live in the browser at 2026-10-29T14:24:48Z) — so the
    // network-independent pin is: never fail against the true source, never
    // pending-with-fake-complete, and complete ONLY carrying a real
    // attestation with a time. The {} -> pending mapping itself is pinned
    // deterministically in section 6.
    const r = await quiet(verifyOts(PROOF, PINNED_SOURCE_SHA));
    if (r.status === 'pending') pass('offline: {} reads pending');
    else if (r.status === 'complete' && Array.isArray(r.attestations) && r.attestations.length > 0
      && !Number.isNaN(Date.parse(r.genTime))) {
      pass(`network: upgraded and confirmed with ${r.attestations.length} attestation(s), genTime ${r.genTime}`);
    } else fail('neither an honest pending nor an attestation-backed complete', JSON.stringify(r));
  }

  section('3. BARE .ots WITH A WRONG SOURCE reads FAIL (defect 1 regression)');
  {
    const wrong = hexToBytes(PINNED_SOURCE_SHA.slice(0, 62) + (PINNED_SOURCE_SHA.slice(62) === 'aa' ? 'bb' : 'aa'));
    const r = await quiet(verifyOts(PROOF, [...wrong].map((b) => b.toString(16).padStart(2, '0')).join('')));
    if (r.status === 'error' && /match/i.test(r.error || '')) pass(`error: ${r.error}`);
    else fail('wrong-source proof did not read fail', JSON.stringify(r));
  }

  section('4. THE OLD SYNTHETIC ZERO HASH still reads FAIL, proving it was never a digest');
  {
    // The pre-fix page verified bare .ots against 64 zeros; every proof failed
    // with exactly this error. Pin that zeros can never verify, so the only
    // route to a pass is the real digest.
    const r = await quiet(verifyOts(PROOF, '0'.repeat(64)));
    if (r.status === 'error' && /match/i.test(r.error || '')) pass(`error: ${r.error}`);
    else fail('zero-hash check did not read fail', JSON.stringify(r));
  }

  section('5. TAMPERED PROOF reads FAIL');
  {
    // (a) broken magic: parse fails outright.
    const badMagic = PROOF.slice(); badMagic[1] ^= 0x01;
    const ra = parseOtsDigest(badMagic);
    const va = await quiet(verifyOts(badMagic, PINNED_SOURCE_SHA));
    if (!ra.ok && va.status === 'error') pass(`tampered magic: ${va.error}`);
    else fail('tampered magic not a clean fail', JSON.stringify({ ra, va }));

    // (b) tampered digest: proof now commits to a different digest than the
    // source, which must read fail against the true source hash.
    const digestBytes = hexToBytes(PINNED_SOURCE_SHA);
    const at = indexOfBytes(PROOF, digestBytes);
    if (at < 0) fail('digest bytes not found in proof (fixture broken?)');
    else {
      const badDigest = PROOF.slice(); badDigest[at] ^= 0x01;
      const rb = parseOtsDigest(badDigest);
      const vb = await quiet(verifyOts(badDigest, PINNED_SOURCE_SHA));
      if (rb.ok && rb.digestHex !== PINNED_SOURCE_SHA && vb.status === 'error' && /match/i.test(vb.error || '')) {
        pass(`tampered digest: ${vb.error}`);
      } else fail('tampered digest not a clean fail', JSON.stringify({ rb, vb }));
    }
  }

  section('6. COMPLETE CLASSIFICATION — only a verified attestation WITH a time reads complete');
  {
    // A Bitcoin-confirmed proof's documented OT.verify shape (javascript-
    // opentimestamps README: {bitcoin:{timestamp,height}}). Stubbed because
    // confirming a real attestation needs the block explorer (network).
    const BTC_TS = 1516803127; // 2018-01-24T14:12:07.000Z, the lib's documented example
    const cases = [
      ['{bitcoin:{timestamp,height}} reads complete', async () => ({ bitcoin: { timestamp: BTC_TS, height: 507478 } }),
        (r) => r.status === 'complete' && r.genTime === '2018-01-24T14:12:07.000Z' && r.attestations?.[0]?.chain === 'bitcoin'],
      ['{} (pending proof) reads pending', async () => ({}), (r) => r.status === 'pending'],
      ['null reads pending', async () => null, (r) => r.status === 'pending'],
      ['attestation WITHOUT a time reads pending', async () => ({ bitcoin: { height: 507478 } }), (r) => r.status === 'pending'],
      ['legacy numeric result reads complete', async () => BTC_TS, (r) => r.status === 'complete' && r.genTime === '2018-01-24T14:12:07.000Z'],
    ];
    for (const [label, impl, ok] of cases) {
      const r = await withStubbedVerify(() => verifyOts(PROOF, PINNED_SOURCE_SHA), impl);
      if (ok(r)) pass(label);
      else fail(label, JSON.stringify(r));
    }
    // A thrown error reads fail with its message (unless pending/calendar).
    const thrown = await withStubbedVerify(() => verifyOts(PROOF, PINNED_SOURCE_SHA),
      async () => { throw new Error('File does not match original!'); });
    if (thrown.status === 'error' && /match/i.test(thrown.error || '')) pass('thrown mismatch reads fail');
    else fail('thrown mismatch misclassified', JSON.stringify(thrown));
    const cal = await withStubbedVerify(() => verifyOts(PROOF, PINNED_SOURCE_SHA),
      async () => { throw new Error('Calendar timeout while upgrading pending attestation'); });
    if (cal.status === 'pending') pass('thrown calendar/pending error reads pending');
    else fail('calendar error misclassified', JSON.stringify(cal));
  }

  section('7. PAGE + COPY PINS — the synthetic-hash page path and offline claims stay gone');
  {
    const vjs = readFileSync(join(REPO, 'public', 'js', 'verify.js'), 'utf8');
    if (!vjs.includes("'0'.repeat(64)")) pass('verify.js no longer builds a synthetic all-zero hash');
    else fail('verify.js still contains the synthetic all-zero hash');
    if (vjs.includes('parseOtsDigest')) pass('verify.js binds bare .ots via parseOtsDigest');
    else fail('verify.js does not use parseOtsDigest');

    const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
    if (!readme.includes('works offline after first load')) pass('README blanket offline claim gone');
    else fail('README still claims verification works offline after first load');

    const indexHtml = readFileSync(join(REPO, 'public', 'index.html'), 'utf8');
    if (!indexHtml.includes('Works offline after first load')) pass('index.html offline heading gone');
    else fail('index.html still has the offline heading');

    const llms = readFileSync(join(REPO, 'public', 'llms.txt'), 'utf8');
    if (!llms.includes('offline-capable after first page load')) pass('llms.txt offline-capable claim gone');
    else fail('llms.txt still claims offline-capable');

    const vhtml = readFileSync(join(REPO, 'public', 'verify.html'), 'utf8');
    if (vhtml.includes('ots-options') && vhtml.includes('never leave the browser')) pass('verify.html OTS panel discloses what is contacted');
    else fail('verify.html OTS panel missing');
  }

  console.log('');
  if (_failed > 0) {
    console.error(`gate-ots-verify-honesty: FAIL — ${_failed} check(s) failed`);
    process.exit(1);
  }
  console.log('gate-ots-verify-honesty: PASS — bare .ots verifies against its embedded digest,');
  console.log('pending reads pending, complete needs a verified attestation with a time,');
  console.log('and the offline wording names what is contacted.');
}

run().catch((e) => { console.error('gate-ots-verify-honesty: unhandled error:', e); process.exit(1); });
