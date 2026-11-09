// gate-ots-format.mjs — offline gate for the OTS detached-file format fix
// (board row ANCHOR-WORKER-OTS-FORMAT-FIX-1, defects 1+2).
//
// Defect 1: buildOtsPending emitted MAGIC + 0x08 + hash… with NO version byte
// after the magic, so worker-issued proofs were rejected by every standard OTS
// client ("Version 8 detached timestamp files are not supported" — 0x08 read
// as the version). This gate proves, fully offline:
//   1. buildOtsPending now emits the standard 0x01 version byte after the
//      magic (byte 31 = 0x01, byte 32 = 0x08), and its output over two REAL
//      calendar responses is byte-identical to the known-good standard .ots
//      assembled independently in the borrow-triage session (2026-10-29);
//   2. the new output parses with the vendored javascript-opentimestamps
//      0.4.9 (public/vendor/opentimestamps.min.js, loaded with a UMD shim —
//      no network) and shows two pending attestations (alice + bob);
//   3. the new output parses with the relay's own parseOtsPending;
//   4. a LEGACY no-version proof (exactly what the pre-fix builder emitted)
//      still parses with the relay parser (back-compat promise) — and is
//      rejected by the vendored library, the RED-then-GREEN control proving
//      the legacy form really is unreadable by standard clients;
//   5. fix 2 (choice b): upgrade_ots_proof is a confirmation oracle — on a
//      confirming calendar it returns proof_upgraded:false, the original
//      proof bytes unchanged, and no completed_calendar field; when nothing
//      confirms it returns status pending, proof_upgraded:false; a proof
//      already carrying a Bitcoin attestation reports it without touching the
//      bytes;
//   6. the registered tool description states the confirmation-only contract
//      and no longer claims to fetch "a Bitcoin attestation upgrade".
//
// The embedded calendar responses are real alice/btc.calendar.opentimestamps.org
// and bob.btc.calendar.opentimestamps.org /digest replies for SHA-256
// da5c8e2f4f74f23eb271aba00f67e25f37c957237a2bab857aef8db2eb1717b2 (captured
// 2026-10-29, see research/borrow-triage-2026-10-29/ots-selfmade-check.md).
// They are PENDING attestations — no Bitcoin data, nothing secret.

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { buildOtsPending, parseOtsPending, toolUpgradeOtsProof } from '../src/worker.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');

let failed = 0;
function check(label, cond, detail = '') {
  if (cond) {
    console.log('gate-ots-format: ' + label + '... ok');
  } else {
    failed++;
    console.error('gate-ots-format: ' + label + '... FAIL' + (detail ? ' — ' + detail : ''));
  }
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Real calendar /digest responses (alice, bob) and the independently assembled
// standard .ots over them — the golden for the fixed builder's output.
const CAL_ALICE_HEX = 'f00823785b425b39c2a408f0203a8b64f9e0b95de79a430b4dd5414be5d8b5229f70660b2db3fa2886bd69a07c08f010f1399ade63b95ffb9b786b1e1c206d9508f020cce969c8e0b43193e175a1b5d073bfc172b68626f55b7f4931273b56efcd0fdc08f1202b20db82ff4d540ae2dff23b999b466c1b68eef03eecdd8eec81b31ca6c7c89708f020994d615272cdc4ab7f8080774b693400892a84cd47cfaf106674a5ac6068338708f1046ae34e06f00810af274c3f660aa30083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267';
const CAL_BOB_HEX = 'f008c46653ff746123ff08f020381e20bcb99bb888219a3e4fed66954009614996a1234fdfc29ce47259fa294e08f120b4f348022b1d556fb67c8999d6d14c866c3d1d65bcd971f81ec37d90bf1e039108f01083571aedb683a9540c6e32108011572408f120756839517f1da5f0b2559b8d2e2dd3a5bf6fd1494214459c2f8f57e387e95db308f120ef5016a032e343e7693faf5f4f3b0cc8314c4bc4678c5ee4a27cd4381463e6d808f1046ae34e06f008ac2bea1565ada6030083dfe30d2ef90c8e2c2b68747470733a2f2f626f622e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267';
const STANDARD_PROOF_HEX = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108da5c8e2f4f74f23eb271aba00f67e25f37c957237a2bab857aef8db2eb1717b2fff00823785b425b39c2a408f0203a8b64f9e0b95de79a430b4dd5414be5d8b5229f70660b2db3fa2886bd69a07c08f010f1399ade63b95ffb9b786b1e1c206d9508f020cce969c8e0b43193e175a1b5d073bfc172b68626f55b7f4931273b56efcd0fdc08f1202b20db82ff4d540ae2dff23b999b466c1b68eef03eecdd8eec81b31ca6c7c89708f020994d615272cdc4ab7f8080774b693400892a84cd47cfaf106674a5ac6068338708f1046ae34e06f00810af274c3f660aa30083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267f008c46653ff746123ff08f020381e20bcb99bb888219a3e4fed66954009614996a1234fdfc29ce47259fa294e08f120b4f348022b1d556fb67c8999d6d14c866c3d1d65bcd971f81ec37d90bf1e039108f01083571aedb683a9540c6e32108011572408f120756839517f1da5f0b2559b8d2e2dd3a5bf6fd1494214459c2f8f57e387e95db308f120ef5016a032e343e7693faf5f4f3b0cc8314c4bc4678c5ee4a27cd4381463e6d808f1046ae34e06f008ac2bea1565ada6030083dfe30d2ef90c8e2c2b68747470733a2f2f626f622e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267';
const FILE_HASH_HEX = 'da5c8e2f4f74f23eb271aba00f67e25f37c957237a2bab857aef8db2eb1717b2';

const aliceBytes = hexToBytes(CAL_ALICE_HEX);
const bobBytes = hexToBytes(CAL_BOB_HEX);
const standardProof = hexToBytes(STANDARD_PROOF_HEX);
const hashBytes = hexToBytes(FILE_HASH_HEX);

// ---------------------------------------------------------------------------
// 1. Fixed builder: version byte present, output byte-identical to golden.
// ---------------------------------------------------------------------------

const built = buildOtsPending(hashBytes, [aliceBytes, bobBytes]);
check('buildOtsPending emits version byte 0x01 at offset 31, 0x08 at 32',
  built[31] === 0x01 && built[32] === 0x08,
  'bytes[31..32]=' + built[31].toString(16) + ',' + built[32].toString(16));
check('buildOtsPending output is byte-identical to the known-good standard .ots',
  Buffer.from(built).toString('hex') === Buffer.from(standardProof).toString('hex'),
  'built ' + built.length + 'B vs golden ' + standardProof.length + 'B');

// Hex dump of the first 40 bytes, before (legacy, pre-fix shape) and after —
// the before bytes are reconstructed exactly as the pre-fix builder assembled
// them (magic + tag + hash, no version byte).
const OTS_MAGIC = standardProof.slice(0, 31);
const legacyBuilt = new Uint8Array([
  ...OTS_MAGIC, 0x08, ...hashBytes, 0xff, ...aliceBytes, ...bobBytes,
]);
const hexDump = (b) => Buffer.from(b.slice(0, 40)).toString('hex');
console.log('gate-ots-format: first 40 bytes BEFORE (legacy, pre-fix): ' + hexDump(legacyBuilt));
console.log('gate-ots-format: first 40 bytes AFTER  (standard, fixed): ' + hexDump(built));

// ---------------------------------------------------------------------------
// 2. Vendored javascript-opentimestamps parses the new output (no network).
// ---------------------------------------------------------------------------

// The vendored bundle is a browser UMD build; under "type":"module" it must be
// evaluated through a module shim (same library the verify page loads). Load it
// ONCE and reuse — the bundle vendors bitcore-lib, whose duplicate-instance
// detector throws if the bundle is evaluated twice in one process.
let vendoredOts = null;
function loadVendoredOts() {
  if (vendoredOts) return vendoredOts;
  const src = readFileSync(join(ROOT, 'public', 'vendor', 'opentimestamps.min.js'), 'utf8');
  const mod = { exports: {} };
  new Function('module', 'exports', 'define', 'window', 'self', src)(
    mod, mod.exports, undefined, globalThis, globalThis);
  vendoredOts = mod.exports;
  return vendoredOts;
}

let vendoredParsed = null;
try {
  const OT = loadVendoredOts();
  vendoredParsed = OT.DetachedTimestampFile.deserialize(new Uint8Array(built));
  check('vendored javascript-opentimestamps parses the new buildOtsPending output', !!vendoredParsed);
} catch (e) {
  check('vendored javascript-opentimestamps parses the new buildOtsPending output', false, e.message);
}

if (vendoredParsed) {
  try {
    const OT = loadVendoredOts();
    const info = OT.info(vendoredParsed);
    const urls = [...String(info).matchAll(/https?:\/\/[^\s'"]+/g)].map((m) => m[0]);
    const aliceOk = urls.some((u) => u.includes('alice.btc.calendar.opentimestamps.org'));
    const bobOk = urls.some((u) => u.includes('bob.btc.calendar.opentimestamps.org'));
    check('vendored library sees both pending attestations (alice + bob)', aliceOk && bobOk,
      'urls=' + JSON.stringify(urls));
    check('vendored library sees no Bitcoin attestation in the pending proof',
      !String(info).toLowerCase().includes('bitcoin'), '');
  } catch (e) {
    check('vendored library info() over the new output', false, e.message);
  }
}

// ---------------------------------------------------------------------------
// 3. Relay parser accepts the new standard output.
// ---------------------------------------------------------------------------

{
  const parsed = await parseOtsPending(built);
  check('relay parseOtsPending accepts the new standard output',
    parsed.fileHashHex === FILE_HASH_HEX && parsed.pendingBranches.length === 2,
    JSON.stringify({ fileHashHex: parsed.fileHashHex, branches: parsed.pendingBranches.length }));
  check('relay parseOtsPending finds alice + bob pending branches on the new output',
    parsed.pendingBranches.some((b) => b.url.includes('alice.btc.calendar')) &&
    parsed.pendingBranches.some((b) => b.url.includes('bob.btc.calendar')),
    JSON.stringify(parsed.pendingBranches.map((b) => b.url)));
}

// ---------------------------------------------------------------------------
// 4. Legacy no-version proof: relay parser still accepts; vendored library
//    still rejects (RED control — the defect is real).
// ---------------------------------------------------------------------------

{
  const parsed = await parseOtsPending(legacyBuilt);
  check('legacy no-version proof still parses with the relay parser (back-compat)',
    parsed.fileHashHex === FILE_HASH_HEX && parsed.pendingBranches.length === 2,
    JSON.stringify({ fileHashHex: parsed.fileHashHex, branches: parsed.pendingBranches.length }));
  let libErr = null;
  try {
    const OT = loadVendoredOts();
    OT.DetachedTimestampFile.deserialize(new Uint8Array(legacyBuilt));
  } catch (e) {
    libErr = e;
  }
  check('legacy no-version proof is rejected by the vendored library (defect control)',
    !!libErr && /Version .* detached timestamp files are not supported/.test(libErr.message || ''),
    libErr ? libErr.message : 'parsed (unexpected)');
}

// ---------------------------------------------------------------------------
// 5. Fix 2 (choice b): upgrade_ots_proof is an honest confirmation oracle.
// ---------------------------------------------------------------------------

const realFetch = globalThis.fetch;
let fetchCalls;
function stubFetch(fn) {
  fetchCalls = [];
  globalThis.fetch = async (...args) => {
    fetchCalls.push(args[0]);
    return fn(...args);
  };
}
function restoreFetch() {
  globalThis.fetch = realFetch;
}

const OTS_PENDING_AT = hexToBytes('83dfe30d2ef90c8e');
const OTS_BTC_AT = hexToBytes('0588960d73d71901');
function concatBytes(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
function shortVarint(n) {
  if (n >= 128) throw new Error('shortVarint: value too large for this fixture');
  return new Uint8Array([n]);
}
function pendingBranch(url) {
  const u = new TextEncoder().encode(url);
  return concatBytes(new Uint8Array([0x00]), OTS_PENDING_AT, shortVarint(u.length), u);
}
function btcBranch(heightAndBlock) {
  return concatBytes(new Uint8Array([0x00]), OTS_BTC_AT, shortVarint(heightAndBlock.length), heightAndBlock);
}
function singleBranchProof(url) {
  const h = new Uint8Array(32).fill(0x11);
  return concatBytes(OTS_MAGIC, new Uint8Array([0x01, 0x08]), h, pendingBranch(url));
}

// 5a. Calendar confirms — honest completed report, bytes untouched.
{
  const pinned = 'https://alice.btc.calendar.opentimestamps.org';
  const proof = singleBranchProof(pinned);
  const proofB64 = Buffer.from(proof).toString('base64');
  stubFetch(async () => new Response(new Uint8Array([0x01, 0x02, 0x03]), { status: 200 }));
  let result;
  try {
    result = await toolUpgradeOtsProof({ proof: proofB64 }, '1.2.3.4', {});
  } finally {
    restoreFetch();
  }
  check('confirming calendar → status completed',
    result.status === 'completed', JSON.stringify(result));
  check('confirming calendar → proof_upgraded:false (no merge claimed)',
    result.proof_upgraded === false, JSON.stringify(result.proof_upgraded));
  check('confirming calendar → confirmed_by_calendar names the calendar',
    typeof result.confirmed_by_calendar === 'string' && result.confirmed_by_calendar === pinned,
    JSON.stringify(result.confirmed_by_calendar));
  check('confirming calendar → misleading completed_calendar field is gone',
    !('completed_calendar' in result), JSON.stringify(Object.keys(result)));
  check('confirming calendar → returned proof bytes are the ORIGINAL bytes unchanged',
    result.binding?.proof === proofB64, '');
  check('confirming calendar → note points at a full OTS client for the real upgrade',
    typeof result.note === 'string' && /ots upgrade|OpenTimestamps client/.test(result.note),
    JSON.stringify(result.note));
}

// 5b. Nothing confirms — honest pending report.
{
  const pinned = 'https://bob.btc.calendar.opentimestamps.org';
  stubFetch(async () => new Response('', { status: 404 }));
  let result;
  try {
    result = await toolUpgradeOtsProof(
      { proof: Buffer.from(singleBranchProof(pinned)).toString('base64') }, '1.2.3.4', {});
  } finally {
    restoreFetch();
  }
  check('non-confirming calendar → status pending, proof_upgraded:false',
    result.status === 'pending' && result.proof_upgraded === false, JSON.stringify(result));
}

// 5c. Proof already carries a Bitcoin attestation — reported, bytes untouched.
{
  const pinned = 'https://alice.btc.calendar.opentimestamps.org';
  const h = new Uint8Array(32).fill(0x22);
  const heightBlock = new Uint8Array(40).fill(0xab); // synthetic height+blockhash — offline fixture
  const proof = concatBytes(OTS_MAGIC, new Uint8Array([0x01, 0x08]), h, btcBranch(heightBlock));
  const proofB64 = Buffer.from(proof).toString('base64');
  stubFetch(async () => { throw new Error('no fetch expected'); });
  let result;
  try {
    result = await toolUpgradeOtsProof({ proof: proofB64 }, '1.2.3.4', {});
  } finally {
    restoreFetch();
  }
  check('already-Bitcoin proof → status completed, proof_upgraded:false, bytes unchanged',
    result.status === 'completed' && result.proof_upgraded === false && result.binding?.proof === proofB64,
    JSON.stringify(result));
  check('already-Bitcoin proof → no fetch attempted', fetchCalls.length === 0, '');
}

// ---------------------------------------------------------------------------
// 6. Registered tool description states the confirmation-only contract.
// ---------------------------------------------------------------------------

{
  const src = readFileSync(join(ROOT, 'src', 'worker.mjs'), 'utf8');
  const desc = src.match(/name: 'upgrade_ots_proof',\s*\n\s*description:\s*\n?\s*'([^']+)'/);
  check('upgrade_ots_proof description found in worker.mjs', !!desc, '');
  if (desc) {
    check('description says it does NOT modify the proof',
      /does NOT modify the proof/.test(desc[1]), desc[1].slice(0, 120) + '…');
    check('description points users to a full OTS client to upgrade',
      /ots upgrade|OpenTimestamps library/.test(desc[1]), '');
    check('description no longer claims a "Bitcoin attestation upgrade"',
      !/attestation upgrade/i.test(desc[1]), '');
  }
}

if (failed > 0) {
  console.error('gate-ots-format: ' + failed + ' check(s) failed');
  process.exit(1);
}
console.log('gate-ots-format: all checks green');
