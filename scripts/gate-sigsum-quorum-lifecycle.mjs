// gate-sigsum-quorum-lifecycle.mjs — offline gate for the Sigsum witness
// quorum and the pending-binding lifecycle (board row ANCH-QUORUM-LIFECYCLE-1;
// audit findings ANCH-1 MEDIUM, ANCH-3 MEDIUM, ANCH-4 LOW,
// research/AUDIT-PUBLIC-FULLSWEEP-2026-09-01.md).
//
// Proves, mechanically:
//   1. the verdict is gated on witness quorum — a structurally sound record
//      with zero quorum witnesses is 'log-only' and NOT ok (ANCH-1);
//   2. quorum is counted over the THREE sigsum-generic-2025-1 witnesses, not
//      over the 12 pinned cosigners — nine valid recognition-only cosignatures
//      do not add up to a quorum;
//   3. one witness cosigning twice counts once (no self-assembled quorum);
//   4. a tampered record is 'invalid', distinct from 'log-only';
//   5. the three verifier surfaces AGREE — public/lib/sigsum.mjs, the shared
//      verify-runner used by /verify.html and the library, and the MCP
//      verify_anchor_binding tool all return the same verdict for the same
//      binding (ANCH-4);
//   6. a pending binding is 'pending' everywhere and never 'unsupported',
//      never a failure (ANCH-3);
//   7. the pending upgrade path is GET-only — it never re-submits the leaf
//      (a re-stamp burns another 288/24h entry and duplicates the leaf in a
//      permanent public log).
//
// INDEPENDENT DERIVATION (SO #34). The gate never reads the answer from the
// module under test. The three quorum witnesses are transcribed HERE from the
// sigsum-generic-2025-1 policy text, their key hashes are recomputed HERE, and
// the module's own `quorum` flags are then CHECKED against that independent
// derivation rather than trusted. The true-positive vector is a real seasalp
// record; every negative vector is derived from it at runtime by removing or
// duplicating cosignature lines, so a stale fixture cannot make this gate pass.

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const FIXTURE = join(ROOT, 'tests', 'fixtures', 'sigsum-record.fixture.json');

let failed = 0;
function check(label, cond, detail = '') {
  if (cond) {
    console.log('gate-sigsum-quorum-lifecycle: ' + label + '... ok');
  } else {
    failed++;
    console.error('gate-sigsum-quorum-lifecycle: ' + label + '... FAIL' + (detail ? ' — ' + detail : ''));
  }
}

// ---------------------------------------------------------------------------
// The policy, transcribed here rather than imported. Source:
// sigsum-generic-2025-1 (sigsum-go pkg/policy/builtin), the same text the site's
// scripts/register-sigsum.mjs transcribes:
//   group quorum-rule 2 witness.glasklar.is witness.mullvad.net tillitis.se/tillitis-witness-1
//   quorum quorum-rule
// ---------------------------------------------------------------------------
const POLICY_NAME = 'sigsum-generic-2025-1';
const POLICY_K = 2;
const POLICY_WITNESS_KEYS = {
  'witness.glasklar.is': 'b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536',
  'witness.mullvad.net': '15d6d0141543247b74bab3c1076372d9c894f619c376d64b29aa312cc00f61ad',
  'tillitis.se/tillitis-witness-1': '076be8c9ee7ea60916f0df3608c945d7730082ecb37749dad2c9ed339fea770c',
};

async function sha256Hex(hex) {
  const bytes = Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
  return Buffer.from(await crypto.subtle.digest('SHA-256', bytes)).toString('hex');
}

const sigsum = await import(pathToFileURL(join(ROOT, 'public', 'lib', 'sigsum.mjs')).href);
const runner = await import(pathToFileURL(join(ROOT, 'public', 'lib', 'verify-runner.mjs')).href);

const RECORD = JSON.parse(readFileSync(FIXTURE, 'utf8')).sigsum_proof_record;

// ---------------------------------------------------------------------------
// 0. The module's quorum set matches the policy, derived independently.
// ---------------------------------------------------------------------------
{
  const flagged = sigsum.WITNESSES.filter((w) => w.quorum);
  const flaggedNames = flagged.map((w) => w.name).sort();
  const policyNames = Object.keys(POLICY_WITNESS_KEYS).sort();
  check('module marks exactly the 3 policy witnesses as quorum members',
    flaggedNames.length === 3 && flaggedNames.join('|') === policyNames.join('|'),
    'got ' + flaggedNames.join(', '));
  check('each flagged witness carries the key the policy names',
    flagged.every((w) => POLICY_WITNESS_KEYS[w.name] === w.keyHex));
  check('threshold is the policy k (' + POLICY_K + ')',
    sigsum.WITNESS_QUORUM_THRESHOLD === POLICY_K, 'got ' + sigsum.WITNESS_QUORUM_THRESHOLD);
  check('threshold is named against the policy it came from',
    sigsum.QUORUM_POLICY_NAME === POLICY_NAME, 'got ' + sigsum.QUORUM_POLICY_NAME);
  check('the other 9 pins are recognition-only, not quorum members',
    sigsum.WITNESSES.length === 12 && sigsum.WITNESSES.filter((w) => !w.quorum).length === 9);
}

// Split the record's cosignature lines into policy / non-policy using OUR hashes.
const policyKeyHashes = new Set(await Promise.all(Object.values(POLICY_WITNESS_KEYS).map(sha256Hex)));
const policyCosigs = RECORD.witness_cosignatures.filter((c) => policyKeyHashes.has(c.key_hash));
const otherCosigs = RECORD.witness_cosignatures.filter((c) => !policyKeyHashes.has(c.key_hash));
const withCosigs = (cosigs) => ({ ...RECORD, witness_cosignatures: cosigs });

check('fixture carries all 3 policy witnesses (true-positive vector is usable)',
  policyCosigs.length === 3, 'got ' + policyCosigs.length);
check('fixture carries recognition-only cosignatures to test against',
  otherCosigs.length >= 9, 'got ' + otherCosigs.length);

// ---------------------------------------------------------------------------
// 1-4. Verdict states, all derived from the one real record.
// ---------------------------------------------------------------------------
// Flip the low bit of the first byte. Written as an actual mutation rather than
// a literal substitution: this record's checksum happens to START with '00', so
// an earlier `replace(/^../, '00')` here changed nothing and the vector passed
// as ok — a tamper vector that does not tamper is the quietest way for a gate
// to grade itself green.
const flipFirstByte = (hex) => (parseInt(hex.slice(0, 2), 16) ^ 0x01).toString(16).padStart(2, '0') + hex.slice(2);
const tampered = structuredClone(RECORD);
tampered.leaf = { ...tampered.leaf, checksum: flipFirstByte(tampered.leaf.checksum) };
check('the tamper vector actually differs from the real record',
  tampered.leaf.checksum !== RECORD.leaf.checksum
  && tampered.leaf.checksum.length === RECORD.leaf.checksum.length);

const VECTORS = [
  { name: 'real record, 3 policy + 9 recognition cosignatures', binding: RECORD, verdict: 'ok', ok: true },
  { name: 'exactly the policy k (2 quorum witnesses)', binding: withCosigs(policyCosigs.slice(0, 2)), verdict: 'ok', ok: true },
  { name: 'one below the policy k (1 quorum witness)', binding: withCosigs(policyCosigs.slice(0, 1)), verdict: 'below-quorum', ok: false },
  { name: 'NINE valid recognition-only cosignatures, zero quorum witnesses', binding: withCosigs(otherCosigs), verdict: 'log-only', ok: false },
  { name: 'zero witness cosignatures (ANCH-1: used to verify as ok)', binding: withCosigs([]), verdict: 'log-only', ok: false },
  { name: 'one quorum witness cosigning twice counts once', binding: withCosigs([policyCosigs[0], policyCosigs[0]]), verdict: 'below-quorum', ok: false },
  { name: 'tampered leaf checksum is invalid, not log-only', binding: tampered, verdict: 'invalid', ok: false },
];

const verdicts = new Map();
for (const v of VECTORS) {
  const r = await sigsum.verifySigsumBinding(v.binding);
  verdicts.set(v.name, r);
  check('verdict: ' + v.name + ' -> ' + v.verdict,
    r.verdict === v.verdict && r.ok === v.ok,
    'got verdict=' + r.verdict + ' ok=' + r.ok + ' quorum=' + r.quorumWitnessesOk + '/' + r.quorumThreshold);
}

// The load-bearing one, stated as its own assertion: the recognition pins are
// counted and displayed, and still do not add up to a quorum.
{
  const r = verdicts.get('NINE valid recognition-only cosignatures, zero quorum witnesses');
  check('recognition-only cosignatures are counted in witnessesOk but not in quorum',
    r.witnessesOk === 9 && r.quorumWitnessesOk === 0 && r.ok === false,
    'witnessesOk=' + r.witnessesOk + ' quorumWitnessesOk=' + r.quorumWitnessesOk);
}

// ---------------------------------------------------------------------------
// 5. Surface agreement (ANCH-4): the shared runner and the MCP tool return the
//    same verdict as the module for every vector above.
// ---------------------------------------------------------------------------
const worker = (await import(pathToFileURL(join(ROOT, 'src', 'worker.mjs')).href)).default;

async function mcpVerify(binding) {
  const req = new Request('https://anchor.ainumbers.co/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.9' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'verify_anchor_binding', arguments: { binding } },
    }),
  });
  const res = await worker.fetch(req, {}, { waitUntil() {} });
  const body = await res.json();
  const text = body?.result?.content?.[0]?.text;
  const parsed = typeof text === 'string' ? JSON.parse(text) : body?.result;
  return parsed?.results?.[0] ?? parsed;
}

for (const v of VECTORS) {
  const viaRunner = await runner.verifySigsumAnchor(v.binding);
  const expectRunner = v.verdict === 'invalid' ? 'error' : v.verdict;
  check('runner agrees: ' + v.name,
    viaRunner.status === expectRunner && viaRunner.ok === v.ok,
    'got status=' + viaRunner.status + ' ok=' + viaRunner.ok);

  const viaMcp = await mcpVerify(v.binding);
  check('MCP tool agrees: ' + v.name,
    viaMcp && viaMcp.verdict === v.verdict && viaMcp.valid === v.ok,
    'got ' + JSON.stringify({ verdict: viaMcp?.verdict, valid: viaMcp?.valid, reasons: viaMcp?.reasons }));
}

// The MCP result must carry the quorum numbers, not just a boolean — a caller
// has to be able to tell log-only from below-quorum without re-verifying.
{
  const r = await mcpVerify(withCosigs(otherCosigs));
  check('MCP result reports the quorum policy, threshold and count',
    r?.witness_quorum?.policy === POLICY_NAME
    && r.witness_quorum.threshold === POLICY_K
    && r.witness_quorum.cosigned === 0
    && r.witness_quorum.met === false,
    JSON.stringify(r?.witness_quorum));
  check('MCP result explains log-only in its reasons',
    Array.isArray(r?.reasons) && r.reasons.some((x) => x.includes('log-only')),
    JSON.stringify(r?.reasons));
}

// ---------------------------------------------------------------------------
// 6-7. Pending lifecycle (ANCH-3).
// ---------------------------------------------------------------------------
const PENDING = {
  type: 'c2sp-tlog-pending-v1',
  anchored_hash: RECORD.anchored_hash,
  log_origin: RECORD.log_origin,
  log_url: RECORD.log_url,
  log_public_key: RECORD.log_public_key,
  leaf: RECORD.leaf,
  leaf_hash: 'aa'.repeat(32),
  submitted_at: '2026-09-10T03:00:00.000Z',
};

{
  const r = await sigsum.verifySigsumBinding(PENDING);
  check('module: pending binding is pending, not ok, not a crash',
    r.verdict === 'pending' && r.ok === false && r.pending === true, 'got ' + r.verdict);

  const viaRunner = await runner.verifySigsumAnchor(PENDING);
  check('runner: pending binding is pending, NOT unsupported',
    viaRunner.status === 'pending' && viaRunner.ok === false, 'got ' + viaRunner.status);

  const viaMcp = await mcpVerify(PENDING);
  check('MCP tool: pending binding is pending, NOT unsupported',
    viaMcp?.verdict === 'pending' && viaMcp.valid === false
    && !JSON.stringify(viaMcp.reasons).includes('unsupported'),
    JSON.stringify({ verdict: viaMcp?.verdict, reasons: viaMcp?.reasons }));
}

// GET-only: the upgrade path may read the log, never write to it. A stub fetch
// records every request; any POST, or any hit on add-leaf, is a re-stamp.
{
  const realFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: (init?.method || 'GET').toUpperCase() });
    return new Response('', { status: 404 });
  };
  let upgraded;
  try {
    upgraded = await sigsum.upgradeSigsumBinding(PENDING);
  } finally {
    globalThis.fetch = realFetch;
  }
  check('upgrade attempt made at least one request', calls.length > 0);
  check('upgrade is GET-only — no POST on any request',
    calls.every((c) => c.method === 'GET'), JSON.stringify(calls.map((c) => c.method)));
  check('upgrade never touches add-leaf (no re-stamp, 288/24h budget intact)',
    calls.every((c) => !c.url.includes('add-leaf')), JSON.stringify(calls.map((c) => c.url)));
  check('log not sequenced yet -> the SAME pending binding comes back unchanged',
    upgraded === PENDING);

  // A non-pending binding is returned untouched: upgrade cannot be aimed at a
  // completed proof and cause a second submission.
  const noop = await sigsum.upgradeSigsumBinding(RECORD);
  check('upgrade on a completed proof is a no-op', noop === RECORD);
}

if (failed) {
  console.error('\ngate-sigsum-quorum-lifecycle: ' + failed + ' check(s) FAILED');
  process.exit(1);
}
console.log('\ngate-sigsum-quorum-lifecycle: all checks passed');
