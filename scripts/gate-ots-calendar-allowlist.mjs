// gate-ots-calendar-allowlist.mjs — offline gate for the upgrade_ots_proof SSRF
// fix (board row ANCHOR-OTS-SSRF-FIX-1, audit finding A2).
//
// toolUpgradeOtsProof's calendar URL comes straight out of caller-supplied OTS
// proof bytes. Before the fix, worker.mjs called `fetch(url + ...)` on that
// decoded URL unconditionally — an unauthenticated GET-anywhere reachability
// oracle, with no rate limit on the path at all.
//
// This gate builds real OTS pending-proof byte streams (independently of
// src/worker.mjs's own buildOtsPending, so the fixture isn't just testing the
// parser against itself) and drives toolUpgradeOtsProof directly, with global
// fetch stubbed so any outbound call is observable. It proves:
//   1. a proof naming a pinned calendar (https) still upgrades normally;
//   2. the SAME pinned host over plain http is rejected — no fetch attempted;
//   3. a cloud-metadata IP literal (169.254.169.254) is rejected — no fetch;
//   4. an arbitrary attacker host is rejected — no fetch;
//   5. malformed proof bytes are rejected — no fetch, and never a crash;
//   6. the tool now honors env.RELAY_LIMITER (denied → no fetch attempted).

import { toolUpgradeOtsProof } from '../src/worker.mjs';

let failed = 0;
function check(label, cond, detail = '') {
  if (cond) {
    console.log('gate-ots-calendar-allowlist: ' + label + '... ok');
  } else {
    failed++;
    console.error('gate-ots-calendar-allowlist: ' + label + '... FAIL' + (detail ? ' — ' + detail : ''));
  }
}

// ---------------------------------------------------------------------------
// Independent OTS pending-proof byte builder (mirrors the public .ots wire
// format documented in src/worker.mjs's own buildOtsPending, but constructed
// here from scratch so this fixture does not depend on that function).
// ---------------------------------------------------------------------------

const OTS_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
  0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
  0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const OTS_SHA256_TAG = new Uint8Array([0x08]);
const OTS_PENDING_AT = hexToBytes('83dfe30d2ef90c8e'); // 8-byte "pending" attestation tag

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concatBytes(...arrs) {
  const total = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// Single-byte varint is enough — every test URL below is well under 128 bytes.
function shortVarint(n) {
  if (n >= 128) throw new Error('shortVarint: value too large for this fixture');
  return new Uint8Array([n]);
}

function buildPendingBranch(url) {
  const urlBytes = new TextEncoder().encode(url);
  return concatBytes(new Uint8Array([0x00]), OTS_PENDING_AT, shortVarint(urlBytes.length), urlBytes);
}

// One pending branch, no fork — the shape parseOtsPending expects for a
// single-calendar submission.
function buildSingleBranchProof(url) {
  const hashBytes = new Uint8Array(32).fill(0x11);
  return concatBytes(OTS_MAGIC, OTS_SHA256_TAG, hashBytes, buildPendingBranch(url));
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

// ---------------------------------------------------------------------------
// fetch stub
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

// ---------------------------------------------------------------------------
// 1. Pinned calendar, https — upgrade still works, exactly one fetch, to the
//    right URL.
// ---------------------------------------------------------------------------

{
  const pinned = 'https://alice.btc.calendar.opentimestamps.org';
  stubFetch(async () => new Response(new Uint8Array([0x01, 0x02, 0x03]), { status: 200 }));
  let result;
  try {
    result = await toolUpgradeOtsProof(
      { proof: toBase64(buildSingleBranchProof(pinned)) },
      '1.2.3.4',
      {},
    );
  } finally {
    restoreFetch();
  }
  check('pinned https calendar → status completed',
    result.status === 'completed', JSON.stringify(result));
  check('pinned https calendar → exactly one fetch, to the pinned host',
    fetchCalls.length === 1 && String(fetchCalls[0]).startsWith(pinned + '/timestamp/'),
    'fetchCalls=' + JSON.stringify(fetchCalls.map(String)));
}

// ---------------------------------------------------------------------------
// 2. Same pinned HOST, but plain http — must still be rejected (FIX step 2:
//    non-https rejected even if it otherwise matches).
// ---------------------------------------------------------------------------

{
  const httpPinnedHost = 'http://alice.btc.calendar.opentimestamps.org';
  stubFetch(async () => new Response(new Uint8Array([0x01]), { status: 200 }));
  let result;
  try {
    result = await toolUpgradeOtsProof(
      { proof: toBase64(buildSingleBranchProof(httpPinnedHost)) },
      '1.2.3.4',
      {},
    );
  } finally {
    restoreFetch();
  }
  check('non-https on an otherwise-pinned host → rejected, no fetch',
    !!result.error && fetchCalls.length === 0, JSON.stringify(result) + ' fetchCalls=' + fetchCalls.length);
}

// ---------------------------------------------------------------------------
// 3. Cloud-metadata IP literal — rejected, no fetch.
// ---------------------------------------------------------------------------

{
  const metadataUrl = 'http://169.254.169.254/';
  stubFetch(async () => new Response(new Uint8Array([0x01]), { status: 200 }));
  let result;
  try {
    result = await toolUpgradeOtsProof(
      { proof: toBase64(buildSingleBranchProof(metadataUrl)) },
      '1.2.3.4',
      {},
    );
  } finally {
    restoreFetch();
  }
  check('cloud-metadata IP literal (169.254.169.254) → rejected, no fetch',
    !!result.error && fetchCalls.length === 0, JSON.stringify(result) + ' fetchCalls=' + fetchCalls.length);
}

// ---------------------------------------------------------------------------
// 4. Arbitrary attacker host — rejected, no fetch.
// ---------------------------------------------------------------------------

{
  const evilUrl = 'https://evil.example/';
  stubFetch(async () => new Response(new Uint8Array([0x01]), { status: 200 }));
  let result;
  try {
    result = await toolUpgradeOtsProof(
      { proof: toBase64(buildSingleBranchProof(evilUrl)) },
      '1.2.3.4',
      {},
    );
  } finally {
    restoreFetch();
  }
  check('arbitrary attacker host (evil.example) → rejected, no fetch',
    !!result.error && fetchCalls.length === 0, JSON.stringify(result) + ' fetchCalls=' + fetchCalls.length);
}

// ---------------------------------------------------------------------------
// 5. Malformed proof bytes — rejected cleanly (parse failure = reject, never
//    a passthrough), no fetch, no crash.
// ---------------------------------------------------------------------------

{
  stubFetch(async () => new Response(new Uint8Array([0x01]), { status: 200 }));
  let result;
  try {
    result = await toolUpgradeOtsProof({ proof: 'not-valid-base64-!!!' }, '1.2.3.4', {});
  } finally {
    restoreFetch();
  }
  check('malformed (non-base64) proof → clean tool error, no fetch',
    !!result.error && fetchCalls.length === 0, JSON.stringify(result) + ' fetchCalls=' + fetchCalls.length);
}

{
  stubFetch(async () => new Response(new Uint8Array([0x01]), { status: 200 }));
  const garbage = new Uint8Array(40).fill(0xaa); // valid base64, wrong magic
  let result;
  try {
    result = await toolUpgradeOtsProof({ proof: toBase64(garbage) }, '1.2.3.4', {});
  } finally {
    restoreFetch();
  }
  check('malformed (bad magic) proof → clean tool error, no fetch',
    !!result.error && fetchCalls.length === 0, JSON.stringify(result) + ' fetchCalls=' + fetchCalls.length);
}

// ---------------------------------------------------------------------------
// 6. RELAY_LIMITER is now consulted on this path — a denied limit blocks the
//    fetch entirely.
// ---------------------------------------------------------------------------

{
  const pinned = 'https://bob.btc.calendar.opentimestamps.org';
  stubFetch(async () => new Response(new Uint8Array([0x01]), { status: 200 }));
  let limiterCalledWith = null;
  const env = {
    RELAY_LIMITER: {
      limit: async ({ key }) => { limiterCalledWith = key; return { success: false }; },
    },
  };
  let result;
  try {
    result = await toolUpgradeOtsProof(
      { proof: toBase64(buildSingleBranchProof(pinned)) },
      '9.9.9.9',
      env,
    );
  } finally {
    restoreFetch();
  }
  check('RELAY_LIMITER denial → rate-limit error, no fetch',
    !!result.error && fetchCalls.length === 0, JSON.stringify(result) + ' fetchCalls=' + fetchCalls.length);
  check('RELAY_LIMITER.limit called with caller IP',
    limiterCalledWith === '9.9.9.9', 'limiterCalledWith=' + limiterCalledWith);
}

{
  // Sanity: a passing limiter does not block the legitimate path.
  const pinned = 'https://bob.btc.calendar.opentimestamps.org';
  stubFetch(async () => new Response(new Uint8Array([0x01]), { status: 200 }));
  const env = { RELAY_LIMITER: { limit: async () => ({ success: true }) } };
  let result;
  try {
    result = await toolUpgradeOtsProof(
      { proof: toBase64(buildSingleBranchProof(pinned)) },
      '9.9.9.9',
      env,
    );
  } finally {
    restoreFetch();
  }
  check('RELAY_LIMITER success → legitimate upgrade still completes',
    result.status === 'completed' && fetchCalls.length === 1, JSON.stringify(result));
}

if (failed > 0) {
  console.error(`\ngate-ots-calendar-allowlist: ${failed} check(s) failed`);
  process.exit(1);
}
console.log('\ngate-ots-calendar-allowlist: all checks passed');
