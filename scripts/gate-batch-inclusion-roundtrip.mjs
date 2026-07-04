// gate-batch-inclusion-roundtrip.mjs — §20.1 batch inclusion roundtrip gate.
//
// Simulates anchor_batch output → attach binding+inclusion per leaf → verify each.
// Tests verifyMerkleInclusion in roundtrip mode (build batch → verify every leaf).
// Also tests: mutated index, mutated path, mutated leaf, wrong anchored_hash each reject.
//
// Deterministic: no network. Uses real merkle.mjs + a synthetic TST fixture binding.

import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { buildMerkleBatch, verifyMerkleInclusion } from '../public/lib/merkle.mjs';

let _failed = 0;
function pass(label) { console.log('  PASS  ' + label); }
function fail(label, reason) { console.error('  FAIL  ' + label + (reason ? ': ' + reason : '')); _failed++; }
function section(s) { console.log('\n' + s); }
const attempt = async (fn) => { try { return { ok: true, value: await fn() }; } catch (e) { return { ok: false, error: e.message }; } };

// Deterministic leaf inputs (4 = smallest non-trivial even batch).
const BATCH_SIZE = 4;
function makeDigest(i) {
  const b = new Uint8Array(32);
  b[0] = 0xba;
  b[1] = i & 0xff;
  return b;
}
function u8ToHex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function run() {

  section('1. Build batch');

  const digests = Array.from({ length: BATCH_SIZE }, (_, i) => makeDigest(i));
  const batch = await buildMerkleBatch(digests);

  pass('buildMerkleBatch returned root: ' + batch.rootHex.slice(0, 16) + '...');
  if (batch.entries.length === BATCH_SIZE) {
    pass('entries.length = ' + BATCH_SIZE);
  } else {
    fail('wrong entries count', String(batch.entries.length));
  }

  section('2. All per-leaf inclusions verify');

  for (let i = 0; i < BATCH_SIZE; i++) {
    const e = batch.entries[i];
    // Simulate attaching to a binding: anchored_hash = tree root, merkle_inclusion = e.
    const r = await attempt(() =>
      verifyMerkleInclusion(e, { anchoredHashHex: batch.rootHex, artifactHashHex: e.leaf }),
    );
    if (r.ok) {
      pass('leaf ' + i + ' (index=' + e.index + '): inclusion verified');
    } else {
      fail('leaf ' + i + ': inclusion rejected', r.error);
    }
  }

  section('3. Mutated binding is rejected');

  const GOOD = batch.entries[2]; // pick a middle leaf

  // 3a: mutated index.
  {
    const bad = { ...GOOD, index: (GOOD.index + 1) % BATCH_SIZE };
    const r = await attempt(() => verifyMerkleInclusion(bad, { anchoredHashHex: batch.rootHex }));
    r.ok ? fail('mutated index should be rejected') : pass('mutated index rejected');
  }

  // 3b: mutated path node.
  if (GOOD.path.length > 0) {
    const badPath = [...GOOD.path];
    badPath[0] = 'f'.repeat(64);
    const bad = { ...GOOD, path: badPath };
    const r = await attempt(() => verifyMerkleInclusion(bad, { anchoredHashHex: batch.rootHex }));
    r.ok ? fail('mutated path should be rejected') : pass('mutated path[0] rejected');
  }

  // 3c: mutated leaf (wrong artifact).
  {
    const bad = { ...GOOD, leaf: 'ee'.repeat(32) };
    const r = await attempt(() => verifyMerkleInclusion(bad, { anchoredHashHex: batch.rootHex }));
    r.ok ? fail('mutated leaf should be rejected') : pass('mutated leaf rejected (root reconstruction fails)');
  }

  // 3d: wrong anchored_hash (wrong root claim).
  {
    const r = await attempt(() => verifyMerkleInclusion(GOOD, { anchoredHashHex: '0'.repeat(64) }));
    r.ok ? fail('wrong anchored_hash should be rejected') : pass('wrong anchored_hash rejected');
  }

  // 3e: artifactHashHex mismatch.
  {
    const r = await attempt(() => verifyMerkleInclusion(GOOD, { anchoredHashHex: batch.rootHex, artifactHashHex: '1'.repeat(64) }));
    r.ok ? fail('artifactHashHex mismatch should be rejected') : pass('artifactHashHex mismatch rejected');
  }

  section('4. tree_size=2 edge case');

  {
    const two = await buildMerkleBatch([makeDigest(10), makeDigest(11)]);
    for (const e of two.entries) {
      const r = await attempt(() => verifyMerkleInclusion(e, { anchoredHashHex: two.rootHex, artifactHashHex: e.leaf }));
      r.ok ? pass('tree_size=2 leaf ' + e.index + ' verifies') : fail('tree_size=2 leaf ' + e.index, r.error);
    }
  }

  console.log('');
  if (_failed > 0) {
    console.error('gate-batch-inclusion-roundtrip: FAIL — ' + _failed + ' check(s) failed');
    process.exit(1);
  }
  console.log('gate-batch-inclusion-roundtrip: PASS — all checks green');
}

run().catch((e) => {
  console.error('gate-batch-inclusion-roundtrip: unhandled error:', e);
  process.exit(1);
});
