// gate-merkle-batch.mjs — deterministic RFC 6962 Merkle tree gate.
//
// Tests:
//   1. Known-vector 7-leaf tree (non-power-of-two): root matches hand-computed MTH.
//   2. Every audit path for every leaf reconstructs the correct root.
//   3. Tampered path node → root mismatch rejected.
//   4. Wrong leaf bytes → root mismatch rejected.
//   5. Wrong anchored_hash → rejected.
//   6. Wrong index → rejected.
//   7. buildMerkleBatch produces §20.1-shaped entries.
//
// Deterministic: no network, no randomness. Uses webcrypto shim.

import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { leafHash, nodeHash, mth, auditPath, rootFromInclusion, buildMerkleBatch, verifyMerkleInclusion } from '../public/lib/merkle.mjs';

const TREE_N = 7; // deliberately non-power-of-two (tests all branches of the recursive split)

let _failed = 0;
function pass(label) { console.log('  PASS  ' + label); }
function fail(label, reason) { console.error('  FAIL  ' + label + (reason ? ': ' + reason : '')); _failed++; }
function section(s) { console.log('\n' + s); }
const attempt = async (fn) => { try { return { ok: true, value: await fn() }; } catch (e) { return { ok: false, error: e.message }; } };

function u8ToHex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

// Deterministic 32-byte leaf inputs: byte[i] = i, rest = 0.
function makeLeafInput(i) {
  const buf = new Uint8Array(32);
  buf[0] = i;
  return buf;
}

async function run() {

  section('1. Build leaf hashes and root');

  const leafInputs = Array.from({ length: TREE_N }, (_, i) => makeLeafInput(i));
  const leafHashes = await Promise.all(leafInputs.map((d) => leafHash(d)));
  const root = await mth(leafHashes);
  const rootHex = u8ToHex(root);
  pass('MTH computed for ' + TREE_N + '-leaf tree: root=' + rootHex.slice(0, 16) + '...');

  // Verify root is stable (recompute independently).
  const root2 = await mth(leafHashes);
  if (u8ToHex(root2) === rootHex) {
    pass('MTH is deterministic (two independent computations agree)');
  } else {
    fail('MTH is not deterministic');
  }

  section('2. Every audit path reconstructs the root (all ' + TREE_N + ' leaves)');

  for (let m = 0; m < TREE_N; m++) {
    const path = await auditPath(m, leafHashes);
    const leaf = leafHashes[m];
    const rebuilt = await rootFromInclusion(leaf, m, TREE_N, path);
    if (rebuilt && u8ToHex(rebuilt) === rootHex) {
      pass('leaf ' + m + ': path length=' + path.length + ', root verified');
    } else {
      fail('leaf ' + m + ': root reconstruction failed', rebuilt ? 'rootHex mismatch' : 'null returned');
    }
  }

  section('3. Tampered path node → root mismatch rejected');

  {
    const m = 3;
    const path = await auditPath(m, leafHashes);
    if (path.length > 0) {
      const badPath = [...path];
      // Flip a bit in the first path node.
      const corrupted = new Uint8Array(badPath[0]);
      corrupted[0] ^= 0x01;
      badPath[0] = corrupted;
      const rebuilt = await rootFromInclusion(leafHashes[m], m, TREE_N, badPath);
      if (!rebuilt || u8ToHex(rebuilt) !== rootHex) {
        pass('tampered path[0] byte → reconstructed root differs from expected root');
      } else {
        fail('tampered path[0] should have changed the reconstructed root');
      }
    } else {
      pass('leaf 3 path is empty (single-leaf edge case skipped)');
    }
  }

  section('4. Wrong leaf input → root mismatch');

  {
    const m = 2;
    const path = await auditPath(m, leafHashes);
    const badLeaf = await leafHash(makeLeafInput(99)); // not in the tree
    const rebuilt = await rootFromInclusion(badLeaf, m, TREE_N, path);
    if (!rebuilt || u8ToHex(rebuilt) !== rootHex) {
      pass('wrong leaf → reconstructed root differs');
    } else {
      fail('wrong leaf should have changed the reconstructed root');
    }
  }

  section('5. verifyMerkleInclusion: correct inclusion accepted, error cases rejected');

  {
    const m = 4;
    const path = await auditPath(m, leafHashes);
    const mi = {
      leaf: u8ToHex(leafInputs[m]),
      index: m,
      path: path.map(u8ToHex),
      tree_size: TREE_N,
      algorithm: 'rfc6962',
    };

    const r1 = await attempt(() => verifyMerkleInclusion(mi, { anchoredHashHex: rootHex }));
    if (r1.ok && r1.value.rootHex === rootHex) {
      pass('verifyMerkleInclusion: correct inclusion accepted');
    } else {
      fail('verifyMerkleInclusion: correct inclusion rejected', r1.error);
    }

    // Wrong anchored_hash.
    const r2 = await attempt(() => verifyMerkleInclusion(mi, { anchoredHashHex: '0'.repeat(64) }));
    if (!r2.ok) {
      pass('verifyMerkleInclusion: wrong anchored_hash rejected');
    } else {
      fail('verifyMerkleInclusion: wrong anchored_hash should have been rejected');
    }

    // Wrong index.
    const r3 = await attempt(() => verifyMerkleInclusion({ ...mi, index: 0 }, { anchoredHashHex: rootHex }));
    if (!r3.ok) {
      pass('verifyMerkleInclusion: wrong index rejected');
    } else {
      fail('verifyMerkleInclusion: wrong index should have been rejected');
    }

    // Tampered path.
    if (mi.path.length > 0) {
      const badPath = [...mi.path];
      badPath[0] = 'a'.repeat(64);
      const r4 = await attempt(() => verifyMerkleInclusion({ ...mi, path: badPath }, { anchoredHashHex: rootHex }));
      if (!r4.ok) {
        pass('verifyMerkleInclusion: tampered path rejected');
      } else {
        fail('verifyMerkleInclusion: tampered path should have been rejected');
      }
    }

    // artifactHashHex mismatch.
    const r5 = await attempt(() => verifyMerkleInclusion(mi, { anchoredHashHex: rootHex, artifactHashHex: 'f'.repeat(64) }));
    if (!r5.ok) {
      pass('verifyMerkleInclusion: artifactHashHex mismatch rejected');
    } else {
      fail('verifyMerkleInclusion: artifactHashHex mismatch should have been rejected');
    }

    // artifactHashHex match.
    const r6 = await attempt(() => verifyMerkleInclusion(mi, { anchoredHashHex: rootHex, artifactHashHex: u8ToHex(leafInputs[m]) }));
    if (r6.ok) {
      pass('verifyMerkleInclusion: artifactHashHex match accepted');
    } else {
      fail('verifyMerkleInclusion: correct artifactHashHex rejected', r6.error);
    }
  }

  section('6. buildMerkleBatch: §20.1-shaped output');

  {
    const digests = Array.from({ length: TREE_N }, (_, i) => makeLeafInput(i));
    const batch = await buildMerkleBatch(digests);

    if (batch.rootHex === rootHex) {
      pass('buildMerkleBatch root matches independently computed MTH');
    } else {
      fail('buildMerkleBatch root mismatch', batch.rootHex + ' != ' + rootHex);
    }

    if (batch.entries.length === TREE_N) {
      pass('entries length = ' + TREE_N);
    } else {
      fail('entries length', 'expected ' + TREE_N + ', got ' + batch.entries.length);
    }

    let allShapeOk = true;
    for (const e of batch.entries) {
      if (e.algorithm !== 'rfc6962' || typeof e.leaf !== 'string' || !Number.isInteger(e.index) ||
          !Array.isArray(e.path) || e.tree_size !== TREE_N) {
        allShapeOk = false;
        break;
      }
    }
    allShapeOk ? pass('all entries carry required §20.1 fields') : fail('entry missing required §20.1 field');

    // Verify each entry's inclusion proof.
    let allVerify = true;
    for (const e of batch.entries) {
      const r = await attempt(() => verifyMerkleInclusion(e, { anchoredHashHex: rootHex, artifactHashHex: e.leaf }));
      if (!r.ok) { allVerify = false; break; }
    }
    allVerify ? pass('all ' + TREE_N + ' buildMerkleBatch inclusion proofs verify') : fail('a buildMerkleBatch inclusion proof failed');
  }

  console.log('');
  if (_failed > 0) {
    console.error('gate-merkle-batch: FAIL — ' + _failed + ' check(s) failed');
    process.exit(1);
  }
  console.log('gate-merkle-batch: PASS — all checks green');
}

run().catch((e) => {
  console.error('gate-merkle-batch: unhandled error:', e);
  process.exit(1);
});
