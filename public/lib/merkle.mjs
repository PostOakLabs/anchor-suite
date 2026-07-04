// merkle.mjs — RFC 6962 Merkle tree + §20.1 inclusion verifier.
// WebCrypto SHA-256 only; works in Cloudflare Workers and Node (with webcrypto shim).
// Zero dependencies. RFC 6962 §2.1 definitions:
//   leaf hash = SHA-256(0x00 || data)
//   node hash = SHA-256(0x01 || left || right)

function hexToU8(hex) {
  const h = String(hex).replace(/^sha256:/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function u8ToHex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// RFC 6962 §2.1: leaf hash = SHA-256(0x00 || data)
export async function leafHash(data) {
  return sha256(concat(new Uint8Array([0x00]), data));
}

// RFC 6962 §2.1: node hash = SHA-256(0x01 || left || right)
export async function nodeHash(left, right) {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

// Merkle Tree Hash over an array of pre-computed leaf hashes (Uint8Array[]).
// RFC 6962 §2.1: MTH({d(0)}) = SHA-256(0x00 || d(0));
//               MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//               where k is the largest power of 2 less than n.
export async function mth(leafHashes) {
  const n = leafHashes.length;
  if (n === 0) throw new Error('mth: empty tree');
  if (n === 1) return leafHashes[0];
  let k = 1;
  while (k * 2 < n) k *= 2;
  const [l, r] = await Promise.all([mth(leafHashes.slice(0, k)), mth(leafHashes.slice(k))]);
  return nodeHash(l, r);
}

// RFC 6962 §2.1.1: audit path for leaf m in tree of n leaf hashes.
export async function auditPath(m, leafHashes) {
  const n = leafHashes.length;
  if (n === 1) return [];
  let k = 1;
  while (k * 2 < n) k *= 2;
  if (m < k) {
    const [path, sib] = await Promise.all([auditPath(m, leafHashes.slice(0, k)), mth(leafHashes.slice(k))]);
    return [...path, sib];
  }
  const [path, sib] = await Promise.all([auditPath(m - k, leafHashes.slice(k)), mth(leafHashes.slice(0, k))]);
  return [...path, sib];
}

// RFC 9162 §2.1.3.2: reconstruct root from inclusion proof. Returns Uint8Array or null.
export async function rootFromInclusion(leaf, index, size, pathHashes) {
  if (index >= size) return null;
  let fn = BigInt(index), sn = BigInt(size) - 1n;
  let r = leaf;
  for (const v of pathHashes) {
    if (sn === 0n) return null;
    if ((fn & 1n) === 1n || fn === sn) {
      r = await nodeHash(v, r);
      if ((fn & 1n) === 0n) {
        while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; }
      }
    } else {
      r = await nodeHash(r, v);
    }
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n ? r : null;
}

// Build a Merkle batch over raw 32-byte digest Uint8Arrays.
// Returns { root (Uint8Array), rootHex, entries[i]: { leaf, index, path[], tree_size, algorithm } }
// entry.leaf is the 64-hex input digest; path[] is 64-hex node hashes. Shaped as §20.1 merkle_inclusion.
export async function buildMerkleBatch(rawDigests) {
  const n = rawDigests.length;
  if (n < 2 || n > 1024) throw new Error('batch size must be 2..1024');
  const lh = await Promise.all(rawDigests.map((d) => leafHash(d)));
  const root = await mth(lh);
  const paths = await Promise.all(lh.map((_, i) => auditPath(i, lh)));
  const rootHex = u8ToHex(root);
  return {
    root,
    rootHex,
    entries: rawDigests.map((d, i) => ({
      leaf: u8ToHex(d),
      index: i,
      path: paths[i].map(u8ToHex),
      tree_size: n,
      algorithm: 'rfc6962',
    })),
  };
}

// Verify a §20.1 merkle_inclusion object. Throws on failure; returns { rootHex } on success.
// mi: { leaf, index, path[], tree_size, algorithm:"rfc6962" }
// anchoredHashHex: the anchored_hash from the binding (= tree root, 64-hex or sha256:-prefixed)
// artifactHashHex: (optional) the artifact's own hash — mi.leaf MUST equal it when provided
export async function verifyMerkleInclusion(mi, { anchoredHashHex, artifactHashHex } = {}) {
  if (!mi || typeof mi !== 'object') throw new Error('merkle_inclusion must be an object');
  if (mi.algorithm !== 'rfc6962') throw new Error('merkle_inclusion.algorithm must be "rfc6962"');
  const leafHex = String(mi.leaf).replace(/^sha256:/, '');
  if (!/^[0-9a-f]{64}$/.test(leafHex)) throw new Error('merkle_inclusion.leaf must be a 64-hex digest');
  if (artifactHashHex !== undefined && leafHex !== String(artifactHashHex).replace(/^sha256:/, '')) {
    throw new Error('merkle_inclusion.leaf != artifact hash');
  }
  if (!Number.isInteger(mi.index) || mi.index < 0) throw new Error('merkle_inclusion.index must be a non-negative integer');
  if (!Number.isInteger(mi.tree_size) || mi.tree_size <= 0) throw new Error('merkle_inclusion.tree_size must be a positive integer');
  if (!Array.isArray(mi.path)) throw new Error('merkle_inclusion.path must be an array');
  const L = await leafHash(hexToU8(leafHex));
  const pathNodes = mi.path.map((h) => hexToU8(String(h).replace(/^sha256:/, '')));
  const root = await rootFromInclusion(L, mi.index, mi.tree_size, pathNodes);
  if (!root) throw new Error('inclusion path does not reconstruct a root (index/size/path inconsistent)');
  const rootHex = u8ToHex(root);
  if (rootHex !== String(anchoredHashHex).replace(/^sha256:/, '')) throw new Error('reconstructed Merkle root != anchored_hash');
  return { rootHex };
}
