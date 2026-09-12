// sigsum.mjs — client-side Sigsum (seasalp) leaf/checkpoint construction and
// OFFLINE proof verification. Shares the AINumbers site repo's wire protocol
// and verification posture with scripts/register-sigsum.mjs (fetched fresh
// 2026-08-10 from sigsum-go's current implementation — see that script's
// header comment for the protocol source list). Kept as an independent copy
// here per repo fence discipline (anchor-suite is a separate repo from the
// site).
//
// ⚠ NOT byte-for-byte with the site script, and the differences are load-
// bearing (the "byte-for-byte mirror" this comment used to claim was stale;
// ANCH-QUORUM-LIFECYCLE-1, 2026-09-10):
//   · this file pins 12 seasalp cosigners, the site pins the policy's 3;
//   · the site accepts records anchored to EITHER sigsum-generic-2025-1 log
//     (seasalp, ginkgo), this file knows seasalp only;
//   · the site pins the log key and refuses a record that names its own
//     (SO #34); this file still falls back to b.log_public_key — see the
//     note on that fallback in verifySigsumBinding below.
// What IS identical, deliberately, is the quorum posture: k = 2 counted over
// the three sigsum-generic-2025-1 witnesses.
//
// verifySigsumBinding() below NEVER makes a network call — every byte it
// needs lives in the anchor_bindings entry already (Chainpoint guard).

import { hexToBytes, bytesHex, bytesToBase64, base64ToBytes } from './tsq.mjs';

export const LOG_URL = 'https://seasalp.glasklar.is';
export const LOG_PUBLIC_KEY_HEX = '0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25';
// Full seasalp cosigner set as observed on the live tree head 2026-08-20:
// 12 witnesses, every key from a published source and hash-matched against
// the head's cosignature key_hashes before pinning. Sources: glasklar/mullvad/
// tillitis = sigsum-generic-2025-1 vetted trust policy (sigsum-go
// pkg/policy/builtin); the 9 ArmoredWitness devices = transparency-dev/
// armored-witness devices/prod/*.witness.0 ID attestations (vkey alg byte
// stripped).
//
// TWO SETS, ONE LIST (ANCH-QUORUM-LIFECYCLE-1, 2026-09-10). `quorum: true`
// marks the THREE witnesses named in the sigsum-generic-2025-1 trust policy;
// the other nine are RECOGNITION-ONLY pins. A cosignature from a recognition
// pin is displayed and counted in `witnessesOk`, but it can never carry the
// verdict — quorum is counted over the policy group alone (see
// WITNESS_QUORUM_THRESHOLD below). Unknown cosigners are still simply skipped.
export const WITNESSES = [
  { name: 'witness.glasklar.is', keyHex: 'b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536', quorum: true },
  { name: 'witness.mullvad.net', keyHex: '15d6d0141543247b74bab3c1076372d9c894f619c376d64b29aa312cc00f61ad', quorum: true },
  { name: 'tillitis.se/tillitis-witness-1', keyHex: '076be8c9ee7ea60916f0df3608c945d7730082ecb37749dad2c9ed339fea770c', quorum: true },
  { name: 'ArmoredWitness-falling-pond', keyHex: '54c4862caba4ef942fe1abc6afb65d63cba0a55d3e6313ff59154b8586d882e2' },
  { name: 'ArmoredWitness-wispy-wood', keyHex: '456f659e0b0efa658e3a2895e2775a7c6754ae09d5842241bb603d649517068f' },
  { name: 'ArmoredWitness-quiet-wood', keyHex: '9b71799be731b15fe9b54f37cd6f22f9499d3e3309dabcb588bf82e234844913' },
  { name: 'ArmoredWitness-morning-darkness', keyHex: '7ba003654674398b62dd70ab369a3f750a48670354d66f79125827514a0b9fbd' },
  { name: 'ArmoredWitness-shy-wind', keyHex: '198bed2687bcf60fc246eae3583f2a9764287ece65aa1aa9f2b6b04a1628be1d' },
  { name: 'ArmoredWitness-hidden-river', keyHex: 'dae934c7cc1f45ba898a3dfe1265d492a6c58405ddec143fc16f84a0f588e3a5' },
  { name: 'ArmoredWitness-throbbing-bird', keyHex: '98149a5d739b3baa777128f617531ce8b654d24502a7e151244cc5b7597667bc' },
  { name: 'ArmoredWitness-rough-wind', keyHex: 'ea31934afb8632958de2fb37dd9bfabb8dc7961dea67a6ae4c57f1a1ca26eef7' },
  { name: 'ArmoredWitness-floral-sky', keyHex: 'e90299398a4d39d030da888a0923ecf16786881ac12243db73c9f0cf2a2d80e6' },
];

// The named policy's own rule, transcribed:
//   group quorum-rule 2 witness.glasklar.is witness.mullvad.net tillitis.se/tillitis-witness-1
//   quorum quorum-rule
// k is 2 and the DENOMINATOR IS THREE. It is not scaled to the 12 pins above,
// and that is the whole adjudication: were quorum counted over all 12, a record
// cosigned by two ArmoredWitness devices and by none of the policy witnesses
// would pass here while sigsum-generic-2025-1 rejects it — this verifier would
// be strictly weaker than the policy it names, in the direction that matters.
// Counting over the policy group keeps this file's posture identical to the
// site's scripts/register-sigsum.mjs (WITNESS_QUORUM_THRESHOLD = 2 over its
// three-witness pin set), which is what the header's "mirrors the site" claim
// has always promised.
export const WITNESS_QUORUM_THRESHOLD = 2;
export const QUORUM_POLICY_NAME = 'sigsum-generic-2025-1';

const CHECKPOINT_ORIGIN_PREFIX = 'sigsum.org/v1/tree/';
const COSIGNATURE_NAMESPACE = 'cosignature/v1';
const TREE_LEAF_NAMESPACE = 'sigsum.org/v1/tree-leaf';

const subtle = crypto.subtle;
const enc = new TextEncoder();

function concatBytes(...arrs) {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

async function sha256(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); }
async function hashLeafNode(b) { return sha256(concatBytes(new Uint8Array([0x00]), b)); }
async function hashInteriorNode(l, r) { return sha256(concatBytes(new Uint8Array([0x01]), l, r)); }

function attachNamespace(namespace, msgBytes) {
  return concatBytes(enc.encode(namespace), new Uint8Array([0x00]), msgBytes);
}

function leafToBinary({ checksum, signature, keyHash }) {
  return concatBytes(checksum, signature, keyHash);
}

function bytesToBase64Std(bytes) { return bytesToBase64(bytes); } // tsq.mjs's base64 is already standard alphabet

function formatCheckpoint(origin, size, rootHash) {
  return `${origin}\n${size}\n${bytesToBase64Std(rootHash)}\n`;
}

async function sigsumCheckpointOrigin(logPublicKeyBytes) {
  const h = await sha256(logPublicKeyBytes);
  return `${CHECKPOINT_ORIGIN_PREFIX}${bytesHex(h)}`;
}

function toCosignedData(origin, size, rootHash, timestamp) {
  return `${COSIGNATURE_NAMESPACE}\ntime ${timestamp}\n${formatCheckpoint(origin, size, rootHash)}`;
}

// RFC 9162 §2.1.3.2 inclusion-proof verification — same algorithm as
// register-sigsum.mjs / sigsum-go's merkle.VerifyInclusion.
async function verifyInclusion({ leaf, index, size, root, path }) {
  let r = leaf;
  let fn = index;
  let remaining = path;
  for (let sn = size - 1; sn > 0; fn = Math.floor(fn / 2), sn = Math.floor(sn / 2)) {
    const isOdd = (fn & 1) === 1;
    if (isOdd) {
      r = await hashInteriorNode(remaining[0], r);
      remaining = remaining.slice(1);
    } else if (fn < sn) {
      r = await hashInteriorNode(r, remaining[0]);
      remaining = remaining.slice(1);
    }
  }
  return bytesHex(r) === bytesHex(root);
}

function bytesEq(a, b) { return bytesHex(a) === bytesHex(b); }

async function importEd25519Public(hex) {
  return subtle.importKey('raw', hexToBytes(hex), { name: 'Ed25519' }, true, ['verify']);
}

// ---------------------------------------------------------------------------
// Registration (POST via the same-origin /relay/sigsum/* proxy — seasalp
// itself has no CORS headers). Returns an anchor_bindings entry, type
// 'c2sp-tlog-proof-v1', matching the shape verifySigsumBinding() below reads.
//
// NOTE: the rate-limit token (Sigsum-Token) is never held or seen by this
// file. seasalp enforces "288 entries per 24h for each domain suffix", and
// ainumbers.co's own bucket is unlocked by the DNS TXT record at
// _sigsum_v1.ainumbers.co plus a signing key held server-side; a tokenless
// caller falls into a shared "unknown domain" bucket that measured 429 in
// testing (SIGSUM-ANCHOR-1 check-off). The relay attaches the token for us,
// and only to submissions carrying the first-party session artifact minted
// below — so a submission without one still reaches the log, it just lands in
// the shared bucket and may come back 429. Either outcome is surfaced to the
// user rather than hidden.
// ---------------------------------------------------------------------------

// Session artifact for the add-leaf relay. Opaque here: it is minted and
// verified server-side (src/worker.mjs sealSigsumSession) and carries no
// secret. Held in memory for the life of the page only — nothing is stored,
// and a failed mint is never fatal: the stamp proceeds without it.
const SESSION_HEADER = 'X-Anchor-Session';
let sessionArtifact = null; // { value, expiresAt } | null

async function sessionHeaders() {
  const now = Date.now();
  if (!sessionArtifact || sessionArtifact.expiresAt <= now + 5_000) {
    sessionArtifact = null;
    try {
      const res = await fetch('/relay/sigsum/session', { signal: AbortSignal.timeout(10_000) });
      if (res.ok) {
        const body = await res.json();
        const ttl = Number(body?.ttl_ms);
        if (typeof body?.session === 'string' && body.session.length > 0 && ttl > 0) {
          sessionArtifact = { value: body.session, expiresAt: now + ttl };
        }
      }
    } catch {
      // Mint unreachable: submit tokenless rather than block the stamp.
    }
  }
  return sessionArtifact ? { [SESSION_HEADER]: sessionArtifact.value } : {};
}

export async function stampSigsum(hashHex) {
  const messageBytes = hexToBytes(hashHex);
  const keyPair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKeyBytes = new Uint8Array(await subtle.exportKey('raw', keyPair.publicKey));

  const checksum = await sha256(messageBytes);
  const leafSigData = attachNamespace(TREE_LEAF_NAMESPACE, checksum);
  const leafSignature = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, keyPair.privateKey, leafSigData));

  const body = `message=${bytesHex(messageBytes)}\nsignature=${bytesHex(leafSignature)}\npublic_key=${bytesHex(publicKeyBytes)}\n`;

  const submitRes = await fetch('/relay/sigsum/add-leaf', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain; charset=utf-8', ...(await sessionHeaders()) },
    body,
    signal: AbortSignal.timeout(30_000),
  });
  const submitText = await submitRes.text();
  if (submitRes.status !== 200 && submitRes.status !== 202) {
    throw new Error(`Sigsum add-leaf HTTP ${submitRes.status}: ${submitText.slice(0, 200)}`);
  }

  const keyHash = await sha256(publicKeyBytes);
  const leafHash = await hashLeafNode(leafToBinary({ checksum, signature: leafSignature, keyHash }));

  const pending = {
    // Pending binding: the leaf is submitted and in flight; inclusion has not
    // been observed yet. A transparency log is asynchronous — seasalp merges
    // and gathers witness cosignatures on its own cadence — so the stamp
    // returns immediately with everything needed to upgrade later, mirroring
    // the OpenTimestamps submit-now/upgrade-later treatment. The tab never
    // blocks on a witness round. Upgrade with upgradeSigsumBinding() below.
    // Keep this object in the exported bindings so a closed tab does not
    // orphan a submitted leaf whose proof was never collected.
    type: 'c2sp-tlog-pending-v1',
    anchored_hash: 'sha256:' + hashHex,
    log_origin: await sigsumCheckpointOrigin(hexToBytes(LOG_PUBLIC_KEY_HEX)),
    log_url: LOG_URL,
    log_public_key: LOG_PUBLIC_KEY_HEX,
    leaf: {
      checksum: bytesHex(checksum),
      signature: bytesHex(leafSignature),
      public_key: bytesHex(publicKeyBytes),
    },
    leaf_hash: bytesHex(leafHash),
    submitted_at: new Date().toISOString(),
  };

  // One quick look for the lucky case where the merge already happened —
  // ~6s worst case, never a 38s frozen tab (the 2026-08-20 defect A).
  const upgraded = await tryFetchInclusion(pending, 3, 2000);
  return upgraded ?? pending;
}

// Re-check a pending binding against the log and, if the leaf is now
// sequenced, upgrade it to a complete 'c2sp-tlog-proof-v1'. Returns the
// complete binding on success, or the SAME pending binding (unchanged) if
// the leaf is still not observable — never throws for "not yet", only for
// transport-level surprises. This is the "check inclusion" action: it spends
// zero domain budget (GET paths are unmetered) and never re-submits the leaf
// — a re-stamp would burn another of the 288/24h entries and write a
// duplicate leaf into a permanent public log (defect A2, 2026-08-20).
export async function upgradeSigsumBinding(pending) {
  if (pending?.type !== 'c2sp-tlog-pending-v1') return pending;
  const upgraded = await tryFetchInclusion(pending, 3, 2000);
  return upgraded ?? pending;
}

async function tryFetchInclusion(pending, attempts, delayMs) {
  let cosignedHead = null;
  let inclusion = null;
  for (let attempt = 0; attempt < attempts && !inclusion; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, delayMs));
    let headRes;
    try {
      headRes = await fetch('/relay/sigsum/get-tree-head', { signal: AbortSignal.timeout(15_000) });
    } catch { continue; }
    if (headRes.status !== 200) continue;
    const head = parseAsciiLines(await headRes.text());
    const size = Number(head.size?.[0] ?? 0);
    if (size < 1) continue;
    let proofRes;
    try {
      proofRes = await fetch(`/relay/sigsum/get-inclusion-proof/${size}/${pending.leaf_hash}`, { signal: AbortSignal.timeout(15_000) });
    } catch { continue; }
    if (proofRes.status !== 200) continue;
    const proofFields = parseAsciiLines(await proofRes.text());
    cosignedHead = head;
    inclusion = {
      size,
      leafIndex: Number(proofFields.leaf_index[0]),
      path: (proofFields.node_hash || []).map(hexToBytes),
    };
  }
  if (!inclusion) return null;

  const rootHash = hexToBytes(cosignedHead.root_hash[0]);
  return {
    type: 'c2sp-tlog-proof-v1',
    anchored_hash: pending.anchored_hash,
    log_origin: pending.log_origin,
    log_url: pending.log_url,
    log_public_key: pending.log_public_key,
    leaf: pending.leaf,
    tree_head: {
      size: inclusion.size,
      root_hash: bytesHex(rootHash),
      log_signature: (cosignedHead.signature || [])[0],
    },
    inclusion_proof: {
      leaf_index: inclusion.leafIndex,
      path: inclusion.path.map(bytesHex),
    },
    witness_cosignatures: parseCosignatures(cosignedHead),
  };
}

// Each `cosignature=` line is ONE space-separated field:
//   <key_hash_hex> <timestamp> <signature_hex>
// — measured live behavior recorded in register-sigsum.mjs:376; the response
// never sends a parallel `key_hash=` field. The previous parse here read a
// nonexistent key_hash list and mis-indexed parts (defect B, 2026-08-20:
// key_hash=undefined, timestamp=NaN, signature=<the timestamp>) — latent
// only because the old 38s poll timed out first and masked it.
function parseCosignatures(cosignedHead) {
  const cosignatures = [];
  for (const line of cosignedHead.cosignature || []) {
    const parts = line.split(' ');
    cosignatures.push({ key_hash: parts[0], timestamp: Number(parts[1]), signature: parts[2] });
  }
  return cosignatures;
}

function parseAsciiLines(text) {
  const out = {};
  for (const line of text.split('\n')) {
    if (!line) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq);
    const val = line.slice(eq + 1);
    (out[key] ??= []).push(val);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Offline verification — NEVER calls seasalp. Verifies: the leaf commits to
// the claimed anchored_hash, the leaf signature, the RFC 6962 inclusion
// proof, the log's own checkpoint signature (pinned key), and the witness
// cosignatures (resolved by key hash against the 12 pins above) over the SAME
// checkpoint.
//
// THE VERDICT IS FOUR-VALUED, and `ok` is the conjunction of BOTH halves:
//   'ok'           every structural check passed AND the policy quorum is met.
//   'below-quorum' structure is sound, 1 policy witness cosigned, k is 2.
//   'log-only'     structure is sound, ZERO policy witnesses cosigned. The log
//                  asserts inclusion on its own authority and nobody else has
//                  countersigned that assertion, so a split view of the tree is
//                  not excluded. Sound is not the same as witnessed.
//   'invalid'      a structural check failed.
// Before ANCH-QUORUM-LIFECYCLE-1 `witnessesOk` was computed and then dropped on
// the floor: `ok` was the four structural checks alone, so a zero-witness record
// verified exactly like a fully cosigned one.
// ---------------------------------------------------------------------------

export async function verifySigsumBinding(b) {
  if (b?.type === 'c2sp-tlog-pending-v1') {
    // A pending binding proves submission material only — inclusion has not
    // been fetched yet, so there is nothing to verify offline. Distinct state,
    // never a pass and never a crash: upgrade it first (upgradeSigsumBinding).
    return {
      ok: false, pending: true, verdict: 'pending',
      checksumOk: null, leafSigOk: null, inclusionOk: null, logSigOk: null,
      witnessesOk: 0, quorumWitnessesOk: 0, quorumThreshold: WITNESS_QUORUM_THRESHOLD,
      quorumMet: false, quorumPolicy: QUORUM_POLICY_NAME, witnessDetail: [],
    };
  }
  const messageBytes = hexToBytes(b.anchored_hash.replace(/^sha256:/, ''));
  const recomputedChecksum = await sha256(messageBytes);
  const checksumOk = bytesHex(recomputedChecksum) === b.leaf.checksum;

  const leafPub = await importEd25519Public(b.leaf.public_key);
  const leafSigData = attachNamespace(TREE_LEAF_NAMESPACE, hexToBytes(b.leaf.checksum));
  const leafSigOk = await subtle.verify({ name: 'Ed25519' }, leafPub, hexToBytes(b.leaf.signature), leafSigData);

  const keyHash = await sha256(hexToBytes(b.leaf.public_key));
  const leafBin = leafToBinary({ checksum: hexToBytes(b.leaf.checksum), signature: hexToBytes(b.leaf.signature), keyHash });
  const leafHash = await hashLeafNode(leafBin);
  const root = hexToBytes(b.tree_head.root_hash);
  const inclusionOk = await verifyInclusion({
    leaf: leafHash, index: b.inclusion_proof.leaf_index, size: b.tree_head.size, root,
    path: b.inclusion_proof.path.map(hexToBytes),
  });

  // ⚠ KNOWN GAP, deliberately left in place by ANCH-QUORUM-LIFECYCLE-1 (whose
  // fence is quorum and lifecycle, not log pinning): this trusts the record's
  // OWN claim about which key signed the checkpoint, so a self-minted keypair
  // still satisfies logSigOk. The site fixed the same shape under SO #34 by
  // pinning LOGS and refusing anything else. Quorum gating above now MITIGATES
  // it — a self-signed log carries no pinned witness cosignatures, so such a
  // record lands on 'log-only' and never on 'ok' — but mitigation is not the
  // fix, and a follow-up row should pin the log key here as the site does.
  const logPub = await importEd25519Public(b.log_public_key || LOG_PUBLIC_KEY_HEX);
  const checkpointText = formatCheckpoint(b.log_origin, b.tree_head.size, root);
  const logSigOk = await subtle.verify({ name: 'Ed25519' }, logPub, hexToBytes(b.tree_head.log_signature), enc.encode(checkpointText));

  let witnessesOk = 0;
  let quorumWitnessesOk = 0;
  const witnessDetail = [];
  const countedQuorumKeys = new Set();
  for (const cs of b.witness_cosignatures || []) {
    let matched = null;
    for (const cand of WITNESSES) {
      const h = await sha256(hexToBytes(cand.keyHex));
      if (bytesHex(h) === cs.key_hash) { matched = cand; break; }
    }
    if (!matched) { witnessDetail.push({ key_hash: cs.key_hash, matched: false }); continue; }
    const wPub = await importEd25519Public(matched.keyHex);
    const cosData = toCosignedData(b.log_origin, b.tree_head.size, root, cs.timestamp);
    const ok = await subtle.verify({ name: 'Ed25519' }, wPub, hexToBytes(cs.signature), enc.encode(cosData));
    if (ok) {
      witnessesOk++;
      // One witness counts ONCE toward quorum however many cosignature lines it
      // signs: a record carrying the same witness twice (two timestamps over the
      // same checkpoint, which the wire format permits) must not self-assemble a
      // 2-of-3 quorum out of one signer.
      if (matched.quorum && !countedQuorumKeys.has(matched.keyHex)) {
        countedQuorumKeys.add(matched.keyHex);
        quorumWitnessesOk++;
      }
    }
    witnessDetail.push({ name: matched.name, matched: true, valid: ok, quorum: Boolean(matched.quorum) });
  }

  const structurallyOk = Boolean(checksumOk && leafSigOk && inclusionOk && logSigOk);
  const quorumMet = quorumWitnessesOk >= WITNESS_QUORUM_THRESHOLD;
  const verdict = !structurallyOk ? 'invalid'
    : quorumMet ? 'ok'
    : quorumWitnessesOk === 0 ? 'log-only'
    : 'below-quorum';
  return {
    ok: structurallyOk && quorumMet,
    verdict,
    structurallyOk,
    checksumOk, leafSigOk, inclusionOk, logSigOk,
    witnessesOk,
    quorumWitnessesOk,
    quorumThreshold: WITNESS_QUORUM_THRESHOLD,
    quorumMet,
    quorumPolicy: QUORUM_POLICY_NAME,
    witnessDetail,
  };
}
