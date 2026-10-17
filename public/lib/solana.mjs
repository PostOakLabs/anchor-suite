// solana.mjs — OCG §20.4 `solana-memo` binding verifier (verification-only leg).
//
// A solana-memo binding is LEDGER-ORDERING evidence: the anchored hash (or, under
// §20.1 merkle_inclusion, the Merkle root) was written into a Solana transaction's
// Memo-program instruction by the holder of a named signer key, and the transaction
// landed in a named slot. It proves "committed no later than slot N by holder of key
// K" — nothing more. It is NOT an RFC 3161 token, NOT eIDAS, there is no signed
// time, blockTime is a validator estimate, and there is NO offline verification:
// checking it structurally requires a Solana JSON-RPC endpoint, chosen by whoever
// verifies (this module never bundles or prefers one, beyond what the caller passes).
//
// The verification-only discipline (SPEC §20.4): this module holds no key, mints
// nothing, signs nothing, submits nothing. It only READS a transaction the caller's
// RPC returns. Stage 2 (writing anchors) is out of scope by design.
//
// Zero dependencies beyond WebCrypto-free string work + the shared merkle.mjs
// (§20.1 inclusion check reuses the same RFC 6962 implementation as every other
// binding — no second Merkle tree). Runs in the Worker and in the browser.

import { verifyMerkleInclusion } from './merkle.mjs';

// The two Memo programs that ever existed on Solana: the legacy spl-memo and the
// current Memo program. A memo instruction from either commits its data.
export const SOLANA_MEMO_PROGRAMS = new Set([
  'Memo1UhkJR1HyELaSYHKif5up2ibsXFelhsjoJh4fwKNHW', // legacy spl-memo
  'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',    // current Memo program
]);

const B58_TX_SIG = /^[1-9A-HJ-NP-Za-km-z]{87,88}$/;
const B58_PUBKEY = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;
const SHA256_REF = /^sha256:[0-9a-f]{64}$/;
const CLUSTERS = new Set(['mainnet-beta', 'devnet', 'testnet']);

const DEFAULT_TIMEOUT_MS = 15000;

// ---------------------------------------------------------------------------
// Shape validation (mirrors the OCG schema oneOf variant for this type)
// ---------------------------------------------------------------------------

export function validateSolanaMemoBindingShape(b) {
  const errs = [];
  if (!b || typeof b !== 'object') return ['binding is not an object'];
  if (b.type !== 'solana-memo') errs.push('type must be "solana-memo"');
  if (!CLUSTERS.has(b.cluster)) errs.push('cluster must be mainnet-beta, devnet or testnet');
  if (typeof b.signature !== 'string' || !B58_TX_SIG.test(b.signature)) {
    errs.push('signature must be a base58 transaction signature (87-88 chars)');
  }
  if (!Number.isInteger(b.slot) || b.slot < 0) errs.push('slot must be a non-negative integer');
  if (b.commitment !== 'finalized') errs.push('commitment must be "finalized" (the only level §20.4 defines)');
  if (typeof b.signer !== 'string' || !B58_PUBKEY.test(b.signer)) {
    errs.push('signer must be a base58 pubkey (43-44 chars)');
  }
  if (typeof b.anchored_hash !== 'string' || !SHA256_REF.test(b.anchored_hash)) {
    errs.push('anchored_hash must be "sha256:<64 lowercase hex>"');
  }
  if (b.block_time !== undefined && b.block_time !== null && !Number.isInteger(b.block_time)) {
    errs.push('block_time, when present, must be an integer (unix seconds) or null');
  }
  return errs;
}

// ---------------------------------------------------------------------------
// RPC endpoint handling — the endpoint is ALWAYS the verifier's choice
// ---------------------------------------------------------------------------

function isIpLiteralOrLocal(host) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[') ||
    host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local');
}

// Parse + validate a user-chosen RPC URL. workerSide adds the SSRF posture the
// Worker owes (https only, no IP literals / localhost, no embedded credentials);
// the browser is free to point at a local dev RPC.
export function normalizeSolanaRpcUrl(raw, { workerSide = false } = {}) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('RPC endpoint is not a valid URL'); }
  if (workerSide) {
    if (u.protocol !== 'https:') throw new Error('RPC endpoint must be https:// when verified through the Worker');
    if (isIpLiteralOrLocal(u.hostname)) throw new Error('RPC endpoint must be a public https hostname, not an IP literal or localhost');
  } else if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new Error('RPC endpoint must be http(s)://');
  }
  if (u.username || u.password) throw new Error('RPC endpoint must not embed credentials');
  return u.toString();
}

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

// Collect the memo text: every instruction whose program is a Memo program
// contributes its data; the on-chain convention concatenates them in order.
// jsonParsed gives spl-memo instructions { program: 'spl-memo', parsed: 'text' }.
// Unknown-program shape { programId, accounts, data } is handled by programId.
function collectMemoTexts(transaction) {
  const out = [];
  const instructions = [];
  const tx = transaction?.transaction || {};
  if (Array.isArray(tx.instructions)) instructions.push(...tx.instructions);
  if (Array.isArray(tx.message?.instructions)) instructions.push(...tx.message.instructions);
  for (const ins of instructions) {
    if (!ins || typeof ins !== 'object') continue;
    const programId = typeof ins.programId === 'string' ? ins.programId : null;
    const isMemo = ins.program === 'spl-memo' || (programId && SOLANA_MEMO_PROGRAMS.has(programId));
    if (!isMemo) continue;
    if (typeof ins.parsed === 'string') out.push(ins.parsed);
    else if (ins.data != null) out.push({ unparsed: ins.data }); // json encoding fallback, base58
  }
  return out;
}

function signerAccounts(transaction) {
  const keys = transaction?.transaction?.message?.accountKeys;
  if (!Array.isArray(keys)) return null;
  const flags = [];
  for (const k of keys) {
    if (typeof k === 'string') return { bare: true };
    if (k && typeof k.pubkey === 'string') flags.push({ pubkey: k.pubkey, signer: k.signer === true });
  }
  return { accounts: flags };
}

export async function verifySolanaMemoBinding(binding, opts = {}) {
  const shapeErrs = validateSolanaMemoBindingShape(binding);
  if (shapeErrs.length) return { ok: false, verdict: 'invalid', reasons: shapeErrs, caveats: [] };

  const {
    rpcUrl,
    signerAllowlist = null,
    artifactHashHex,
    fetchImpl = null,
    workerSide = false,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = opts;

  if (!rpcUrl || typeof rpcUrl !== 'string') {
    return {
      ok: false, verdict: 'invalid',
      reasons: ['solana-memo verification requires an RPC endpoint chosen by the verifier (none provided)'],
      caveats: [],
    };
  }

  let endpoint;
  try {
    endpoint = normalizeSolanaRpcUrl(rpcUrl, { workerSide });
  } catch (e) {
    return { ok: false, verdict: 'invalid', reasons: [e.message], caveats: [] };
  }

  const doFetch = fetchImpl || (typeof fetch === 'function' ? fetch : null);
  if (!doFetch) return { ok: false, verdict: 'error', reasons: ['no fetch implementation available'], caveats: [] };

  // getTransaction at FINALIZED: an RPC answering at finalized only returns the
  // transaction once its block is finalized (economic finality, not legal).
  let body;
  try {
    const res = await doFetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1, method: 'getTransaction',
        params: [binding.signature, {
          commitment: 'finalized',
          maxSupportedTransactionVersion: 0,
          encoding: 'jsonParsed',
        }],
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return { ok: false, verdict: 'error', reasons: ['RPC HTTP ' + res.status], caveats: [] };
    body = await res.json();
  } catch (e) {
    return { ok: false, verdict: 'error', reasons: ['RPC call failed: ' + (e.message || String(e))], caveats: [] };
  }
  if (body?.error) {
    return { ok: false, verdict: 'error', reasons: ['RPC error: ' + (body.error.message || JSON.stringify(body.error))], caveats: [] };
  }
  const tx = body?.result;
  if (!tx || typeof tx !== 'object') {
    return {
      ok: false, verdict: 'invalid',
      reasons: ['transaction not found at finalized commitment (unknown signature, pruned history, or wrong cluster/RPC)'],
      caveats: [],
    };
  }

  const reasons = [];
  const caveats = [];

  // (3) slot equality — the receipt's slot IS the claim "no later than slot N".
  if (!Number.isInteger(tx.slot) || tx.slot !== binding.slot) {
    reasons.push('slot mismatch: binding says ' + binding.slot + ', transaction landed in ' + tx.slot);
  }

  // (2) memo data equals anchored_hash (or the committed root under §20.1).
  const expected = binding.anchored_hash;
  const memoParts = collectMemoTexts(tx);
  const hasUnparsed = memoParts.some((p) => p && typeof p === 'object');
  const memoText = memoParts.map((p) => (typeof p === 'string' ? p : '')).join('');
  if (hasUnparsed) {
    reasons.push('memo instruction returned unparsed data; verifier requires jsonParsed encoding');
  } else if (memoText === '') {
    reasons.push('no Memo-program instruction found in the transaction');
  } else if (memoText !== expected) {
    reasons.push('memo data does not equal anchored_hash (or the committed Merkle root)');
  }

  // §20.1 inclusion, when present: leaf == artifact hash, reconstructed root == anchored_hash.
  if (binding.merkle_inclusion && typeof binding.merkle_inclusion === 'object') {
    try {
      await verifyMerkleInclusion(binding.merkle_inclusion, {
        anchoredHashHex: binding.anchored_hash.replace(/^sha256:/, ''),
        artifactHashHex,
      });
    } catch (e) {
      reasons.push('merkle_inclusion: ' + (e.message || String(e)));
    }
  }

  // (4) signer: must be among the transaction's signer-flagged accounts.
  const acc = signerAccounts(tx);
  if (acc === null || acc.bare === true) {
    reasons.push('RPC returned account keys without signer flags (jsonParsed encoding required)');
  } else {
    const entry = acc.accounts.find((a) => a.pubkey === binding.signer);
    if (!entry) reasons.push('signer ' + binding.signer + ' is not an account of this transaction');
    else if (!entry.signer) reasons.push('signer ' + binding.signer + ' did not sign this transaction');
  }

  // (5) signer allowlist: the verifier's published key list, when it holds one.
  let signerPinned = false;
  if (signerAllowlist !== null) {
    const list = Array.isArray(signerAllowlist) ? signerAllowlist : [signerAllowlist];
    const clean = list.filter((s) => typeof s === 'string' && s.trim() !== '').map((s) => s.trim());
    if (clean.length === 0) {
      reasons.push('signer_allowlist provided but empty');
    } else if (!clean.includes(binding.signer)) {
      reasons.push('signer ' + binding.signer + ' is not on the provided signer allowlist');
    } else {
      signerPinned = true;
    }
  } else {
    caveats.push('signer not pinned: anyone can write the same memo; the binding proves only what the ledger records');
  }

  // cluster vs endpoint: a heuristic sanity check, honestly reported as one.
  let host = '';
  try { host = new URL(endpoint).hostname; } catch { /* already validated */ }
  const hostCluster = /devnet/.test(host) ? 'devnet' : /testnet/.test(host) ? 'testnet' : /mainnet/.test(host) ? 'mainnet-beta' : null;
  if (hostCluster && hostCluster !== binding.cluster) {
    reasons.push('cluster mismatch: binding says ' + binding.cluster + ', RPC hostname suggests ' + hostCluster);
  } else if (!hostCluster) {
    caveats.push('cluster not cross-checked against a custom RPC hostname');
  }

  // block_time is an ESTIMATE: a mismatch is reported, never silently accepted,
  // but it cannot invalidate the slot-ordered claim (the slot is the anchor).
  if (binding.block_time != null && tx.blockTime != null && binding.block_time !== tx.blockTime) {
    caveats.push('block_time estimate differs from the RPC\'s current estimate (validator-estimated, not signed)');
  }

  const ok = reasons.length === 0;
  return {
    ok,
    verdict: ok ? 'ok' : 'invalid',
    cluster: binding.cluster,
    slot: Number.isInteger(tx.slot) ? tx.slot : null,
    blockTime: Number.isInteger(tx.blockTime) ? tx.blockTime : null,
    signature: binding.signature,
    signer: binding.signer,
    signerPinned,
    memoMatched: memoText === expected && !hasUnparsed && memoText !== '',
    rpc: host,
    reasons,
    caveats,
  };
}
