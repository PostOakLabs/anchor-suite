// gate-solana-memo.mjs — offline gate for the OCG §20.4 verification-only
// solana-memo leg (ANCHOR-SOLANA-LEG-SPEC-1, Stage 1).
//
// Two halves:
//
// 1. GOLDEN PARITY — existing receipts verify IDENTICALLY. The checked-in
//    fixture tests/fixtures/golden-anchor-bindings.fixture.json was generated
//    by running origin/main's worker and this branch's worker through the same
//    MCP tools/call verify_anchor_binding (real Sigstore TST from
//    gate-tst-verify.mjs, an OTS pending entry, an unknown type) and asserting
//    byte-equal payloads. This gate re-runs the current tool over the same
//    inputs and requires the same results: the rfc3161 path still verifies the
//    real token against the pinned root, OTS still returns pending, and the
//    unknown-type fallback still answers "unsupported binding type" — for
//    unknown types INCLUDING unknown solana-ish spellings (solana-memo-v9),
//    which must NOT be silently accepted by the new branch.
//
// 2. §20.4 VERIFIER — every path of public/lib/solana.mjs against a MOCKED RPC
//    (deterministic; this gate never touches the network, same discipline as
//    every other gate). Proves: the happy path verifies memo==anchored_hash at
//    finalized with the recorded signer; a caller-pinned signer allowlist is
//    enforced both ways; slot/memo/signer/not-found/allowlist misses FAIL; the
//    §20.1 merkle leg reconstructs the root from leaf+path through the SAME
//    merkle.mjs implementation every other binding uses; the missing-RPC entry
//    is invalid with a clear reason (never an error); the Worker-side SSRF
//    posture rejects non-https / IP-literal endpoints; and block_time is
//    treated as an estimate (mismatch = caveat, never validity).
//
// No key, no secret and no write path exists anywhere in this leg — the
// verification-only discipline is the point (Stage 2 is out of scope).

import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { toolVerifyAnchorBinding } from '../src/worker.mjs';
import { verifySolanaMemoBinding, validateSolanaMemoBindingShape } from '../public/lib/solana.mjs';
import { leafHash, mth, auditPath } from '../public/lib/merkle.mjs';

function hexToU8(hex) {
  const h = String(hex).replace(/^sha256:/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function u8Hex(u8) { return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join(''); }

let failed = 0;
function check(label, cond, detail = '') {
  if (cond) console.log('gate-solana-memo: ' + label + '... ok');
  else { failed++; console.error('gate-solana-memo: ' + label + '... FAIL' + (detail ? ' — ' + detail : '')); }
}

// ---------------------------------------------------------------------------
// Part 1: golden parity — existing receipts unchanged
// ---------------------------------------------------------------------------

const golden = JSON.parse(readFileSync(new URL('../tests/fixtures/golden-anchor-bindings.fixture.json', import.meta.url), 'utf8'));

{
  const out = await toolVerifyAnchorBinding({ anchors: { anchor_bindings: golden.inputs } });
  const same = JSON.stringify(out.results) === JSON.stringify(golden.expectedResults);
  if (!same && process.argv.includes('--update-golden')) {
    // Regeneration path: only ever updates expectedResults from the SAME inputs.
    // If the inputs themselves need to change, the fixture must be regenerated
    // from a genuine old-vs-new comparison, never hand-edited.
    golden.expectedResults = out.results;
    writeFileSync(new URL('../tests/fixtures/golden-anchor-bindings.fixture.json', import.meta.url),
      JSON.stringify(golden, null, 2) + '\n');
    console.log('gate-solana-memo: golden fixture updated (same inputs, new expectedResults)');
    process.exit(0);
  }
  check('golden parity: rfc3161/ots/unknown outputs identical to fixture', same,
    'got ' + JSON.stringify(out.results?.map((r) => [r.type, r.valid])));
  check('golden parity: real TST still verifies against the pinned root',
    out.results?.[0]?.valid === true && out.results?.[0]?.type === 'rfc3161-tst');
  check('golden parity: unknown-type fallback unchanged',
    out.results?.[2]?.reasons?.[0] === 'unsupported binding type: made-up-v0');
}

{
  const out = await toolVerifyAnchorBinding({
    anchors: { anchor_bindings: [{ type: 'solana-memo-v9', anchored_hash: 'sha256:' + 'ab'.repeat(32) }] },
  });
  check('unknown near-miss type solana-memo-v9 still hits the fallback',
    out.results?.[0]?.reasons?.[0] === 'unsupported binding type: solana-memo-v9');
}

// ---------------------------------------------------------------------------
// Fixtures for part 2
// ---------------------------------------------------------------------------

const HASH = 'sha256:' + '1f'.repeat(32);
// Synthetic base58-shaped identifiers (shape-only checks; nothing on-chain):
const SIGNER = 'A'.repeat(43);
const OTHER = 'B'.repeat(43);
const SIG = 'S'.repeat(88);
const SLOT = 312345678;
const BLOCK_TIME = 1762000000;
const RPC = 'https://api.mainnet-beta.solana.com';

function rpcResponse(result) {
  return async () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 });
}

function finalizedTx({ memo = HASH, signerFlag = true, slot = SLOT, signer = SIGNER } = {}) {
  return {
    slot,
    blockTime: BLOCK_TIME,
    transaction: {
      message: {
        accountKeys: [
          { pubkey: signer, signer: signerFlag, writable: true },
          { pubkey: OTHER, signer: false, writable: false },
        ],
        instructions: [
          { program: 'spl-memo', programId: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', parsed: memo },
        ],
      },
    },
  };
}

function baseBinding(over = {}) {
  return {
    type: 'solana-memo',
    cluster: 'mainnet-beta',
    signature: SIG,
    slot: SLOT,
    block_time: BLOCK_TIME,
    commitment: 'finalized',
    signer: SIGNER,
    anchored_hash: HASH,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Part 2a: the shared verifier directly
// ---------------------------------------------------------------------------

{
  const r = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: RPC, fetchImpl: rpcResponse(finalizedTx()) });
  check('happy path: valid, memo matched, slot read back',
    r.ok === true && r.memoMatched === true && r.slot === SLOT && r.verdict === 'ok');
  check('happy path: unpinned signer carried as an explicit caveat, not silence',
    r.signerPinned === false && r.caveats.some((c) => c.includes('not pinned')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), {
    rpcUrl: RPC, signerAllowlist: [SIGNER], fetchImpl: rpcResponse(finalizedTx()),
  });
  check('allowlist hit: pinned, no unpinned caveat',
    r.ok === true && r.signerPinned === true && !r.caveats.some((c) => c.includes('not pinned')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), {
    rpcUrl: RPC, signerAllowlist: [OTHER], fetchImpl: rpcResponse(finalizedTx()),
  });
  check('allowlist miss: invalid with allowlist reason',
    r.ok === false && r.reasons.some((x) => x.includes('not on the provided signer allowlist')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: RPC, fetchImpl: rpcResponse(finalizedTx({ memo: 'sha256:' + '9e'.repeat(32) })) });
  check('memo mismatch fails', r.ok === false && r.reasons.some((x) => x.includes('memo data does not equal')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: RPC, fetchImpl: rpcResponse(finalizedTx({ slot: SLOT + 1 })) });
  check('slot mismatch fails', r.ok === false && r.reasons.some((x) => x.includes('slot mismatch')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: RPC, fetchImpl: rpcResponse(finalizedTx({ signerFlag: false })) });
  check('non-signer account fails', r.ok === false && r.reasons.some((x) => x.includes('did not sign this transaction')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: RPC, fetchImpl: rpcResponse(null) });
  check('not found at finalized is invalid, not an error',
    r.ok === false && r.verdict === 'invalid' && r.reasons.some((x) => x.includes('not found at finalized')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), {
    rpcUrl: RPC,
    fetchImpl: async () => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { message: 'rate limited' } }), { status: 200 }),
  });
  check('RPC JSON error surfaces as verdict error', r.ok === false && r.verdict === 'error' && r.reasons[0].includes('rate limited'));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: RPC, fetchImpl: rpcResponse(finalizedTx({ signerFlag: true })) });
  // block_time estimate differs from tx.blockTime on purpose:
  const r2 = await verifySolanaMemoBinding(baseBinding({ block_time: BLOCK_TIME + 37 }), {
    rpcUrl: RPC, fetchImpl: rpcResponse(finalizedTx()),
  });
  check('block_time estimate mismatch is a caveat, never invalidates the slot-ordered claim',
    r.ok === true && r2.ok === true && r2.caveats.some((c) => c.includes('validator-estimated')));
}

{
  const r = await verifySolanaMemoBinding(baseBinding(), {});
  check('no RPC provided: invalid with the missing-RPC reason',
    r.ok === false && r.reasons.some((x) => x.includes('requires an RPC endpoint')));
}

{
  const bad = validateSolanaMemoBindingShape({ type: 'solana-memo', cluster: 'mainnet', commitment: 'confirmed' });
  check('shape validation rejects bad cluster and commitment', bad.length >= 2, JSON.stringify(bad));
}

// Worker-side endpoint posture (workerSide: true is what the MCP tool passes
// on its real runtime path; browser callers may use a local dev RPC)
{
  const r1 = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: 'http://127.0.0.1:8899', workerSide: true });
  const r2 = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: 'https://198.51.100.7/rpc', workerSide: true });
  const r3 = await verifySolanaMemoBinding(baseBinding(), { rpcUrl: 'https://user:pass@api.mainnet-beta.solana.com', workerSide: true });
  check('workerSide posture: localhost http rejected',
    !r1.ok && (r1.reasons[0].includes('https') || r1.reasons[0].includes('IP literal')), r1.reasons.join('; '));
  check('workerSide posture: IP literal https rejected', !r2.ok && r2.reasons[0].includes('IP literal'), r2.reasons.join('; '));
  check('workerSide posture: embedded credentials rejected', !r3.ok && r3.reasons[0].includes('credentials'), r3.reasons.join('; '));
}

// ---------------------------------------------------------------------------
// Part 2b: §20.1 merkle leg — same merkle.mjs as every other binding
// ---------------------------------------------------------------------------

{
  const leafHex = 'aa'.repeat(32);
  const siblingHex = 'bb'.repeat(32);
  const leafHashes = [await leafHash(hexToU8(leafHex)), await leafHash(hexToU8(siblingHex))];
  const rootHex = u8Hex(await mth(leafHashes));
  const path = (await auditPath(0, leafHashes)).map((h) => 'sha256:' + u8Hex(h));
  const rootRef = 'sha256:' + rootHex;

  const b = baseBinding({ anchored_hash: rootRef, merkle_inclusion: { leaf: 'sha256:' + leafHex, index: 0, path, tree_size: 2, algorithm: 'rfc6962' } });
  const r = await verifySolanaMemoBinding(b, {
    rpcUrl: RPC,
    artifactHashHex: leafHex,
    fetchImpl: rpcResponse(finalizedTx({ memo: rootRef })),
  });
  check('merkle leg: memo commits the root, inclusion reconstructs it, verifies',
    r.ok === true && r.memoMatched === true, JSON.stringify(r.reasons));

  const rWrongLeaf = await verifySolanaMemoBinding(b, {
    rpcUrl: RPC,
    artifactHashHex: 'cc'.repeat(32), // artifact hash is NOT the leaf
    fetchImpl: rpcResponse(finalizedTx({ memo: rootRef })),
  });
  check('merkle leg: leaf != artifact hash fails', rWrongLeaf.ok === false && rWrongLeaf.reasons.some((x) => x.includes('merkle_inclusion')));

  const rWrongMemo = await verifySolanaMemoBinding(b, {
    rpcUrl: RPC,
    artifactHashHex: leafHex,
    fetchImpl: rpcResponse(finalizedTx({ memo: 'sha256:' + '00'.repeat(32) })), // memo commits something else
  });
  check('merkle leg: memo not committing the root fails', rWrongMemo.ok === false);
}

// ---------------------------------------------------------------------------
// Part 2c: through the MCP tool (entry shape + missing-RPC path)
// ---------------------------------------------------------------------------

{
  const out = await toolVerifyAnchorBinding({ binding: baseBinding() });
  const e = out.results?.[0];
  check('tool entry without solana_rpc: invalid, clear reason, never an error',
    e?.type === 'solana-memo' && e?.valid === false && e?.verdict === 'invalid' &&
    e?.reasons?.some((x) => x.includes('solana_rpc')) && e?.caveats !== undefined,
    JSON.stringify(e?.reasons));
}

{
  const out = await toolVerifyAnchorBinding(
    {
      binding: baseBinding(),
      solana_rpc: RPC,
      signer_allowlist: [SIGNER],
      artifact_hash: HASH,
    },
    { fetchImpl: rpcResponse(finalizedTx()) },
  );
  const e = out.results?.[0];
  check('tool entry with mocked RPC + allowlist: valid, pinned, gen_time from blockTime',
    e?.valid === true && e?.verdict === 'ok' && e?.signer_pinned === true && e?.memo_matched === true &&
    e?.gen_time === new Date(BLOCK_TIME * 1000).toISOString() && e?.tsa === 'mainnet-beta' && e?.slot === SLOT,
    JSON.stringify(e));
}

if (failed) {
  console.error('\ngate-solana-memo: ' + failed + ' check(s) failed');
  process.exit(1);
}
console.log('\ngate-solana-memo: all checks green (golden parity + §20.4 verifier)');
