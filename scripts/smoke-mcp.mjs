// smoke-mcp.mjs — post-deploy smoke for the /mcp endpoint.
//
// Checks:
//   1. initialize returns HTTP 200 with protocolVersion and serverInfo fields.
//   2. tools/list returns the five expected tools.
//   3. (optional) anchor_hash against Sigstore returns a binding that
//      verify_anchor_binding accepts as valid. Skipped without --round-trip.
//   4. (optional) Synthetic passkey assertion round-trip through
//      create_signature_envelope and verify_signature_envelope.
//      Skipped without --sig-round-trip.
//
// Exit codes:
//   0 — all checks passed
//   1 — an MCP structural failure (wrong protocol, missing tool, bad response)
//
// Usage:
//   node scripts/smoke-mcp.mjs                          # initialize + tools/list
//   node scripts/smoke-mcp.mjs --round-trip             # + anchor_hash/verify round-trip
//   node scripts/smoke-mcp.mjs --sig-round-trip         # + signature envelope round-trip
//   MCP_BASE=https://anchor.ainumbers.co node ...       # target override (default: live)

const BASE = process.env.MCP_BASE || 'https://anchor.ainumbers.co';
const MCP_URL = BASE + '/mcp';
const ROUND_TRIP = process.argv.includes('--round-trip');
const SIG_ROUND_TRIP = process.argv.includes('--sig-round-trip');
const BATCH_ROUND_TRIP = process.argv.includes('--batch-round-trip');

const EXPECTED_TOOLS = [
  'list_anchor_authorities',
  'anchor_hash',
  'anchor_batch',
  'verify_anchor_binding',
  'upgrade_ots_proof',
  'create_signature_envelope',
  'verify_signature_envelope',
];

let nextId = 1;

async function mcpCall(method, params = {}) {
  const id = nextId++;
  const res = await fetch(MCP_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  if (res.status !== 200) throw new Error(`HTTP ${res.status} from /mcp (method: ${method})`);
  const body = await res.json();
  if (body.error) throw new Error(`MCP error ${body.error.code}: ${body.error.message}`);
  return body.result;
}

// ---- 1. initialize ----------------------------------------------------------

process.stdout.write('smoke-mcp: checking initialize... ');
let initResult;
try {
  initResult = await mcpCall('initialize', {
    protocolVersion: '2024-11-05',
    capabilities: {},
    clientInfo: { name: 'smoke-mcp', version: '1.0' },
  });
} catch (e) {
  console.error('FAIL');
  console.error('  ' + e.message);
  process.exit(1);
}

if (!initResult.protocolVersion) {
  console.error('FAIL — missing protocolVersion in initialize response');
  process.exit(1);
}
if (!initResult.serverInfo?.name) {
  console.error('FAIL — missing serverInfo.name');
  process.exit(1);
}
console.log('ok (' + initResult.serverInfo.name + ' ' + (initResult.serverInfo.version || '') + ')');

// ---- 2. tools/list ----------------------------------------------------------

process.stdout.write('smoke-mcp: checking tools/list... ');
let toolsResult;
try {
  toolsResult = await mcpCall('tools/list');
} catch (e) {
  console.error('FAIL');
  console.error('  ' + e.message);
  process.exit(1);
}

const toolNames = (toolsResult.tools || []).map((t) => t.name);
const missing = EXPECTED_TOOLS.filter((n) => !toolNames.includes(n));
if (missing.length > 0) {
  console.error('FAIL — missing tools: ' + missing.join(', '));
  console.error('  got: ' + toolNames.join(', '));
  process.exit(1);
}
console.log('ok (' + toolNames.join(', ') + ')');

// ---- 3. anchor_hash + verify_anchor_binding round-trip (optional) -----------

if (ROUND_TRIP) {
  const TEST_HASH = 'sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576f3e7f9ce3c567b8d';

  process.stdout.write('smoke-mcp: anchor_hash (sigstore + freetsa)... ');
  let anchorResult;
  try {
    const r = await mcpCall('tools/call', {
      name: 'anchor_hash',
      arguments: { hash: TEST_HASH, authorities: ['sigstore', 'freetsa'] },
    });
    anchorResult = JSON.parse(r.content[0].text);
  } catch (e) {
    console.error('FAIL');
    console.error('  ' + e.message);
    process.exit(1);
  }

  if (!Array.isArray(anchorResult.anchor_bindings) || anchorResult.anchor_bindings.length === 0) {
    const fails = (anchorResult.failures || []).map((f) => f.authority + ': ' + f.reason).join('; ');
    console.error('FAIL — no anchor_bindings returned. failures: ' + (fails || 'none'));
    process.exit(1);
  }
  console.log('ok (' + anchorResult.anchor_bindings.length + ' binding(s), ' + (anchorResult.failures || []).length + ' failure(s))');

  process.stdout.write('smoke-mcp: verify_anchor_binding... ');
  let verifyResult;
  try {
    const r = await mcpCall('tools/call', {
      name: 'verify_anchor_binding',
      arguments: { anchors: { anchor_bindings: anchorResult.anchor_bindings } },
    });
    verifyResult = JSON.parse(r.content[0].text);
  } catch (e) {
    console.error('FAIL');
    console.error('  ' + e.message);
    process.exit(1);
  }

  const allValid = verifyResult.results?.every((r) => r.valid);
  if (!allValid) {
    const bad = (verifyResult.results || []).filter((r) => !r.valid);
    console.error('FAIL — some bindings did not verify:');
    for (const r of bad) console.error('  ' + r.tsa + ': ' + (r.reasons || []).join('; '));
    process.exit(1);
  }
  console.log('ok (' + verifyResult.results.length + ' valid)');
}

// ---- 4. create_signature_envelope + verify_signature_envelope (optional) ----

if (SIG_ROUND_TRIP) {
  // Synthetic P-256 fixture — no hardware passkey needed.
  // Uses Node.js WebCrypto (available since Node 19; required: Node 22 per CI).

  const DOC_DIGEST = 'sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234';

  process.stdout.write('smoke-mcp: create_signature_envelope... ');
  let createResult;
  try {
    const r = await mcpCall('tools/call', {
      name: 'create_signature_envelope',
      arguments: { doc_digest: DOC_DIGEST, parties: ['smoke-test'], message: 'AM-3 gate' },
    });
    createResult = JSON.parse(r.content[0].text);
  } catch (e) {
    console.error('FAIL');
    console.error('  ' + e.message);
    process.exit(1);
  }
  if (!createResult.envelope_id || !createResult.sign_url) {
    console.error('FAIL — missing envelope_id or sign_url');
    process.exit(1);
  }
  console.log('ok (envelope_id=' + createResult.envelope_id.slice(0, 8) + '...)');

  process.stdout.write('smoke-mcp: building synthetic passkey assertion... ');

  // Generate a P-256 key pair.
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );

  // Build the signing message that the Anchorproof UI would create.
  const signingMsg = JSON.stringify({
    doc_digest: DOC_DIGEST,
    envelope_id: createResult.envelope_id,
    role: 'sender',
    signed_at: new Date().toISOString(),
  });

  // Build clientDataJSON with the signing message as the challenge (base64url-encoded UTF-8).
  const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
  const challengeB64url = b64url(new TextEncoder().encode(signingMsg));
  const clientDataObj = {
    type: 'webauthn.get',
    challenge: challengeB64url,
    origin: 'https://anchor.ainumbers.co',
    crossOrigin: false,
  };
  const clientDataJSONBytes = new TextEncoder().encode(JSON.stringify(clientDataObj));

  // Build minimal authenticatorData: rpIdHash(32) + flags(1) + counter(4).
  // flags = UP|UV = 0x05, BE=0 so evidence_strength = device_bound.
  const rpIdHash = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode('anchor.ainumbers.co'),
  ));
  const flags = new Uint8Array([0x05]);
  const counter = new Uint8Array([0, 0, 0, 1]);
  const authData = new Uint8Array([...rpIdHash, ...flags, ...counter]);

  // Signed data = authenticatorData || SHA-256(clientDataJSON).
  const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSONBytes));
  const signedData = new Uint8Array([...authData, ...cdjHash]);

  // Sign — Node WebCrypto returns P1363 (r||s); verifyAssertion handles both DER and P1363.
  const sigBytes = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    signedData,
  ));

  // Export the credential public key as SPKI base64.
  const spkiBuf = await crypto.subtle.exportKey('spki', publicKey);
  const spkiBase64 = Buffer.from(spkiBuf).toString('base64');

  console.log('ok');

  process.stdout.write('smoke-mcp: verify_signature_envelope (no anchor_bindings)... ');
  let verSigResult;
  try {
    const r = await mcpCall('tools/call', {
      name: 'verify_signature_envelope',
      arguments: {
        doc_digest: DOC_DIGEST,
        signatures: [{
          assertion: {
            authenticatorData: Buffer.from(authData).toString('base64'),
            clientDataJSON: Buffer.from(clientDataJSONBytes).toString('base64'),
            signature: Buffer.from(sigBytes).toString('base64'),
          },
          credential_pubkey: spkiBase64,
          signer: 'smoke-test',
          role: 'sender',
        }],
      },
    });
    verSigResult = JSON.parse(r.content[0].text);
  } catch (e) {
    console.error('FAIL');
    console.error('  ' + e.message);
    process.exit(1);
  }

  if (!verSigResult.valid) {
    const reason = verSigResult.per_signature?.[0]?.reason || 'unknown';
    console.error('FAIL — valid=false: ' + reason);
    process.exit(1);
  }
  const es = verSigResult.per_signature?.[0]?.evidence_strength;
  if (es !== 'device_bound') {
    console.error('FAIL — expected evidence_strength=device_bound, got ' + es);
    process.exit(1);
  }
  console.log('ok (valid=true, evidence_strength=' + es + ')');

  // Also verify that the request_binding from create is accepted by verify_anchor_binding.
  if (Array.isArray(createResult.request_binding?.anchor_bindings) &&
      createResult.request_binding.anchor_bindings.length > 0) {
    process.stdout.write('smoke-mcp: verify_anchor_binding on request event... ');
    let vabResult;
    try {
      const r = await mcpCall('tools/call', {
        name: 'verify_anchor_binding',
        arguments: { anchors: { anchor_bindings: createResult.request_binding.anchor_bindings } },
      });
      vabResult = JSON.parse(r.content[0].text);
    } catch (e) {
      console.error('FAIL');
      console.error('  ' + e.message);
      process.exit(1);
    }
    const allValid = vabResult.results?.every((r) => r.valid);
    if (!allValid) {
      const bad = (vabResult.results || []).filter((r) => !r.valid);
      console.error('FAIL — request event binding invalid:');
      for (const r of bad) console.error('  ' + r.tsa + ': ' + (r.reasons || []).join('; '));
      process.exit(1);
    }
    console.log('ok (' + vabResult.results.length + ' valid)');
  } else {
    console.log('smoke-mcp: request_binding anchor_bindings empty (TSA may have failed) — skipping');
  }
}

// ---- 5. anchor_batch + verify_anchor_binding merkle inclusion round-trip (optional) ----

if (BATCH_ROUND_TRIP) {
  const BATCH_HASHES = [
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
  ];

  process.stdout.write('smoke-mcp: anchor_batch (sigstore, 3 hashes)... ');
  let batchResult;
  try {
    const r = await mcpCall('tools/call', {
      name: 'anchor_batch',
      arguments: { hashes: BATCH_HASHES, authorities: ['sigstore'] },
    });
    batchResult = JSON.parse(r.content[0].text);
  } catch (e) {
    console.error('FAIL');
    console.error('  ' + e.message);
    process.exit(1);
  }

  if (!batchResult.root || !Array.isArray(batchResult.anchor_bindings) || batchResult.anchor_bindings.length === 0) {
    const fails = (batchResult.failures || []).map((f) => f.authority + ': ' + f.reason).join('; ');
    console.error('FAIL — no root or anchor_bindings. failures: ' + (fails || 'none'));
    process.exit(1);
  }
  if (!Array.isArray(batchResult.entries) || batchResult.entries.length !== BATCH_HASHES.length) {
    console.error('FAIL — entries length mismatch');
    process.exit(1);
  }
  // Check §20.1 shape on all entries.
  for (const e of batchResult.entries) {
    const mi = e.merkle_inclusion;
    if (!mi || mi.algorithm !== 'rfc6962' || typeof mi.leaf !== 'string' ||
        !Number.isInteger(mi.index) || !Array.isArray(mi.path) || !Number.isInteger(mi.tree_size)) {
      console.error('FAIL — entry missing §20.1 merkle_inclusion fields');
      process.exit(1);
    }
  }
  console.log('ok (root=' + batchResult.root.slice(7, 23) + '..., ' + batchResult.entries.length + ' entries)');

  // Verify each leaf's binding via verify_anchor_binding.
  process.stdout.write('smoke-mcp: verify_anchor_binding with merkle_inclusion (all 3 leaves)... ');
  let anyFail = false;
  for (const entry of batchResult.entries) {
    const syntheticBinding = {
      ...batchResult.anchor_bindings[0],
      merkle_inclusion: entry.merkle_inclusion,
    };
    let vr;
    try {
      const r = await mcpCall('tools/call', {
        name: 'verify_anchor_binding',
        arguments: {
          binding: syntheticBinding,
          artifact_hash: entry.hash,
        },
      });
      vr = JSON.parse(r.content[0].text);
    } catch (e) {
      console.error('FAIL');
      console.error('  ' + e.message);
      process.exit(1);
    }
    const res = vr.results?.[0];
    if (!res?.valid) {
      anyFail = true;
      console.error('\nFAIL — leaf ' + entry.merkle_inclusion.index + ' verify failed: ' + (res?.reasons || []).join('; '));
      break;
    }
    if (!res.merkle_inclusion?.verified) {
      anyFail = true;
      console.error('\nFAIL — leaf ' + entry.merkle_inclusion.index + ' merkle_inclusion not verified');
      break;
    }
  }
  if (!anyFail) {
    console.log('ok (all 3 leaves valid with merkle_inclusion.verified=true)');
  } else {
    process.exit(1);
  }
}

console.log('\nsmoke-mcp: all checks passed');
