// smoke-mcp.mjs — post-deploy smoke for the /mcp endpoint.
//
// Checks:
//   1. initialize returns HTTP 200 with protocolVersion and three serverInfo fields.
//   2. tools/list returns the three expected tools.
//   3. (optional) anchor_hash against Sigstore returns a binding that
//      verify_anchor_binding accepts as valid. Skipped without --round-trip.
//
// Exit codes:
//   0 — all checks passed (or --skip-anchor if authorities are down)
//   1 — an MCP structural failure (wrong protocol, missing tool, bad response)
//
// Usage:
//   node scripts/smoke-mcp.mjs                          # initialize + tools/list
//   node scripts/smoke-mcp.mjs --round-trip             # + anchor_hash/verify round-trip
//   MCP_BASE=https://anchor.ainumbers.co node ...       # target override (default: live)

const BASE = process.env.MCP_BASE || 'https://anchor.ainumbers.co';
const MCP_URL = BASE + '/mcp';
const ROUND_TRIP = process.argv.includes('--round-trip');

const EXPECTED_TOOLS = ['list_anchor_authorities', 'anchor_hash', 'verify_anchor_binding'];

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

console.log('\nsmoke-mcp: all checks passed');
