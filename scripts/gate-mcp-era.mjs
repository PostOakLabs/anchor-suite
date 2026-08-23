// gate-mcp-era.mjs — offline gate for the 2026-07-28 era-gated request rules.
//
// smoke-mcp.mjs proves these against a DEPLOYED endpoint; this gate proves the same
// rules in CI before anything deploys, by invoking the Worker's fetch handler directly.
// Both matter: a rule that only a post-deploy smoke can catch is a rule that reaches
// production before it is checked.
//
// The pairing is the point. Every modern-era rejection below has a legacy control
// asserting an old client still gets 200 for the same shape — dual-support is a hard
// requirement, so a fix that strands legacy clients must fail here, not in the field.

import worker from '../src/worker.mjs';

const MODERN = '2026-07-28';
// Stated here INDEPENDENTLY, never imported from the worker — a gate that reads the list
// it validates from the artifact under test proves nothing (SO #34). If the worker gains a
// version, this line goes stale and the gate turns red until someone updates it on purpose.
const MCP_SUPPORTED = ['2026-07-28', '2025-06-18', '2024-11-05'];
const URL_MCP = 'https://anchor.ainumbers.co/mcp';
const env = { ASSETS: { fetch: () => new Response('asset', { status: 200 }) } };

let failed = 0;
function check(label, cond, detail = '') {
  if (cond) {
    console.log('gate-mcp-era: ' + label + '... ok');
  } else {
    failed++;
    console.error('gate-mcp-era: ' + label + '... FAIL' + (detail ? ' — ' + detail : ''));
  }
}

let nextId = 1;
async function call(headers, body) {
  const res = await worker.fetch(
    new Request(URL_MCP, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, ...body }),
    }),
    env,
  );
  let parsed = {};
  try { parsed = JSON.parse(await res.clone().text()); } catch { /* non-JSON body */ }
  return { status: res.status, body: parsed, headers: res.headers };
}

const meta = (extra = {}) => ({
  'io.modelcontextprotocol/protocolVersion': MODERN,
  'io.modelcontextprotocol/clientCapabilities': {},
  ...extra,
});
const MODERN_H = { 'MCP-Protocol-Version': MODERN };

// ---- modern era: the 2026-07-28 rules are enforced ---------------------------

{
  const r = await call({ ...MODERN_H, 'Mcp-Method': 'tools/list' },
    { method: 'tools/list', params: { _meta: meta() } });
  check('modern: fully conformant tools/list → 200 + resultType complete',
    r.status === 200 && r.body.result?.resultType === 'complete' && r.body.result?.tools?.length > 0,
    `status=${r.status}`);
}

{
  const r = await call({ ...MODERN_H, 'Mcp-Method': 'no/such/method' },
    { method: 'no/such/method', params: { _meta: meta() } });
  check('modern: unknown method → 404 + -32601',
    r.status === 404 && r.body.error?.code === -32601, `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call(MODERN_H, { method: 'tools/list', params: { _meta: meta() } });
  check('modern: missing Mcp-Method header → 400 + -32020',
    r.status === 400 && r.body.error?.code === -32020, `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call({ 'Mcp-Method': 'tools/list' },
    { method: 'tools/list', params: { _meta: meta() } });
  check('modern via _meta alone: missing MCP-Protocol-Version header → 400 + -32020',
    r.status === 400 && r.body.error?.code === -32020, `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call({ ...MODERN_H, 'Mcp-Method': 'tools/call' },
    { method: 'tools/call', params: { name: 'list_anchor_authorities', arguments: {}, _meta: meta() } });
  check('modern: tools/call missing Mcp-Name header → 400 + -32020',
    r.status === 400 && r.body.error?.code === -32020, `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call({ ...MODERN_H, 'Mcp-Method': 'tools/list' }, { method: 'tools/list', params: {} });
  check('modern: no per-request _meta → 400 + -32602',
    r.status === 400 && r.body.error?.code === -32602, `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call({ ...MODERN_H, 'Mcp-Method': 'tools/list' },
    { method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': MODERN } } });
  check('modern: _meta missing clientCapabilities → 400 + -32602 naming the field',
    r.status === 400 && r.body.error?.code === -32602 &&
      (r.body.error?.data?.missingFields || []).includes('io.modelcontextprotocol/clientCapabilities'),
    `status=${r.status} code=${r.body.error?.code}`);
}

{
  // Both versions are individually supported, so this isolates the header/body compare.
  const r = await call({ ...MODERN_H, 'Mcp-Method': 'tools/list' },
    { method: 'tools/list', params: { _meta: meta({ 'io.modelcontextprotocol/protocolVersion': '2025-06-18' }) } });
  check('modern: version header disagrees with body _meta version → 400 + -32020',
    r.status === 400 && r.body.error?.code === -32020, `status=${r.status} code=${r.body.error?.code}`);
}

{
  const b64 = Buffer.from('list_anchor_authorities', 'utf8').toString('base64');
  const r = await call(
    { ...MODERN_H, 'Mcp-Method': 'tools/call', 'Mcp-Name': `=?base64?${b64}?=` },
    { method: 'tools/call', params: { name: 'list_anchor_authorities', arguments: {}, _meta: meta() } });
  check('modern: base64 Mcp-Name sentinel decoded before compare → 200',
    r.status === 200 && r.body.result?.resultType === 'complete', `status=${r.status}`);
}

// ---- legacy era: identical shapes must still be served -----------------------

{
  const r = await call({}, { method: 'tools/list', params: {} });
  check('legacy control: bare no-header tools/list → 200 + tools',
    r.status === 200 && r.body.result?.tools?.length > 0, `status=${r.status}`);
}

{
  const r = await call({ 'Mcp-Method': 'no/such/method' }, { method: 'no/such/method', params: {} });
  check('legacy control: unknown method stays 200 + -32601',
    r.status === 200 && r.body.error?.code === -32601, `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call({ 'MCP-Protocol-Version': '2025-06-18' }, { method: 'tools/list', params: {} });
  check('legacy control: 2025-06-18 client with no _meta → 200 + tools',
    r.status === 200 && r.body.result?.tools?.length > 0, `status=${r.status}`);
}

{
  const r = await call({ 'MCP-Protocol-Version': '2024-11-05' }, { method: 'tools/list', params: {} });
  check('legacy control: 2024-11-05 client with no _meta → 200 + tools',
    r.status === 200 && r.body.result?.tools?.length > 0, `status=${r.status}`);
}

for (const v of ['2024-11-05', '2025-06-18', MODERN]) {
  const r = await call({}, { method: 'initialize', params: { protocolVersion: v, capabilities: {} } });
  check(`legacy control: initialize ${v} → 200 + its own version (never held to modern rules)`,
    r.status === 200 && r.body.result?.protocolVersion === v, `status=${r.status} got=${r.body.result?.protocolVersion}`);
}

// ---- initialize is a NEGOTIATION, not an assertion (ANCHOR-MCP-NEGOTIATE-1) ---
// Lifecycle §Initialization: an unsupported `params.protocolVersion` on initialize gets
// 200 + a version the server DOES support; the client then decides whether to disconnect.
// A 400 there strands every client whose opening offer we do not implement. The asserted
// path (header / _meta) keeps -32022 — there the version is already negotiated.
//
// ⚠ The lesson this section exists for: probe versions the server does NOT like. The
// pre-fix regression survived a full deploy cycle because every version probed was on
// the supported list, so nothing ever exercised the off-list branch.

// Off-list offers, spanning a REAL published revision the anchor does not implement and a
// version that never existed. Both must negotiate, not reject.
for (const v of ['2025-03-26', '2019-01-01']) {
  const r = await call({}, { method: 'initialize', params: { protocolVersion: v, capabilities: {} } });
  check(`negotiate: initialize ${v} (off-list) → 200 + negotiated ${MODERN}, no error`,
    r.status === 200 && r.body.result?.protocolVersion === MODERN && r.body.error === undefined,
    `status=${r.status} got=${r.body.result?.protocolVersion} code=${r.body.error?.code}`);
  check(`negotiate: initialize ${v} response header carries the negotiated version`,
    r.headers.get('mcp-protocol-version') === MODERN, `got=${r.headers.get('mcp-protocol-version')}`);
  check(`negotiate: initialize ${v} never echoes a version we do not implement`,
    r.body.result?.protocolVersion !== v && MCP_SUPPORTED.includes(r.body.result?.protocolVersion),
    `got=${r.body.result?.protocolVersion}`);
}

// The whole supported ladder plus the off-list case, in one table — the shape a client
// actually sees. 2024-11-05 is DELIBERATE legacy support and must keep echoing itself.
for (const [offer, expected] of [
  ['2024-11-05', '2024-11-05'],
  ['2025-03-26', MODERN],
  ['2025-06-18', '2025-06-18'],
  [MODERN, MODERN],
]) {
  const r = await call({}, { method: 'initialize', params: { protocolVersion: offer, capabilities: {} } });
  check(`negotiate table: initialize ${offer} → 200 + ${expected}`,
    r.status === 200 && r.body.result?.protocolVersion === expected,
    `status=${r.status} got=${r.body.result?.protocolVersion}`);
}

// The header path is the OTHER half of the split and must NOT have been loosened.
{
  const r = await call({ 'MCP-Protocol-Version': '2025-03-26', 'Mcp-Method': 'tools/list' },
    { method: 'tools/list', params: {} });
  check('split: asserted 2025-03-26 via header → still 400 + -32022 with data.supported',
    r.status === 400 && r.body.error?.code === -32022 &&
      Array.isArray(r.body.error?.data?.supported) && r.body.result === undefined,
    `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call({ 'Mcp-Method': 'tools/list' },
    { method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2025-03-26' } } });
  check('split: asserted 2025-03-26 via _meta → still 400 + -32022',
    r.status === 400 && r.body.error?.code === -32022, `status=${r.status} code=${r.body.error?.code}`);
}

{
  // An assertion beats an offer: initialize carrying an off-list HEADER is still rejected,
  // even though its params.protocolVersion is one we support. Negotiation must not become
  // a bypass for the asserted path.
  const r = await call({ 'MCP-Protocol-Version': '2025-03-26', 'Mcp-Method': 'initialize' },
    { method: 'initialize', params: { protocolVersion: MODERN, capabilities: {} } });
  check('split: off-list header on initialize → 400 + -32022 (assertion beats offer)',
    r.status === 400 && r.body.error?.code === -32022, `status=${r.status} code=${r.body.error?.code}`);
}

// ---- unchanged invariants ----------------------------------------------------

{
  const r = await call({ 'Mcp-Method': 'tools/call' },
    { method: 'tools/call', params: { name: 'definitely_not_a_tool', arguments: {} } });
  check('unknown TOOL is still -32602, not -32601',
    r.body.error?.code === -32602, `code=${r.body.error?.code}`);
}

{
  const r = await call({ 'MCP-Protocol-Version': '1999-01-01', 'Mcp-Method': 'tools/list' },
    { method: 'tools/list', params: {} });
  check('unsupported version → 400 + -32022 with data.supported',
    r.status === 400 && r.body.error?.code === -32022 && Array.isArray(r.body.error?.data?.supported),
    `status=${r.status} code=${r.body.error?.code}`);
}

{
  const r = await call({ ...MODERN_H, 'Mcp-Method': 'server/discover' },
    { method: 'server/discover', params: { _meta: meta() } });
  check('server/discover → supportedVersions + capabilities + serverInfo',
    r.status === 200 && r.body.result?.supportedVersions?.includes(MODERN) &&
      !!r.body.result?.capabilities &&
      !!r.body.result?._meta?.['io.modelcontextprotocol/serverInfo']?.name,
    `status=${r.status}`);
}

for (const verb of ['GET', 'DELETE']) {
  const res = await worker.fetch(new Request(URL_MCP, { method: verb }), env);
  check(`${verb} /mcp → 405 (SEP-2567)`, res.status === 405, `got ${res.status}`);
}

if (failed > 0) {
  console.error(`\ngate-mcp-era: ${failed} check(s) failed`);
  process.exit(1);
}
console.log('\ngate-mcp-era: all checks passed');
