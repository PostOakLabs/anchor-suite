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
  return { status: res.status, body: parsed };
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
