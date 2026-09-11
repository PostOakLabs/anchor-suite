// run-gates.mjs — run every deterministic CI gate locally, in order, and fail
// on the first red. The TSA smoke harness is separate (scripts/smoke-tsa.mjs)
// because it talks to third parties.

import { spawnSync } from 'child_process';
import { readFileSync, readdirSync, statSync } from 'fs';
import { dirname, join, relative } from 'path';
import { fileURLToPath } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(HERE, '..', 'public');

// ── gate: A2A signed agent card (ANCHOR-WEBMCP-1, spec §3.8) ──────────────────
// Verifies public/.well-known/agent-card.json: detached JWS (EdDSA/Ed25519) over
// the JCS-canonical card, kid resolved against public/.well-known/jwks.json and
// re-derived from the published raw key (did:key fingerprint convention). The
// canon + fingerprint logic is embedded (no cross-repo import): cgCanon mirrors
// repo/chaingraph/kernels/_hash.mjs byte-identically (RFC 8785 over I-JSON); the
// did:key form is base58btc(0xed01 || raw pubkey), matching _proof.mjs. An
// ALWAYS-ON tamper self-test (flip one content byte → verify must FAIL) keeps a
// RED-then-GREEN control inside every gate run.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58btc(bytes) {
  let n = [...bytes].reduce((a, b) => a * 256n + BigInt(b), 0n);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = '1' + s; else break; }
  return s;
}
const cgCanon = (v) =>
  Array.isArray(v) ? v.map(cgCanon)
  : (v && typeof v === 'object')
    ? Object.keys(v).sort().reduce((o, k) => (o[k] = cgCanon(v[k]), o), {})
    : v;

async function verifyCardSig(card, jwksKeys) {
  const sigs = card.signatures;
  if (!Array.isArray(sigs) || sigs.length === 0) return { ok: false, why: 'no signatures[] member (unsigned card)' };
  const cardForCanon = structuredClone(card);
  delete cardForCanon.signatures;
  const payloadB64 = Buffer.from(new TextEncoder().encode(JSON.stringify(cgCanon(cardForCanon)))).toString('base64url');
  for (const sig of sigs) {
    if (typeof sig?.protected !== 'string' || typeof sig?.signature !== 'string')
      return { ok: false, why: 'malformed signatures[] entry (protected/signature strings required)' };
    let header;
    try { header = JSON.parse(Buffer.from(sig.protected, 'base64url').toString('utf8')); }
    catch { return { ok: false, why: 'protected header is not valid base64url JSON' }; }
    if (header.alg !== 'EdDSA') return { ok: false, why: `unexpected alg ${JSON.stringify(header.alg)} (want EdDSA)` };
    if (typeof header.kid !== 'string' || !header.kid.startsWith('did:key:'))
      return { ok: false, why: 'protected header has no did:key kid' };
    const key = jwksKeys.find((k) => k.kty === 'OKP' && k.crv === 'Ed25519' && k.kid === header.kid);
    if (!key) return { ok: false, why: `signing kid ${header.kid} not present in jwks.json keys` };
    const fingerprint = 'did:key:z' + base58btc(new Uint8Array([0xed, 0x01, ...Buffer.from(key.x, 'base64')]));
    if (fingerprint !== header.kid) return { ok: false, why: `jwks key x does not re-derive to the kid (${fingerprint} != ${header.kid})` };
    const pubKey = await globalThis.crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: key.x }, { name: 'Ed25519' }, true, ['verify']);
    const ok = await globalThis.crypto.subtle.verify('Ed25519', pubKey, Buffer.from(sig.signature, 'base64url'), new TextEncoder().encode(`${sig.protected}.${payloadB64}`));
    if (!ok) return { ok: false, why: `Ed25519 verify FAILED for kid ${header.kid} — card content does not match the signature` };
  }
  return { ok: true, kid: JSON.parse(Buffer.from(sigs[0].protected, 'base64url').toString('utf8')).kid };
}

async function gateAgentCardSig() {
  const card = JSON.parse(readFileSync(join(PUBLIC, '.well-known', 'agent-card.json'), 'utf8'));
  const jwks = JSON.parse(readFileSync(join(PUBLIC, '.well-known', 'jwks.json'), 'utf8'));
  if (!card.protocolVersion) throw new Error('card has no protocolVersion — not an A2A agent card?');
  const mutated = structuredClone(card);
  mutated.version = mutated.version === '0.0.0-tampered' ? '0.0.0-tampered2' : '0.0.0-tampered';
  if ((await verifyCardSig(mutated, jwks.keys)).ok) throw new Error('SELF-TEST INCONCLUSIVE: a tampered card VERIFIED — the gate is blind');
  const r = await verifyCardSig(card, jwks.keys);
  if (!r.ok) throw new Error(r.why);
  console.log(`✓ agent-card signature valid (kid ${r.kid}; matches jwks.json; tamper self-test failed-as-expected)`);
}

// ── gate: WebMCP tool-name uniqueness over this suite's own pages ─────────────
// The site's name-uniqueness gate cannot see anchor-suite. Every page-level
// mc.registerTool({ name: ... }) must be unique across the whole public/ first-
// party surface (all *.html + first-party /js/ + /lib/ modules; /vendor/ and
// .well-known/ are third-party/data, not registration surfaces).
function gateToolNameUniqueness() {
  const seen = new Map();
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = statSync(p);
      if (st.isDirectory()) { if (name !== 'vendor' && name !== '.well-known') walk(p, files); continue; }
      if (/\.html$|\.m?js$/.test(name)) files.push(p);
    }
  };
  walk(PUBLIC);
  for (const file of files) {
    const rel = relative(PUBLIC, file).replace(/\\/g, '/');
    const m = readFileSync(file, 'utf8').matchAll(/registerTool\s*\(\s*\{\s*name:\s*['"]([^'"]+)['"]/g);
    for (const hit of m) {
      if (!seen.has(hit[1])) seen.set(hit[1], []);
      seen.get(hit[1]).push(rel);
    }
  }
  const dupes = [...seen.entries()].filter(([, fs]) => fs.length > 1);
  if (dupes.length) {
    for (const [name, fs] of dupes) console.error(`   - duplicate tool name '${name}' in: ${fs.join(', ')}`);
    throw new Error(`${dupes.length} duplicate WebMCP tool name(s) across public/`);
  }
  console.log(`✓ tool names unique: ${seen.size} registered (${[...seen.keys()].join(', ') || 'none'})`);
}

async function main() {
  let failed = 0;
  const inProcess = [
    ['agent-card-signature', gateAgentCardSig],
    ['tool-name-uniqueness', gateToolNameUniqueness],
  ];
  for (const [name, fn] of inProcess) {
    console.log(`\n=== ${name} (in run-gates.mjs) ===`);
    try { await fn(); } catch (e) { console.error(`✗ ${name}: ${e.message}`); failed++; }
  }
  for (const entry of GATES) {
    const file = typeof entry === 'string' ? entry : entry.file;
    const args = typeof entry === 'string' ? [] : entry.args;
    console.log(`\n=== ${file}${args.length ? ' ' + args.join(' ') : ''} ===`);
    const r = spawnSync(process.execPath, [join(HERE, file), ...args], { stdio: 'inherit' });
    if (r.status !== 0) failed++;
  }
  if (failed) {
    console.error(`\n${failed} gate(s) red`);
    process.exit(1);
  }
  console.log('\nall gates green');
}

const GATES = [
  'check-dead-links.mjs',
  'check-no-inline-scripts.mjs',
  'check-copy.mjs',
  'check-root-freshness.mjs',
  'check-vendor-freshness.mjs',
  { file: 'check-credits-coverage.mjs', args: ['anchor-suite'] },
  { file: 'gen-credits.mjs', args: ['anchor-suite', '--check'] },
  'check-secrets.mjs',
  'gate-tst-verify.mjs',
  'gate-verify-assertion.mjs',
  'gate-merkle-batch.mjs',
  'gate-batch-inclusion-roundtrip.mjs',
  'gate-escalation-closure.mjs',
  'gate-mcp-era.mjs',
  'gate-sigsum-budget-counter.mjs',
  'gate-sigsum-session-token.mjs',
  'gate-ots-calendar-allowlist.mjs',
];

await main();
