// check-no-inline-scripts.mjs — CSP guard.
//
// The estate CSP (public/_headers) is `script-src 'self'` with no 'unsafe-inline' and no
// nonce/hash. Any inline EXECUTABLE <script> (type="module" or classic, no src) is therefore
// silently BLOCKED by the browser — the page's JS never runs. This exact bug left the whole
// /sign/* surface dead (the drop-zone click, banner, and passkey flow all wired inside an
// inline module that CSP refused to execute).
//
// This gate fails if any public/**/*.html has an inline executable script. Data blocks
// (type="application/json", "application/ld+json") are not executed and are allowed. Load
// page JS from external files under /js/ instead (script-src 'self' permits same-origin src).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(HERE, '..', 'public');

// Pages with a known inline script still pending externalization. Empty this out as they
// are fixed; a NEW inline script (not listed here) hard-fails the gate.
const KNOWN_PENDING = new Set([
  'sign/verify.html', // countersign/verify page — externalization tracked as a follow-up
]);

function walk(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, acc);
    else if (name.endsWith('.html')) acc.push(p);
  }
  return acc;
}

// Match <script ...>...</script>; capture the opening-tag attributes and the body.
const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
const DATA_TYPES = /type\s*=\s*["'](application\/(ld\+)?json)["']/i;
const HAS_SRC = /\bsrc\s*=/i;

let offenders = [];
let pending = [];

for (const file of walk(PUBLIC)) {
  const rel = relative(PUBLIC, file).replace(/\\/g, '/');
  const html = readFileSync(file, 'utf8');
  let m;
  SCRIPT_RE.lastIndex = 0;
  while ((m = SCRIPT_RE.exec(html))) {
    const attrs = m[1] || '';
    const body = (m[2] || '').trim();
    if (HAS_SRC.test(attrs)) continue;        // external — allowed
    if (DATA_TYPES.test(attrs)) continue;     // data block — not executed
    if (!body) continue;                      // empty inline — harmless
    if (KNOWN_PENDING.has(rel)) { pending.push(rel); continue; }
    offenders.push(rel);
  }
}

if (pending.length) {
  console.log(`known-pending inline scripts (allowlisted): ${[...new Set(pending)].join(', ')}`);
}
if (offenders.length) {
  console.error('✗ inline executable <script> found (blocked by CSP script-src \'self\'):');
  for (const o of [...new Set(offenders)]) console.error(`   - ${o}`);
  console.error('Move the JS to an external /js/*.js file and reference it with <script type="module" src="...">.');
  process.exit(1);
}
console.log('✓ no disallowed inline scripts');
