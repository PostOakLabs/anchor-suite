// check-dead-links.mjs — strict-zero internal dead links across public/ HTML.
// Internal href/src must resolve to a committed file (directories resolve to
// index.html). External links are listed for review but checked by humans,
// not the network, so CI stays deterministic.

import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, dirname, resolve, sep } from 'path';
import { fileURLToPath } from 'url';

const PUBLIC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'public');

function* htmlFiles(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* htmlFiles(p);
    else if (name.endsWith('.html')) yield p;
  }
}

const failures = [];
const externals = new Set();

for (const file of htmlFiles(PUBLIC_DIR)) {
  const html = readFileSync(file, 'utf8');
  const refs = [...html.matchAll(/(?:href|src)\s*=\s*"([^"]+)"/g)].map((m) => m[1]);
  for (const ref of refs) {
    if (/^(https?:)?\/\//.test(ref)) { externals.add(ref); continue; }
    if (/^(mailto:|data:|#)/.test(ref)) continue;
    const clean = ref.split('#')[0].split('?')[0];
    if (!clean) continue;
    let target = clean.startsWith('/') ? join(PUBLIC_DIR, clean) : join(dirname(file), clean);
    if (existsSync(target) && statSync(target).isDirectory()) target = join(target, 'index.html');
    if (clean.endsWith('/')) target = join(target); // already handled above
    if (!existsSync(target)) {
      failures.push(`${file.replace(PUBLIC_DIR + sep, '')}: ${ref}`);
    }
  }
}

if (externals.size) {
  console.log('external links (not fetched, review by hand):');
  for (const e of externals) console.log('  ' + e);
}
if (failures.length) {
  console.error(`DEAD LINKS (${failures.length}):`);
  for (const f of failures) console.error('  ' + f);
  process.exit(1);
}
console.log('dead-link check: zero internal dead links');
