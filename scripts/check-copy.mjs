// check-copy.mjs — copy hallmarks for reader-facing text (house humanization
// standard): no em-dashes, no internal build codes, and the word
// "browserchain" never appears in public naming. Scans public/ HTML plus the
// repo-level Markdown docs; vendored files are exempt (their prose is
// upstream's).

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, resolve, sep, dirname } from 'path';
import { fileURLToPath } from 'url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = join(REPO, 'public');

function* files(dir, exts) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (p === join(PUBLIC_DIR, 'vendor')) continue; // upstream prose, exempt
      yield* files(p, exts);
    } else if (exts.some((e) => name.endsWith(e))) yield p;
  }
}

const targets = [
  ...files(PUBLIC_DIR, ['.html', '.md', '.txt']),
  ...['README.md', 'ROOTS.md', 'VENDORED.md'].map((f) => join(REPO, f)),
];

const RULES = [
  { name: 'em-dash', re: /—/g },
  { name: 'browserchain in public naming', re: /browserchain/gi },
  { name: 'internal build code', re: /\b(?:art-\d{1,4}|T\d{3})\b/g },
];

const failures = [];
for (const file of targets) {
  const text = readFileSync(file, 'utf8');
  for (const rule of RULES) {
    const hits = text.match(rule.re);
    if (hits) failures.push(`${file.replace(REPO + sep, '')}: ${rule.name} (${hits.length}x)`);
  }
}

if (failures.length) {
  console.error('COPY HALLMARK failures:');
  for (const f of failures) console.error('  ' + f);
  process.exit(1);
}
console.log(`copy check: ${targets.length} files clean`);
