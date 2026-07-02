// check-secrets.mjs — there are no secrets in this repo, ever, so anything
// that looks like one is a failure. Scans every git-tracked file. The big
// vendored bundles legitimately contain PEM header STRINGS in code, so the
// private-key rule skips them; the token rules apply everywhere.

import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tracked = execSync('git ls-files', { cwd: REPO, encoding: 'utf8' }).split('\n').filter(Boolean);

const BUNDLE_EXEMPT = new Set([
  'public/vendor/pkijs.bundle.mjs',
  'public/vendor/opentimestamps.min.js',
  'public/vendor/ocg/lib/_noble-bn254.bundle.mjs',
]);

const RULES = [
  { name: 'private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/, skipBundles: true },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'generic api key assignment', re: /(?:api[_-]?key|api[_-]?token|secret[_-]?key|access[_-]?token)["'\s:=]+["'][A-Za-z0-9_\-]{20,}["']/i },
  { name: 'Cloudflare API token env', re: /CLOUDFLARE_API_TOKEN\s*[:=]\s*["']?[A-Za-z0-9_\-]{30,}/ },
];

const failures = [];
for (const rel of tracked) {
  let text;
  try { text = readFileSync(resolve(REPO, rel), 'utf8'); } catch { continue; }
  for (const rule of RULES) {
    if (rule.skipBundles && BUNDLE_EXEMPT.has(rel)) continue;
    if (rule.re.test(text)) failures.push(`${rel}: ${rule.name}`);
  }
}

if (failures.length) {
  console.error('SECRET-SCAN failures (this repo must never contain secrets):');
  for (const f of failures) console.error('  ' + f);
  process.exit(1);
}
console.log(`secret scan: ${tracked.length} tracked files clean`);
