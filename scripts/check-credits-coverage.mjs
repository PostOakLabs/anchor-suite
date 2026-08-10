#!/usr/bin/env node
// Gate: fails when a vendored-looking file has no data/credits-registry.json entry
// covering it. Detects vendoring by convention used across the 4 repos:
//   - a `*.bundle.mjs`/`*.bundle.js` filename (anywhere)
//   - a singular `vendor/` path segment (anywhere) — the third-party staging
//     convention used by postject, pkijs, chainlink-protos-cre
//   - a plural `vendored/` path segment, UNLESS it's inside a known first-party
//     cross-repo MIRROR root for this repo (MIRROR_ROOTS below).
// Usage: node scripts/check-credits-coverage.mjs <repo-id>
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '..', '..');
const repoId = process.argv[2];
if (!repoId || !['repo', 'mcp-apps-poc', 'helm', 'anchor-suite'].includes(repoId)) {
  console.error('Usage: node scripts/check-credits-coverage.mjs <repo-id>  (repo-id: repo|mcp-apps-poc|helm|anchor-suite)');
  process.exit(1);
}

const registry = JSON.parse(readFileSync(path.join(ROOT, 'data', 'credits-registry.json'), 'utf8'));
const covered = registry.vendored
  .filter(v => v.repos.includes(repoId))
  .flatMap(v => (v.paths && v.paths[repoId]) || [])
  .map(p => p.replace(/\\/g, '/'));

// Roots to exclude from the path-based (singular/plural "vendor(ed)/") signal
// per repo — either a first-party cross-repo mirror ("vendored" by naming
// convention, not by license — has its own MANIFEST.json saying so), or a
// non-code asset class this gate doesn't scope to (fonts, pinned TSA/CA root
// certs — see ROOTS.md). A bundle-suffixed or nested vendor/ file inside one
// of these still triggers via the other signals.
const EXCLUDE_ROOTS = {
  repo: [],
  'mcp-apps-poc': [],
  helm: ['hub/vendored/ocg/', 'hub/vendored/anchor-suite/', 'ui/vendored/'],
  'anchor-suite': ['public/vendor/ocg/', 'public/vendor/roots/', 'public/vendor/fonts/'],
}[repoId];
// Filenames that are documentation/manifests about vendoring, not vendored
// code themselves — would otherwise self-flag by sitting inside a vendor/ dir.
const EXCLUDE_FILES = new Set(['VENDORED.md']);

const EXCLUDE_DIRS = new Set(['.git', 'node_modules', '.wt', '.wrangler', '.claude-worktrees', '.worktrees', 'bundled', 'dist']);
const VENDOR_SINGULAR_RE = /(^|\/)vendor\//i;
const VENDOR_PLURAL_RE = /(^|\/)vendored\//i;
const BUNDLE_FILE_RE = /\.bundle\.(mjs|js)$/i;

function inExcludedRoot(relPath) {
  return EXCLUDE_ROOTS.some(root => relPath.startsWith(root));
}

function isCovered(relPath) {
  return covered.some(c => relPath === c || relPath.startsWith(c.endsWith('/') ? c : c + '/') || (c.endsWith('/') && relPath.startsWith(c)));
}

function walk(dir, relDir, out) {
  let entries;
  try { entries = readdirSync(dir); } catch { return; }
  for (const name of entries) {
    if (EXCLUDE_DIRS.has(name) || EXCLUDE_FILES.has(name)) continue;
    const full = path.join(dir, name);
    const rel = relDir ? `${relDir}/${name}` : name;
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) {
      walk(full, rel, out);
    } else {
      const isBundleFile = BUNDLE_FILE_RE.test(name);
      const isVendorSingular = VENDOR_SINGULAR_RE.test(rel) && !inExcludedRoot(rel);
      const isVendorPlural = VENDOR_PLURAL_RE.test(rel) && !inExcludedRoot(rel);
      if (isBundleFile || isVendorSingular || isVendorPlural) out.push(rel);
    }
  }
}

const found = [];
walk(ROOT, '', found);

const uncovered = found.filter(f => !isCovered(f));

if (uncovered.length) {
  console.error(`check-credits-coverage: ${uncovered.length} vendored-looking file(s) with no data/credits-registry.json entry for repo "${repoId}":`);
  for (const f of uncovered) console.error(`  - ${f}`);
  console.error('Add an entry to data/credits-registry.json (vendored[].paths.' + repoId + ') and re-run scripts/gen-credits.mjs.');
  process.exit(1);
}

console.log(`check-credits-coverage: ${found.length} vendored-looking file(s) scanned, all covered by the registry.`);
