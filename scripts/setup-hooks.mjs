// One-shot: enable this repo's committed git hooks for the current clone.
//   node scripts/setup-hooks.mjs
// Points core.hooksPath at the version-controlled .githooks/ dir (Git 2.9+).
// Idempotent. Ported from the ainumbers site repo's setup-hooks.mjs, 2026-07-20.
import { execSync } from 'node:child_process';

try {
  const current = (() => {
    try { return execSync('git config --get core.hooksPath', { encoding: 'utf8' }).trim(); }
    catch { return ''; }
  })();
  if (current === '.githooks') {
    console.log('✓ core.hooksPath already = .githooks — pre-push gate active.');
    process.exit(0);
  }
  execSync('git config core.hooksPath .githooks', { stdio: 'inherit' });
  console.log('✓ core.hooksPath set to .githooks — pre-push gate now active for this clone.');
} catch (e) {
  console.error('✗ failed to set core.hooksPath:', e.message);
  process.exit(1);
}
