// check-copy.mjs — copy hallmarks for reader-facing text (house humanization
// standard, ported from ainumbers/scripts/check-copy-hallmarks.mjs 2026-07-20,
// memory project-ainumbers-copytell-refined-pass). Scans public/ HTML plus the
// repo-level Markdown docs; vendored files are exempt (their prose is
// upstream's).
//
// Original 3 rules (em-dash, "browserchain" in public naming, internal build
// codes) stay zero-tolerance, no baseline — this repo has zero legacy debt
// (15 files, clean at port time), so the em-dash/jargon BASELINE mechanism the
// site repo needs for its 480+ tool legacy debt has nothing to shield here.
//
// Ported ANTI-AI-TELL categories (permanent, feedback-anti-ai-tell-copy-ban):
// italics-for-emphasis (<em>/<i>, h1-h6 headers exempt as title-styling),
// "not just X but"/"isn't just"/"more than just", dramatic-fragment openers,
// validation-phrasing, filler-vocab denylist, decorative emoji in headers —
// all zero-tolerance, no baseline (same reasoning: no legacy debt to shield).
//
// Ported BOLD category (Tim 2026-07-20): unlike the other categories this repo
// is NOT clean — public/index.html, integrate.html, sign.html use <strong> as
// legitimate list-lead-in styling ("Hash locally.", "Save it with the
// document."), not AI-tell emphasis. Same baseline+ratchet design as the site
// repo: scripts/copy-hallmarks-baseline.json snapshots per-file counts via
// --update, no file may exceed its baselined count, new files must be clean.
//
// TWOTONE ("It is not X. It is Y.") is blocking, zero-tolerance, no baseline
// (COPYTELL-SWEEP-1, 2026-07-20 — italics precedent): this repo has zero hits,
// so there is no legacy debt to shield. Rule-of-three TRIAD stays advisory
// PERMANENTLY, matching the site repo.
//
// COPYTELL-SWEEP-1 also reviewed all 14 baselined bold hits (public/index.html,
// integrate.html, sign/sign.html): every one is a step/platform-name list-lead
// ("Hash locally.", "SAP DMS / GOS.") — genuine structural labels, not
// narrative emphasis, per the conservative-always rule. Bold baseline is
// unchanged (nothing to ratchet without distorting the list-header pattern).
//
// HTML files get script/style/pre/code/comments stripped before any pattern
// runs (same scope as the site gate) so JS source and inline styles can never
// trip a prose rule. Markdown/text files are scanned as-is — they carry no
// such blocks in this repo.

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'fs';
import { join, resolve, sep, dirname, extname } from 'path';
import { fileURLToPath } from 'url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = join(REPO, 'public');
const BASELINE_PATH = join(REPO, 'scripts', 'copy-hallmarks-baseline.json');
const UPDATE = process.argv.includes('--update');

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

const EMDASH = /—/g;
const RULES = [
  { name: 'em-dash', re: EMDASH },
  { name: 'browserchain in public naming', re: /browserchain/gi },
  // Matches the site repo's actual jargon set (scripts/check-copy-hallmarks.mjs
  // in the ainumbers repo): "Wave N" / "W-A".."W-F" / standalone "D0". The
  // previous art-NNN/T-id pattern here was a mis-port — art-NNN is the PUBLIC
  // chaingraph node id scheme (the site's own \b rule comment says so
  // explicitly: "keeps ART-ids ... safe"), not an internal build code, and
  // Conversion Lab pages need to link art-191/art-193 by design (CV-1).
  { name: 'Wave-N build code', re: /\bWave\s+\d+\b/g },
  { name: 'W-x badge code', re: /\bW-[A-F]\b/g },
  { name: 'D0 badge code', re: /\bD0\b/g },
];

// --- ANTI-AI-TELL BAN (ported, zero-tolerance, no baseline — see header) ---
const NOTJUSTBUT = [
  [/\bnot\s+just\b(?:(?!\bbut\b)[^.?!]){0,80}\bbut\b/gi, '"not just X but" construction'],
  [/\bisn['’]?t\s+just\b/gi, '"isn\'t just"'],
  [/\bmore\s+than\s+just\b/gi, '"more than just"'],
];
const DRAMATIC_FRAGMENT = /\bThe (?:result|catch|takeaway|verdict|kicker|bottom line)\?/gi;
const VALIDATION_PHRASING = /\byou['’]?re\s+not\s+(?:alone|imagining\s+(?:it|things))\b/gi;
const FILLER_VOCAB = [
  [/\bdelv(?:e|es|ed|ing)\b/gi, 'delve'],
  [/\btapestr(?:y|ies)\b/gi, 'tapestry'],
  [/\btestament\s+to\b/gi, 'testament to'],
  [/\bquiet(?:ly)?\s+(?:revolution|shift|force|power|evolution)\b/gi, 'quiet(ly) X'],
  [/\bseamless(?:ly)?\b/gi, 'seamless'],
  [/\bgame[\s-]?chang(?:er|ing)\b/gi, 'game-changer'],
  [/\belevat(?:e|es|ed|ing)\s+(?:your|our|its|their)\s+\w+/gi, 'elevate your/our/its X'],
  [/\bunlock(?:s|ed|ing)?\s+(?:your\s+|the\s+full\s+|new\s+|greater\s+)?(?:potential|value|growth|opportunit(?:y|ies)|insight(?:s)?|power|possibilit(?:y|ies))\b/gi, 'unlock potential/value/growth (marketing sense)'],
  [/\bit['’]?s\s+worth\s+noting\b/gi, "it's worth noting"],
  [/\bin\s+today['’]?s\s+fast-paced\b/gi, "in today's fast-paced"],
];
const EMOJI = /[\u{2600}-\u{27BF}\u{1F300}-\u{1FAFF}]/gu;
const EMOJI_UI_EXEMPT = new Set(['✓', '✗', '✔', '✔️', '❌', '✅', '⚠', '⚠️', '🔒', '🔏', '🚫', '☑', '☑️', '➡', '➡️', '→', '⭐', '★', '☆', '❓', '❗', '‼', '⏳', '⏱', '⏱️']);
function nonExemptEmoji(text) {
  return (text.match(EMOJI) || []).filter((ch) => !EMOJI_UI_EXEMPT.has(ch));
}

// Advisory only, PERMANENTLY — heuristic, catches legitimate 3-item lists too often.
const TRIAD = /\b\w+,\s*\w+,\s*(?:and|&)\s*\w+\b/g;
// Blocking, zero-tolerance, no baseline (COPYTELL-SWEEP-1).
const TWOTONE_HIGHPRECISION = /\b(?:is|are|was|were) not (?:a|an|the )?[\w-]+\.\s+(?:It|They|This|That) (?:is|are)\b/g;

/** Strip script/style/pre/code bodies + comments from HTML; pass through non-HTML as-is. */
function proseText(raw, ext) {
  if (ext !== '.html') return raw;
  return raw
    .replace(/<script\b[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[\s\S]*?<\/style>/gi, ' ')
    .replace(/<pre\b[\s\S]*?<\/pre>/gi, ' ')
    .replace(/<code\b[\s\S]*?<\/code>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');
}

function headerText(prose, ext) {
  if (ext !== '.html') return '';
  const out = [];
  const re = /<h[1-6]\b[^>]*>([\s\S]*?)<\/h[1-6]>/gi;
  let m;
  while ((m = re.exec(prose))) out.push(m[1].replace(/<[^>]+>/g, ' '));
  return out.join(' ');
}

const findings = {}; // rel -> { bold }

const failures = [];
const advisories = [];

for (const file of targets) {
  const rel = file.replace(REPO + sep, '').split(sep).join('/');
  const ext = extname(file);
  const raw = readFileSync(file, 'utf8');
  const prose = proseText(raw, ext);

  for (const rule of RULES) {
    const hits = prose.match(rule.re);
    if (hits) failures.push(`${rel}: ${rule.name} (${hits.length}x)`);
  }

  const hallmarks = [];
  const proseOutsideHeaders = ext === '.html'
    ? prose.replace(/<h[1-6]\b[^>]*>[\s\S]*?<\/h[1-6]>/gi, ' ')
    : prose;
  const italics = (proseOutsideHeaders.match(/<(em|i)\b[^>]*>[^<]+<\/\1>/gi) || []).length;
  if (italics) hallmarks.push(`italics-for-emphasis ×${italics}`);
  for (const [re, label] of NOTJUSTBUT) {
    const m = prose.match(re) || [];
    if (m.length) hallmarks.push(`${label} ×${m.length}`);
  }
  const dramatic = (prose.match(DRAMATIC_FRAGMENT) || []).length;
  if (dramatic) hallmarks.push(`dramatic-fragment ×${dramatic}`);
  const validation = (prose.match(VALIDATION_PHRASING) || []).length;
  if (validation) hallmarks.push(`validation-phrasing ×${validation}`);
  for (const [re, label] of FILLER_VOCAB) {
    const m = prose.match(re) || [];
    if (m.length) hallmarks.push(`filler-vocab "${label}" ×${m.length}`);
  }
  const emojiHeaders = nonExemptEmoji(headerText(prose, ext)).length;
  if (emojiHeaders) hallmarks.push(`emoji-in-header ×${emojiHeaders}`);
  if (hallmarks.length) failures.push(`${rel}: ANTI-AI-TELL hit(s): ${hallmarks.join('; ')}`);

  // BOLD — baseline+ratchet, not zero-tolerance (see header comment).
  const bold = (proseOutsideHeaders.match(/<(b|strong)\b[^>]*>[^<]+<\/\1>/gi) || []).length;
  if (bold) findings[rel] = { bold };

  const twotoneHP = (prose.match(TWOTONE_HIGHPRECISION) || []).length;
  if (twotoneHP) failures.push(`${rel}: ${twotoneHP} HIGH-PRECISION twotone construction(s) ("It is not X. It is Y." family) — rewrite as a direct statement`);
  const triad = (prose.match(TRIAD) || []).length;
  if (triad) advisories.push(`${rel}: ${triad} possible rule-of-three triad(s)`);
}

if (UPDATE) {
  const baseline = {};
  for (const [rel, f] of Object.entries(findings)) baseline[rel] = { bold: f.bold };
  writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
  console.log(`copy check: bold baseline written for ${Object.keys(baseline).length} file(s).`);
  process.exit(0);
}

const baseline = existsSync(BASELINE_PATH) ? JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) : {};
const improvements = [];
for (const [rel, f] of Object.entries(findings)) {
  const bBold = (baseline[rel] || {}).bold || 0;
  if (f.bold > bBold) failures.push(`${rel}: ${f.bold} bold/strong hit(s) (baseline ${bBold})`);
  else if (f.bold < bBold) improvements.push(`${rel}: bold ${bBold} -> ${f.bold}`);
}
for (const rel of Object.keys(baseline)) {
  if (!findings[rel]) improvements.push(`${rel}: clean (baseline entry can be dropped)`);
}

if (advisories.length) {
  console.log(`copy check ADVISORY (not failing):\n  ` + advisories.join('\n  '));
}
if (improvements.length) {
  console.log(`copy check: ${improvements.length} file(s) beat the bold baseline — tighten with --update:\n  ` + improvements.join('\n  '));
}
if (failures.length) {
  console.error('COPY HALLMARK failures:');
  for (const f of failures) console.error('  ' + f);
  process.exit(1);
}
console.log(`copy check: ${targets.length} files clean (${Object.keys(baseline).length} baselined for bold).`);
