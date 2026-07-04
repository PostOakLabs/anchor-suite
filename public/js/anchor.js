// anchor.js — anchor.html working surface logic.
// Imports: pkijs via tst.js, OTS via window.OpenTimestamps (loaded as UMD script).
// No inline scripts, no eval, no innerHTML. All DOM ops via element APIs.

import {
  hexToBytes, bytesHex, bytesToBase64, base64ToBytes,
  freshNonce, freshNonce6, buildTsqDer,
} from '/lib/tsq.mjs';
import { parseTstDer, extractTstMeta, dnOf } from '/js/tst.js';
import { saveToLibrary } from '/lib/library-bridge.mjs';

// ---- state ----------------------------------------------------------------

let currentHashHex = null;  // 64 hex chars, no prefix
let currentFile = null;     // File object | null
let currentOcgArtifact = null; // parsed OCG JSON | null
let stampResults = [];      // anchor_bindings entries (successful stamps)

// ---- DOM refs (resolved after DOMContentLoaded) ---------------------------

let providerCheckboxes = {};

// ---- utility --------------------------------------------------------------

function el(id) { return document.getElementById(id); }

function setStatus(containerId, cls, msg) {
  const c = el(containerId);
  if (!c) return;
  c.textContent = msg;
  c.className = 'inline-status ' + cls;
}

function showEl(id, show = true) {
  const e = el(id);
  if (e) e.hidden = !show;
}

function makeEl(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// ---- toast ----------------------------------------------------------------

function showToast(msg) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const t = makeEl('div', 'toast', msg);
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add('toast-show'));
  setTimeout(() => { t.classList.remove('toast-show'); setTimeout(() => t.remove(), 300); }, 3000);
}

// ---- hash display ---------------------------------------------------------

function displayHash(hex) {
  currentHashHex = hex;
  stampResults = [];
  const display = el('hash-display');
  if (display) display.hidden = false;
  const val = el('hash-value');
  if (val) val.textContent = 'sha256:' + hex;
  showEl('stamp-section', true);
  showEl('output-area', false);
  clearResults();
}

function clearResults() {
  const ra = el('results-area');
  if (ra) ra.textContent = '';
  const pa = el('progress-area');
  if (pa) pa.textContent = '';
  showEl('output-area', false);
}

// ---- file handling --------------------------------------------------------

async function sha256Bytes(buf) {
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return bytesHex(new Uint8Array(hash));
}

function isOcgArtifact(obj) {
  return obj &&
    typeof obj.execution_hash === 'string' &&
    obj.policy_parameters !== undefined &&
    obj.output_payload !== undefined;
}

async function processFile(file) {
  currentFile = file;
  currentOcgArtifact = null;
  showEl('recompute-row', false);

  const buf = await file.arrayBuffer();
  const hex = await sha256Bytes(buf);

  // Try to detect an OCG artifact (JSON with execution_hash)
  if (file.name.endsWith('.json') || file.type === 'application/json') {
    try {
      const text = new TextDecoder().decode(buf);
      const obj = JSON.parse(text);
      if (isOcgArtifact(obj)) {
        currentOcgArtifact = obj;
        // Use execution_hash as the anchored_hash (per §20)
        const execHex = obj.execution_hash.replace(/^sha256:/, '');
        displayHash(execHex);
        showEl('ocg-banner', true);
        showEl('recompute-row', true);
        const reRow = el('recompute-row');
        if (reRow) {
          const fn = reRow.querySelector('.recompute-filename');
          if (fn) fn.textContent = file.name;
        }
        return;
      }
    } catch { /* not valid JSON, fall through to file hash */ }
  }

  showEl('ocg-banner', false);
  displayHash(hex);
}

// §4 recompute offer — runs client-side via vendored OCG verifier
async function handleRecompute() {
  if (!currentOcgArtifact) return;
  const btn = el('recompute-btn');
  const status = el('recompute-status');
  if (btn) btn.disabled = true;
  if (status) { status.textContent = 'Verifying...'; status.className = 'inline-status'; }

  try {
    const { verifyExecutionHash } = await import('/vendor/ocg/verify.mjs');
    const result = await verifyExecutionHash(currentOcgArtifact);
    if (result.valid) {
      if (status) { status.textContent = 'Execution hash confirmed'; status.className = 'inline-status ok'; }
    } else {
      if (status) {
        status.textContent = 'Hash mismatch: computed ' + result.computed_hash;
        status.className = 'inline-status err';
      }
    }
  } catch (e) {
    if (status) { status.textContent = 'Verify error: ' + e.message; status.className = 'inline-status err'; }
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ---- hash paste / deep link -----------------------------------------------

function trySetHashFromText(raw) {
  const m = raw.trim().match(/(?:^|sha256:)([0-9a-f]{64})$/i);
  if (m) { displayHash(m[1].toLowerCase()); return true; }
  return false;
}

// ---- TSA stamping ---------------------------------------------------------

async function stampSigstore(hashHex) {
  const nonce6 = freshNonce6();
  const nonceNum = parseInt(bytesHex(nonce6), 16);
  const hashB64 = bytesToBase64(hexToBytes(hashHex));

  const res = await fetch('https://timestamp.sigstore.dev/api/v1/timestamp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ artifactHash: hashB64, hashAlgorithm: 'sha256', nonce: nonceNum, certificates: true }),
    signal: AbortSignal.timeout(30_000),
  });

  if (!res.ok) throw new Error('Sigstore HTTP ' + res.status);
  const der = await res.arrayBuffer();
  return { der: new Uint8Array(der), logOrigin: 'https://timestamp.sigstore.dev/api/v1/timestamp' };
}

async function stampRelay(relayPath, directUrl, hashHex) {
  const nonce = freshNonce();
  const tsqDer = buildTsqDer(hexToBytes(hashHex), nonce);

  const res = await fetch(relayPath, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: tsqDer,
    signal: AbortSignal.timeout(35_000),
  });

  if (!res.ok) throw new Error('Relay HTTP ' + res.status);
  const ct = (res.headers.get('Content-Type') || '').split(';')[0].trim();
  if (ct !== 'application/timestamp-reply') throw new Error('Unexpected Content-Type: ' + ct);
  const der = await res.arrayBuffer();
  return { der: new Uint8Array(der), logOrigin: directUrl };
}

async function stampGitHub(hashHex) {
  const nonce = freshNonce();
  const tsqDer = buildTsqDer(hexToBytes(hashHex), nonce);

  const res = await fetch('https://timestamp.githubapp.com/api/v1/timestamp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: tsqDer,
    signal: AbortSignal.timeout(30_000),
  });

  if (!res.ok) throw new Error('GitHub TSA HTTP ' + res.status);
  const der = await res.arrayBuffer();
  return { der: new Uint8Array(der), logOrigin: 'https://timestamp.githubapp.com/api/v1/timestamp' };
}

async function stampOts(hashHex) {
  const OT = globalThis.OpenTimestamps;
  if (!OT) throw new Error('OpenTimestamps library not loaded');

  const hashBytes = hexToBytes(hashHex);
  const fileOts = OT.DetachedTimestampFile.fromHash(new OT.Ops.OpSHA256(), hashBytes);
  await OT.stamp(fileOts);
  const otsBytes = fileOts.serializeToBytes();

  return {
    type: 'opentimestamps',
    anchored_hash: 'sha256:' + hashHex,
    log_origin: 'bitcoin',
    proof: bytesToBase64(new Uint8Array(otsBytes)),
  };
}

// Turn a DER result + logOrigin into an anchor_bindings entry.
function derToBinding(der, logOrigin, hashHex) {
  const { tstInfo, signed } = parseTstDer(der);
  const meta = extractTstMeta(tstInfo, signed);
  return {
    type: 'rfc3161-tst',
    anchored_hash: 'sha256:' + hashHex,
    log_origin: logOrigin,
    proof: bytesToBase64(der),
    ...meta,
  };
}

// ---- provider config ------------------------------------------------------

const PROVIDERS = [
  {
    id: 'sigstore',
    label: 'Sigstore TSA',
    note: 'OpenSSF public-good, instant',
    defaultOn: true,
    stamp: (h) => stampSigstore(h).then(({ der, logOrigin }) => derToBinding(der, logOrigin, h)),
  },
  {
    id: 'digicert',
    label: 'DigiCert',
    note: 'Commercial CA (AATL root), instant',
    defaultOn: true,
    stamp: (h) => stampRelay('/relay/digicert', 'http://timestamp.digicert.com', h).then(({ der, logOrigin }) => derToBinding(der, logOrigin, h)),
  },
  {
    id: 'sectigo',
    label: 'Sectigo',
    note: 'Commercial CA, instant',
    defaultOn: false,
    stamp: (h) => stampRelay('/relay/sectigo', 'http://timestamp.sectigo.com', h).then(({ der, logOrigin }) => derToBinding(der, logOrigin, h)),
  },
  {
    id: 'freetsa',
    label: 'FreeTSA',
    note: 'Community TSA (pair with another for reliability)',
    defaultOn: false,
    stamp: (h) => stampRelay('/relay/freetsa', 'https://freetsa.org/tsr', h).then(({ der, logOrigin }) => derToBinding(der, logOrigin, h)),
  },
  {
    id: 'github',
    label: 'GitHub TSA',
    note: 'HSM-backed (undocumented for third-party use)',
    defaultOn: false,
    stamp: (h) => stampGitHub(h).then(({ der, logOrigin }) => derToBinding(der, logOrigin, h)),
  },
  {
    id: 'opentimestamps',
    label: 'OpenTimestamps',
    note: 'Bitcoin-anchored, trust-minimized (pending for several hours)',
    defaultOn: false,
    stamp: (h) => stampOts(h),
  },
];

// ---- build provider UI ----------------------------------------------------

function buildProviderList() {
  const list = el('provider-list');
  if (!list) return;
  list.textContent = '';

  for (const p of PROVIDERS) {
    const row = document.createElement('label');
    row.className = 'provider-row';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.id = 'cb-' + p.id;
    cb.name = p.id;
    cb.checked = p.defaultOn;
    providerCheckboxes[p.id] = cb;

    const nameSpan = makeEl('span', 'p-name', p.label);
    const noteSpan = makeEl('span', 'p-note', p.note);

    const statusSpan = document.createElement('span');
    statusSpan.id = 'pstatus-' + p.id;
    statusSpan.className = 'p-status';

    row.appendChild(cb);
    row.appendChild(nameSpan);
    row.appendChild(noteSpan);
    row.appendChild(statusSpan);
    list.appendChild(row);
  }
}

// ---- stamping -------------------------------------------------------------

async function doStamp() {
  if (!currentHashHex) return;
  const selected = PROVIDERS.filter((p) => providerCheckboxes[p.id]?.checked);
  if (selected.length === 0) { alert('Select at least one timestamp authority.'); return; }

  const btn = el('stamp-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Stamping...'; }
  showEl('progress-area', true);
  showEl('output-area', false);
  stampResults = [];

  // Reset per-provider status
  for (const p of selected) {
    const s = el('pstatus-' + p.id);
    if (s) { s.textContent = 'waiting...'; s.className = 'p-status pending'; }
  }

  // Run all selected providers in parallel
  const jobs = selected.map(async (p) => {
    const s = el('pstatus-' + p.id);
    if (s) { s.textContent = 'stamping...'; s.className = 'p-status pending'; }
    try {
      const binding = await p.stamp(currentHashHex);
      stampResults.push(binding);
      if (s) { s.textContent = binding.gen_time || 'pending'; s.className = 'p-status ok'; }
    } catch (e) {
      if (s) { s.textContent = 'failed: ' + e.message; s.className = 'p-status err'; }
    }
  });

  await Promise.allSettled(jobs);

  if (btn) { btn.disabled = false; btn.textContent = 'Stamp'; }

  if (stampResults.length > 0) {
    buildOutputSection();
    showEl('output-area', true);

    // Save to Artifact Library
    try {
      let rawText, parsed;
      if (currentOcgArtifact) {
        parsed = { ...currentOcgArtifact, anchor_bindings: stampResults };
        rawText = JSON.stringify(parsed, null, 2);
      } else {
        parsed = { anchor_bindings: stampResults };
        rawText = JSON.stringify(parsed, null, 2);
      }
      await saveToLibrary(rawText, parsed);
      showToast('Saved to Artifact Library');
    } catch { /* non-fatal */ }
  }
}

// ---- output section -------------------------------------------------------

function buildOutputSection() {
  const area = el('output-area');
  if (!area) return;
  area.textContent = '';

  const heading = makeEl('h3', 'output-heading', 'Your stamps (' + stampResults.length + ')');
  area.appendChild(heading);

  const dlRow = document.createElement('div');
  dlRow.className = 'output-row';

  const jsonBtn = makeEl('button', 'btn btn-sm', 'Download anchors.json');
  jsonBtn.type = 'button';
  jsonBtn.addEventListener('click', downloadAnchorsJson);
  dlRow.appendChild(jsonBtn);

  if (currentOcgArtifact) {
    const artifactBtn = makeEl('button', 'btn btn-sm', 'Download artifact with anchor_bindings');
    artifactBtn.type = 'button';
    artifactBtn.addEventListener('click', downloadReemittedArtifact);
    dlRow.appendChild(artifactBtn);
  }

  const libraryBtn = makeEl('button', 'btn btn-sm btn-ghost', 'View in Library');
  libraryBtn.type = 'button';
  libraryBtn.addEventListener('click', () => { location.href = '/artifacts.html'; });
  dlRow.appendChild(libraryBtn);

  const printBtn = makeEl('button', 'btn btn-sm btn-ghost', 'Printable receipt');
  printBtn.type = 'button';
  printBtn.addEventListener('click', showReceipt);
  dlRow.appendChild(printBtn);

  area.appendChild(dlRow);

  const list = document.createElement('ul');
  list.className = 'binding-summary';
  for (const b of stampResults) {
    const li = document.createElement('li');
    const origin = b.log_origin || 'unknown';
    li.textContent = (b.type === 'opentimestamps' ? 'OTS (pending)' : origin.replace(/^https?:\/\//, '').split('/')[0]) +
      (b.gen_time ? ' - ' + b.gen_time : '');
    list.appendChild(li);
  }
  area.appendChild(list);

  const verifyHint = makeEl('p', 'verify-hint', 'Verify these stamps at /verify.html or with openssl ts -verify.');
  area.appendChild(verifyHint);
}

function anchorsJsonPayload() {
  return JSON.stringify({ anchor_bindings: stampResults }, null, 2);
}

function downloadAnchorsJson() {
  const json = anchorsJsonPayload();
  const blob = new Blob([json], { type: 'application/json' });
  triggerDownload(blob, 'anchors.json');
}

function downloadReemittedArtifact() {
  if (!currentOcgArtifact) return;
  const artifact = { ...currentOcgArtifact, anchor_bindings: stampResults };
  const blob = new Blob([JSON.stringify(artifact, null, 2)], { type: 'application/json' });
  const name = (currentFile?.name || 'artifact').replace(/\.json$/, '') + '.anchored.json';
  triggerDownload(blob, name);
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function showReceipt() {
  const w = window.open('', '_blank');
  if (!w) return;
  const hashStr = 'sha256:' + currentHashHex;
  let rows = '';
  for (const b of stampResults) {
    if (b.type === 'opentimestamps') {
      rows += '<tr><td>OpenTimestamps</td><td>bitcoin</td><td>pending (several hours)</td></tr>\n';
    } else {
      const origin = (b.log_origin || '').replace(/^https?:\/\//, '').split('/')[0];
      rows += `<tr><td>${origin}</td><td>${b.policy_oid || ''}</td><td>${b.gen_time || ''}</td></tr>\n`;
    }
  }
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Anchor Receipt</title>
<style>body{font-family:monospace;padding:2rem;max-width:80ch}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:0.4rem 0.6rem;text-align:left}th{background:#f4f4f0}</style>
</head><body>
<h1>Anchor Receipt</h1>
<p><strong>Hash:</strong> ${hashStr}</p>
<p>Post Oak Labs never sees your document. The timestamp authorities listed below are the issuers.</p>
<table><thead><tr><th>Authority</th><th>Policy OID</th><th>Timestamp</th></tr></thead><tbody>${rows}</tbody></table>
<p>Verify with: <code>openssl ts -verify -digest &lt;hash&gt; -in tst.der -CAfile &lt;root.pem&gt;</code></p>
<p>Full receipt: download anchors.json and verify at anchor.ainumbers.co/verify.html</p>
</body></html>`;
  w.document.write(html);
  w.document.close();
}

// ---- copy hash button -----------------------------------------------------

function copyHash() {
  const val = 'sha256:' + currentHashHex;
  navigator.clipboard?.writeText(val).catch(() => {});
  const btn = el('copy-hash-btn');
  if (btn) {
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  }
}

// ---- init -----------------------------------------------------------------

function init() {
  buildProviderList();

  // Deep link: #eh=sha256:abc123...
  const frag = location.hash.slice(1);
  const m = frag.match(/(?:^|[&;])eh=sha256:([0-9a-f]{64})(?:[&;]|$)/i);
  if (m) displayHash(m[1].toLowerCase());

  // Drop zone
  const dz = el('drop-zone');
  if (dz) {
    dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
    dz.addEventListener('drop', async (e) => {
      e.preventDefault();
      dz.classList.remove('drag-over');
      const file = e.dataTransfer?.files?.[0];
      if (file) await processFile(file);
    });
    dz.addEventListener('click', () => el('file-input')?.click());
  }

  // File input (hidden, triggered by drop zone click)
  const fi = el('file-input');
  if (fi) {
    fi.addEventListener('change', async () => {
      const file = fi.files?.[0];
      if (file) await processFile(file);
      fi.value = '';
    });
  }

  // Hash text input
  const hashInput = el('hash-input');
  if (hashInput) {
    hashInput.addEventListener('input', () => {
      const ok = trySetHashFromText(hashInput.value);
      hashInput.classList.toggle('input-err', hashInput.value.length > 10 && !ok);
    });
    hashInput.addEventListener('paste', (e) => {
      const text = e.clipboardData?.getData('text') || '';
      setTimeout(() => { if (!trySetHashFromText(text)) trySetHashFromText(hashInput.value); }, 0);
    });
  }

  // Recompute button
  const rcBtn = el('recompute-btn');
  if (rcBtn) rcBtn.addEventListener('click', handleRecompute);

  // Stamp button
  const sb = el('stamp-btn');
  if (sb) sb.addEventListener('click', doStamp);

  // Copy hash button
  const chBtn = el('copy-hash-btn');
  if (chBtn) chBtn.addEventListener('click', copyHash);
}

document.addEventListener('DOMContentLoaded', init);
