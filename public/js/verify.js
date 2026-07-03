// verify.js — verify.html working surface logic.
// Accepts: .anchors.json, OCG artifact .json, raw .der TST, .ots file.
// All verification is client-side; works offline after first load.

import { bytesHex, base64ToBytes, parseTstDer, verifyTstBinding } from '/js/tst.js';
import { verifyExecutionHash, verifySignature, verifyComputeProof } from '/vendor/ocg/verify.mjs';
import { verifyOts } from '/lib/verify-runner.mjs';
import { saveToLibrary } from '/lib/library-bridge.mjs';

// ---- DOM helpers ----------------------------------------------------------

function el(id) { return document.getElementById(id); }

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

// ---- file classification --------------------------------------------------

function isOcgArtifact(obj) {
  return obj &&
    typeof obj.execution_hash === 'string' &&
    obj.policy_parameters !== undefined &&
    obj.output_payload !== undefined;
}

function isAnchorsJson(obj) {
  return obj && Array.isArray(obj.anchor_bindings);
}

// ---- result card builder --------------------------------------------------

function clearResults() {
  const area = el('results-area');
  if (area) area.textContent = '';
}

function addCard(authority, status, lines, details) {
  const area = el('results-area');
  if (!area) return;

  const card = makeEl('div', 'result-card');
  const header = makeEl('div', 'result-header');

  const badge = makeEl('span', 'badge badge-' + status,
    status === 'ok' ? 'Verified' : status === 'pending' ? 'Pending' : 'Failed');
  header.appendChild(badge);

  const name = makeEl('span', 'result-name', authority);
  header.appendChild(name);

  card.appendChild(header);

  for (const line of lines) {
    const p = makeEl('p', 'result-line', line);
    card.appendChild(p);
  }

  if (details && details.length) {
    const toggleBtn = makeEl('button', 'detail-toggle', 'Show details');
    toggleBtn.type = 'button';
    const detailBox = makeEl('div', 'detail-box');
    detailBox.hidden = true;
    for (const d of details) {
      const p = makeEl('p', 'detail-line', d);
      detailBox.appendChild(p);
    }
    toggleBtn.addEventListener('click', () => {
      const open = !detailBox.hidden;
      detailBox.hidden = open;
      toggleBtn.textContent = open ? 'Show details' : 'Hide details';
    });
    card.appendChild(toggleBtn);
    card.appendChild(detailBox);
  }

  area.appendChild(card);
}

// ---- binding verification -------------------------------------------------

async function verifyBindings(bindings) {
  clearResults();
  showEl('results-area', true);

  for (const b of bindings) {
    if (b.type === 'rfc3161-tst') {
      const label = (b.log_origin || 'Unknown TSA').replace(/^https?:\/\//, '').split('/')[0];
      const r = await verifyTstBinding(b);
      if (r.ok) {
        addCard(
          label,
          'ok',
          ['Timestamp: ' + r.genTime],
          [
            'Hash: ' + b.anchored_hash,
            'Policy OID: ' + (r.policy || b.policy_oid || 'n/a'),
            'Serial: ' + r.serial,
            'Authority: ' + (b.log_origin || 'n/a'),
          ],
        );
      } else {
        addCard(label, 'fail', ['Verification failed: ' + r.error], [
          'Hash claimed: ' + b.anchored_hash,
          'Authority: ' + (b.log_origin || 'n/a'),
        ]);
      }
    } else if (b.type === 'opentimestamps') {
      const otsBytes = base64ToBytes(b.proof);
      const r = await verifyOts(otsBytes, b.anchored_hash);
      if (r.status === 'complete') {
        addCard('OpenTimestamps', 'ok', ['Bitcoin-anchored at: ' + r.genTime], ['Hash: ' + b.anchored_hash]);
      } else if (r.status === 'pending') {
        addCard('OpenTimestamps', 'pending',
          ['Proof is pending Bitcoin confirmation (typically a few hours after stamping).'],
          ['Hash: ' + b.anchored_hash, 'Tip: re-verify later once Bitcoin block confirms.'],
        );
      } else {
        addCard('OpenTimestamps', 'fail', ['Failed: ' + r.error], ['Hash: ' + b.anchored_hash]);
      }
    } else {
      addCard(b.type || 'Unknown', 'fail', ['Unsupported binding type: ' + b.type], []);
    }
  }
}

async function verifyOcgArtifact(artifact) {
  clearResults();
  showEl('results-area', true);

  // §4 execution hash
  try {
    const r = await verifyExecutionHash(artifact);
    addCard('OCG §4 Execution Hash', r.valid ? 'ok' : 'fail',
      [r.valid ? 'Execution hash matches recomputed hash' : 'Execution hash DOES NOT match recomputed hash'],
      ['Claimed: ' + r.claimed_hash, 'Computed: ' + r.computed_hash]);
  } catch (e) {
    addCard('OCG §4 Execution Hash', 'fail', ['Error: ' + e.message], []);
  }

  // §16 signature (optional)
  if (artifact.audit_signature?.proof) {
    try {
      const valid = await verifySignature(artifact);
      addCard('OCG §16 Data Integrity Signature', valid ? 'ok' : 'fail',
        [valid ? 'eddsa-jcs-2022 signature valid' : 'Signature INVALID'],
        ['verificationMethod: ' + (artifact.audit_signature.proof.verificationMethod || 'n/a')]);
    } catch (e) {
      addCard('OCG §16 Data Integrity Signature', 'fail', ['Error: ' + e.message], []);
    }
  }

  // §18 compute proof (optional)
  if (artifact.audit_signature?.compute_proof) {
    try {
      const valid = verifyComputeProof(artifact);
      addCard('OCG §18 Compute Integrity Proof', valid ? 'ok' : 'fail',
        [valid ? 'Groth16-BN254 seal valid' : 'Seal INVALID'],
        ['receiptFormat: ' + (artifact.audit_signature.compute_proof.receiptFormat || 'n/a')]);
    } catch (e) {
      addCard('OCG §18 Compute Integrity Proof', 'fail', ['Error: ' + e.message], []);
    }
  }

  // §20 anchor bindings (optional)
  if (Array.isArray(artifact.anchor_bindings) && artifact.anchor_bindings.length > 0) {
    addCard('OCG §20 Anchor Bindings', 'ok',
      [artifact.anchor_bindings.length + ' binding(s) found - verifying...'],
      []);
    await verifyBindings(artifact.anchor_bindings);
  }
}

// ---- raw DER file ---------------------------------------------------------
// Parse and report metadata without chain verification (authority unknown).

async function verifyRawDer(bytes) {
  clearResults();
  showEl('results-area', true);

  const { parseRfc3161Tst } = await import('/lib/verify-runner.mjs');
  const r = parseRfc3161Tst(bytes);

  if (!r.ok) {
    addCard('Raw DER', 'fail', ['Parse error: ' + r.error], []);
    return;
  }

  addCard('Raw DER TST', 'ok',
    ['Timestamp: ' + r.genTime, 'Stamped hash: ' + r.stampedHash],
    [
      'Policy OID: ' + r.policyOid,
      'Serial: ' + r.serial,
      'Certs in token: ' + r.certCount,
      'Note: chain not validated (authority unknown). Use /verify.html with anchors.json for full verification.',
    ],
  );
}

// ---- file drop handler ----------------------------------------------------

async function processFile(file) {
  const area = el('results-area');
  if (area) area.textContent = '';

  const buf = await file.arrayBuffer();
  const bytes = new Uint8Array(buf);

  // Try JSON first
  if (file.name.endsWith('.json') || file.name.endsWith('.txt')) {
    try {
      const text = new TextDecoder().decode(bytes);
      const obj = JSON.parse(text);
      if (isOcgArtifact(obj)) {
        await verifyOcgArtifact(obj);
        saveToLibrary(text, obj).then(() => showToast('Saved to Artifact Library')).catch(() => {});
        return;
      }
      if (isAnchorsJson(obj)) {
        await verifyBindings(obj.anchor_bindings);
        saveToLibrary(text, obj).then(() => showToast('Saved to Artifact Library')).catch(() => {});
        return;
      }
      addCard('JSON file', 'fail', ['Not an OCG artifact or anchors.json'], []);
      return;
    } catch { /* not JSON */ }
  }

  // Try OTS
  if (file.name.endsWith('.ots')) {
    const synth = {
      type: 'opentimestamps',
      anchored_hash: 'sha256:' + '0'.repeat(64),
      log_origin: 'bitcoin',
      proof: btoa(String.fromCharCode(...bytes)),
    };
    const r = await verifyOts(bytes, synth.anchored_hash);
    if (r.status === 'complete') {
      addCard('OpenTimestamps', 'ok', ['Bitcoin-anchored at: ' + r.genTime], []);
    } else if (r.status === 'pending') {
      addCard('OpenTimestamps', 'pending', ['Proof is pending Bitcoin confirmation.'], []);
    } else {
      addCard('OpenTimestamps', 'fail', ['Error: ' + r.error], []);
    }
    showEl('results-area', true);
    return;
  }

  // Try raw DER
  await verifyRawDer(bytes);
}

function showEl(id, show) {
  const e = el(id);
  if (e) e.hidden = !show;
}

// ---- init -----------------------------------------------------------------

function init() {
  const dz = el('drop-zone');
  if (dz) {
    dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
    dz.addEventListener('drop', async (e) => {
      e.preventDefault();
      dz.classList.remove('drag-over');
      const file = e.dataTransfer?.files?.[0];
      if (file) {
        const label = el('drop-label');
        if (label) label.textContent = 'Verifying ' + file.name + '...';
        await processFile(file);
      }
    });
    dz.addEventListener('click', () => el('verify-file-input')?.click());
  }

  const fi = el('verify-file-input');
  if (fi) {
    fi.addEventListener('change', async () => {
      const file = fi.files?.[0];
      if (file) {
        const label = el('drop-label');
        if (label) label.textContent = 'Verifying ' + file.name + '...';
        await processFile(file);
      }
      fi.value = '';
    });
  }
}

document.addEventListener('DOMContentLoaded', init);
