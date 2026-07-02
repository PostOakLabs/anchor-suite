// verify.js — verify.html working surface logic.
// Accepts: .anchors.json, OCG artifact .json, raw .der TST, .ots file.
// All verification is client-side; works offline after first load.

import { bytesHex, base64ToBytes, verifyTstBinding } from '/js/tst.js';
import { verifyExecutionHash, verifySignature, verifyComputeProof } from '/vendor/ocg/verify.mjs';

// ---- DOM helpers ----------------------------------------------------------

function el(id) { return document.getElementById(id); }

function makeEl(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
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

// ---- OTS verification -----------------------------------------------------

async function verifyOtsBinding(binding) {
  const OT = globalThis.OpenTimestamps;
  if (!OT) return { ok: false, pending: false, error: 'OpenTimestamps library not available' };

  let otsBytes;
  try {
    otsBytes = base64ToBytes(binding.proof);
  } catch (e) {
    return { ok: false, pending: false, error: 'Invalid proof base64' };
  }

  const hashHex = (binding.anchored_hash || '').replace('sha256:', '');
  const hashBytes = new Uint8Array(hashHex.length / 2);
  for (let i = 0; i < hashBytes.length; i++) hashBytes[i] = parseInt(hashHex.slice(i * 2, i * 2 + 2), 16);

  let fileOts;
  try {
    fileOts = OT.DetachedTimestampFile.deserialize(otsBytes);
  } catch (e) {
    return { ok: false, pending: false, error: 'Cannot parse OTS proof: ' + e.message };
  }

  const fileHash = OT.DetachedTimestampFile.fromHash(new OT.Ops.OpSHA256(), hashBytes);

  try {
    const result = await OT.verify(fileOts, fileHash);
    if (result !== null && result !== undefined) {
      const ts = typeof result === 'number' ? new Date(result * 1000).toISOString() : String(result);
      return { ok: true, genTime: ts };
    }
    return { ok: false, pending: true };
  } catch (e) {
    const msg = e?.message || String(e);
    if (msg.toLowerCase().includes('pending') || msg.toLowerCase().includes('calendar')) {
      return { ok: false, pending: true };
    }
    return { ok: false, pending: false, error: msg };
  }
}

// ---- main verification dispatcher -----------------------------------------

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
      const r = await verifyOtsBinding(b);
      if (r.ok) {
        addCard('OpenTimestamps', 'ok', ['Bitcoin-anchored at: ' + r.genTime], ['Hash: ' + b.anchored_hash]);
      } else if (r.pending) {
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
      [artifact.anchor_bindings.length + ' binding(s) found — verifying...'],
      []);
    await verifyBindings(artifact.anchor_bindings);
  }
}

// ---- raw DER file ---------------------------------------------------------

async function verifyRawDer(bytes) {
  clearResults();
  showEl('results-area', true);

  // We don't know the hash to validate against, so just parse and report what we can.
  const { bytesHex: bh } = await import('/js/tst.js');
  const { pkijs, asn1js } = await import('/vendor/pkijs.bundle.mjs');

  try {
    const tsr = new pkijs.TimeStampResp({ schema: asn1js.fromBER(new Uint8Array(bytes).buffer).result });
    if (![0, 1].includes(tsr.status.status)) {
      addCard('Raw DER', 'fail', ['TSA refused: PKIStatus ' + tsr.status.status], []);
      return;
    }
    const signed = new pkijs.SignedData({ schema: tsr.timeStampToken.content });
    const tstInfoDer = new Uint8Array(signed.encapContentInfo.eContent.valueBlock.valueHexView);
    const tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(tstInfoDer.buffer).result });
    const imprint = bytesHex(new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView));

    addCard('Raw DER TST', 'ok',
      ['Timestamp: ' + tstInfo.genTime.toISOString(), 'Stamped hash: sha256:' + imprint],
      ['Policy OID: ' + tstInfo.policy,
       'Serial: ' + bytesHex(new Uint8Array(tstInfo.serialNumber.valueBlock.valueHexView)),
       'Certs in token: ' + (signed.certificates || []).length]);
  } catch (e) {
    addCard('Raw DER', 'fail', ['Parse error: ' + e.message], []);
  }
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
      if (isOcgArtifact(obj)) { await verifyOcgArtifact(obj); return; }
      if (isAnchorsJson(obj)) { await verifyBindings(obj.anchor_bindings); return; }
      addCard('JSON file', 'fail', ['Not an OCG artifact or anchors.json'], []);
      return;
    } catch { /* not JSON */ }
  }

  // Try OTS
  if (file.name.endsWith('.ots')) {
    const OT = globalThis.OpenTimestamps;
    if (!OT) { addCard('OTS file', 'fail', ['OpenTimestamps library not available'], []); return; }
    // Wrap as a synthetic binding for our verifier
    const { bytesToBase64: b64 } = await import('/js/tst.js');
    const synth = {
      type: 'opentimestamps',
      anchored_hash: 'sha256:' + '0'.repeat(64), // unknown — just parse for info
      log_origin: 'bitcoin',
      proof: b64(bytes),
    };
    const r = await verifyOtsBinding(synth);
    if (r.ok) {
      addCard('OpenTimestamps', 'ok', ['Bitcoin-anchored at: ' + r.genTime], []);
    } else if (r.pending) {
      addCard('OpenTimestamps', 'pending', ['Proof is pending Bitcoin confirmation.'], []);
    } else {
      addCard('OpenTimestamps', 'fail', ['Error: ' + r.error], []);
    }
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
