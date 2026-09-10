// verify.js — verify.html working surface logic.
// Accepts: .anchors.json, OCG artifact .json, raw .der TST, .ots file.
// All verification is client-side; works offline after first load.

import { bytesHex, base64ToBytes, parseTstDer, verifyTstBinding } from '/js/tst.js';
import { verifyExecutionHash, verifySignature, verifyComputeProof } from '/vendor/ocg/verify.mjs';
import { verifyOts } from '/lib/verify-runner.mjs';
import { saveToLibrary } from '/lib/library-bridge.mjs';
import { verifyMerkleInclusion } from '/lib/merkle.mjs';
import { verifySigsumBinding, upgradeSigsumBinding } from '/lib/sigsum.mjs';

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

      // §20.1 additive check: if this binding carries merkle_inclusion, the
      // TSA only ever saw the batch's Merkle root — confirm this item's hash
      // is included under that root before calling the item itself verified.
      let merkleLine = null, merkleOk = true;
      if (b.merkle_inclusion && typeof b.merkle_inclusion === 'object') {
        try {
          await verifyMerkleInclusion(b.merkle_inclusion, { anchoredHashHex: b.anchored_hash });
          merkleLine = 'Merkle inclusion: verified (leaf ' + b.merkle_inclusion.index + ' of ' + b.merkle_inclusion.tree_size + ')';
        } catch (e) {
          merkleOk = false;
          merkleLine = 'Merkle inclusion FAILED: ' + e.message;
        }
      }

      if (r.ok && merkleOk) {
        addCard(
          label,
          'ok',
          [merkleLine ? 'Batch root timestamped: ' + r.genTime : 'Timestamp: ' + r.genTime, ...(merkleLine ? [merkleLine] : [])],
          [
            'Hash: ' + (b.merkle_inclusion?.leaf ? 'sha256:' + b.merkle_inclusion.leaf : b.anchored_hash),
            'Policy OID: ' + (r.policy || b.policy_oid || 'n/a'),
            'Serial: ' + r.serial,
            'Authority: ' + (b.log_origin || 'n/a'),
          ],
        );
      } else {
        addCard(label, 'fail', [!r.ok ? 'Verification failed: ' + r.error : merkleLine], [
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
    } else if (b.type === 'c2sp-tlog-proof-v1') {
      await addSigsumProofCard(b);
    } else if (b.type === 'c2sp-tlog-pending-v1') {
      // A stored pending binding used to fall through to the else-branch below
      // and render as FAIL "Unsupported binding type" — the exact opposite of
      // what stampSigsum promises when it hands the caller a pending object to
      // keep. It is a distinct state with an action attached, not a failure.
      addSigsumPendingCard(b);
    } else {
      addCard(b.type || 'Unknown', 'fail', ['Unsupported binding type: ' + b.type], []);
    }
  }
}

// ---- Sigsum cards -----------------------------------------------------------

function sigsumLabel(b) {
  return (b.log_origin || 'Sigsum').split('/')[0];
}

function sigsumDetailLines(b, r) {
  return [
    'Hash: ' + b.anchored_hash,
    'Log: ' + (b.log_url || b.log_origin || 'n/a'),
    'Tree size: ' + b.tree_head?.size,
    'Leaf index: ' + b.inclusion_proof?.leaf_index,
    'Witness quorum: ' + r.quorumWitnessesOk + ' of ' + r.quorumThreshold + ' required (' + r.quorumPolicy + ')',
    ...r.witnessDetail.map((w) => w.matched
      ? `${w.name}${w.quorum ? ' [quorum]' : ''}: ${w.valid ? 'valid' : 'INVALID'}`
      : `unknown witness key_hash ${w.key_hash}`),
  ];
}

async function addSigsumProofCard(b) {
  const label = sigsumLabel(b);
  try {
    const r = await verifySigsumBinding(b);
    if (r.verdict === 'ok') {
      addCard(label, 'ok',
        ['Included in transparency log',
          r.quorumWitnessesOk + ' of ' + r.quorumThreshold + ' required witnesses cosigned'
          + (r.witnessesOk > r.quorumWitnessesOk ? ' (' + r.witnessesOk + ' pinned cosignatures in total)' : '')],
        sigsumDetailLines(b, r));
    } else if (r.verdict === 'log-only') {
      addCard(label, 'pending',
        ['Log-only: the inclusion proof and the log signature verify, but no witness in the ' + r.quorumPolicy + ' quorum cosigned this checkpoint.',
          'The log is asserting inclusion on its own authority. Nobody independent has countersigned that assertion, so a split view of the tree is not ruled out.'
          + (r.witnessesOk > 0 ? ' ' + r.witnessesOk + ' other pinned cosignature(s) are present and valid, and none of them are in the quorum group.' : '')],
        sigsumDetailLines(b, r));
    } else if (r.verdict === 'below-quorum') {
      addCard(label, 'pending',
        ['Below quorum: ' + r.quorumWitnessesOk + ' of the ' + r.quorumThreshold + ' witnesses required by ' + r.quorumPolicy + ' cosigned this checkpoint.',
          'The proof itself is sound. What is missing is independent corroboration.'],
        sigsumDetailLines(b, r));
    } else {
      addCard(label, 'fail', ['Verification failed'], [
        'checksum match: ' + r.checksumOk, 'leaf signature: ' + r.leafSigOk,
        'inclusion proof: ' + r.inclusionOk, 'log signature: ' + r.logSigOk,
      ]);
    }
  } catch (e) {
    addCard(label, 'fail', ['Verification error: ' + e.message], ['Hash: ' + b.anchored_hash]);
  }
}

// Pending: submitted, not yet sequenced. The card carries the only action that
// can complete it — a GET-only inclusion check, NEVER a re-stamp (a second
// submission would spend another 288/24h budget entry and duplicate the leaf in
// a permanent public log). On success the card is replaced in place by the real
// proof card, verified through the same path as any other proof binding.
function addSigsumPendingCard(b) {
  addCard(sigsumLabel(b), 'pending',
    ['Leaf submitted to the transparency log; inclusion has not been observed yet.',
      'The log merges and gathers witness cosignatures on its own cadence. Check again in a minute.'],
    [
      'Hash: ' + b.anchored_hash,
      'Log: ' + (b.log_url || b.log_origin || 'n/a'),
      'Leaf hash: ' + b.leaf_hash,
      'Submitted at: ' + (b.submitted_at || 'n/a'),
    ]);

  const area = el('results-area');
  const card = area?.lastElementChild;
  if (!card) return;
  const btn = makeEl('button', 'btn-secondary', 'Check inclusion');
  btn.type = 'button';
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Checking...';
    try {
      const upgraded = await upgradeSigsumBinding(b);
      if (upgraded && upgraded !== b) {
        card.remove();
        await addSigsumProofCard(upgraded);
      } else {
        btn.disabled = false;
        btn.textContent = 'Check inclusion';
        card.appendChild(makeEl('p', 'result-line', 'Not sequenced yet. The log merges periodically; try again in a minute.'));
      }
    } catch (e) {
      btn.disabled = false;
      btn.textContent = 'Check inclusion';
      card.appendChild(makeEl('p', 'result-line', 'Check failed: ' + e.message));
    }
  });
  card.appendChild(btn);
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
