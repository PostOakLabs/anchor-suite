// sign-verify.js — Anchorproof verify + countersign page logic.
// External module (CSP script-src 'self'); Trusted-Types-safe (no innerHTML — DOM built
// via createElement + textContent). Previously inline; the estate CSP blocked it. Logic
// unchanged from the inline version.
import {
  hashFileBuffer, verifyAssertion, gradeEvidenceStrength,
  buildSigningMessage, createSigningCredential, signMessage,
  anchorEvent, hashEvent, base64ToBytes, bytesToBase64,
} from '/lib/anchorproof.mjs';
import { buildJadesBT } from '/lib/jades.mjs';
// TST verification: reuse verify-runner.mjs for verify parity
import { verifyRfc3161Tst } from '/lib/verify-runner.mjs';

// ---- Small DOM helpers (Trusted-Types-safe: text only) ----
function elem(tag, opts = {}, ...children) {
  const e = document.createElement(tag);
  if (opts.class) e.className = opts.class;
  if (opts.text != null) e.textContent = opts.text;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) e.setAttribute(k, v);
  if (opts.style) e.setAttribute('style', opts.style);
  for (const c of children) if (c) e.appendChild(c);
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

// ---- State ----
let docDigest = null;
let sigArtifact = null;
let counterArtifact = null;
let counterJades = null;

// ---- Authority list for countersign ----
const AUTHORITIES = [
  { id: 'sigstore', name: 'Sigstore TSA', note: 'OpenSSF, ECDSA-P384' },
  { id: 'digicert', name: 'DigiCert', note: 'Commercial CA, RSA' },
  { id: 'freetsa',  name: 'FreeTSA', note: 'Community, RSA' },
];
const authList = document.getElementById('counter-authority-list');
AUTHORITIES.forEach(({ id, name, note }, i) => {
  const row = elem('label', { class: 'provider-row' });
  const cb = elem('input', { attrs: { type: 'checkbox', name: 'counter-auth', value: id } });
  if (i < 2) cb.checked = true;
  row.appendChild(cb);
  row.appendChild(elem('span', { class: 'p-name', text: name }));
  row.appendChild(elem('span', { class: 'p-note', text: note }));
  authList.appendChild(row);
});

// ---- Document drop ----
wireDropZone('doc-drop', 'doc-input', 'doc-drop-label', async (file) => {
  const reader = new FileReader();
  reader.onload = async (e) => {
    docDigest = await hashFileBuffer(e.target.result);
    document.getElementById('doc-hash-value').textContent = 'sha256:' + docDigest;
    document.getElementById('doc-hash-display').hidden = false;
    updateVerifyBtn();
  };
  reader.readAsArrayBuffer(file);
});

// ---- Signature artifact drop ----
wireDropZone('sig-drop', 'sig-input', 'sig-drop-label', async (file) => {
  const text = await file.text();
  try {
    sigArtifact = JSON.parse(text);
    document.getElementById('sig-drop-label').textContent = file.name;
    updateVerifyBtn();
  } catch {
    document.getElementById('sig-drop-label').textContent = 'Invalid JSON, try again';
  }
}, '.json');

function wireDropZone(zoneId, inputId, labelId, onFile, accept) {
  const zone = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  if (accept) input.accept = accept;
  zone.addEventListener('click', () => input.click());
  zone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') input.click(); });
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const f = e.dataTransfer.files[0]; if (f) onFile(f);
  });
  input.addEventListener('change', () => { if (input.files[0]) onFile(input.files[0]); });
}

function updateVerifyBtn() {
  document.getElementById('verify-btn').disabled = !(docDigest && sigArtifact);
}

// ---- Verify ----
document.getElementById('verify-btn').addEventListener('click', async () => {
  document.getElementById('verify-btn').disabled = true;
  const list = document.getElementById('results-list');
  clear(list);

  const results = [];
  let sigVerifyOk = false;

  // (a) Hash match
  const artifactDigest = (sigArtifact.doc_digest || '').replace(/^sha256:/, '');
  const hashMatch = docDigest === artifactDigest;
  results.push({
    label: 'Document hash match',
    ok: hashMatch,
    detail: hashMatch
      ? `sha256:${docDigest}`
      : `Computed sha256:${docDigest}; artifact has sha256:${artifactDigest}`,
  });

  // (b) WebAuthn assertion verification
  try {
    const assertion = {
      authenticatorData: sigArtifact.assertion?.authenticator_data,
      clientDataJSON: sigArtifact.assertion?.client_data_json,
      signature: sigArtifact.assertion?.signature,
    };
    const origin = `${location.protocol}//${location.host}`;
    const sigResult = await verifyAssertion(
      assertion,
      sigArtifact.spki_public_key,
      sigArtifact.signing_message,
      origin,
    );
    sigVerifyOk = sigResult.ok;
    results.push({
      label: 'Passkey assertion',
      ok: sigResult.ok,
      detail: sigResult.ok
        ? `evidence_strength=${sigResult.evidenceStrength}  BE=${sigResult.BE}  BS=${sigResult.BS}  counter=${sigResult.counter}  alg=${sigResult.alg}`
        : sigResult.reason,
    });
  } catch (e) {
    results.push({ label: 'Passkey assertion', ok: false, detail: 'Error: ' + e.message });
  }

  // (c) TST verification for each binding in the signed event anchor
  // Uses verify-runner.mjs, same code path as verify.html (verify parity).
  const bindings = sigArtifact.signed_event_anchor?.anchor_bindings || [];
  if (bindings.length === 0) {
    results.push({ label: 'Timestamp bindings', ok: null, detail: 'No anchor bindings in artifact.' });
  }
  for (const b of bindings) {
    if (b.type === 'rfc3161-tst') {
      try {
        const derBytes = base64ToBytes(b.proof);
        const r = await verifyRfc3161Tst(derBytes, b.anchored_hash, b.log_origin);
        results.push({
          label: `TST: ${b.log_origin || 'unknown'}`,
          ok: r.ok,
          detail: r.ok
            ? `gen_time=${r.genTime}  policy=${r.policyOid}`
            : (r.error || 'Verification failed'),
        });
      } catch (e) {
        results.push({ label: `TST: ${b.log_origin || 'unknown'}`, ok: false, detail: e.message });
      }
    } else {
      results.push({ label: `Binding (${b.type})`, ok: null, detail: 'Verification not supported for this type.' });
    }
  }

  // Render results
  for (const r of results) {
    const badgeClass = r.ok === true ? 'badge-ok' : r.ok === false ? 'badge-fail' : 'badge-skip';
    const badgeText = r.ok === true ? 'OK' : r.ok === false ? 'Fail' : 'Info';
    const card = elem('div', { class: 'result-card' });
    const header = elem('div', { class: 'result-header' });
    header.appendChild(elem('span', { class: `badge ${badgeClass}`, text: badgeText }));
    header.appendChild(elem('span', { class: 'result-name', text: r.label }));
    card.appendChild(header);
    card.appendChild(elem('p', {
      class: 'result-line',
      style: 'font-family:ui-monospace,monospace;font-size:0.8rem;word-break:break-all',
      text: r.detail || '',
    }));
    list.appendChild(card);
  }

  document.getElementById('results-section').hidden = false;

  // Show countersign section if hash matched and signature verified
  if (hashMatch && sigVerifyOk) {
    document.getElementById('countersign-section').hidden = false;
  }
});

// ---- Countersign ----
document.getElementById('countersign-btn').addEventListener('click', async () => {
  const role = document.getElementById('counter-role').value.trim() || 'Sender';
  const authorities = [...document.querySelectorAll('input[name="counter-auth"]:checked')].map((c) => c.value);

  const btn = document.getElementById('countersign-btn');
  const progress = document.getElementById('counter-progress');
  btn.disabled = true;
  progress.hidden = false;
  progress.style.color = 'var(--muted)';

  const envelope = {
    envelope_id: sigArtifact.envelope_id,
    doc_digest: sigArtifact.doc_digest,
  };

  const signingMessage = buildSigningMessage(envelope, role);
  const rpId = location.hostname;

  try {
    progress.textContent = 'Creating signing key... (browser prompt 1 of 2)';
    const freshChallenge = new Uint8Array(32);
    crypto.getRandomValues(freshChallenge);
    const credInfo = await createSigningCredential(rpId, role, freshChallenge);

    progress.textContent = 'Signing... (browser prompt 2 of 2)';
    const assertion = await signMessage(credInfo.credentialId, signingMessage, rpId);

    const msgObj = JSON.parse(signingMessage);

    progress.textContent = authorities.length > 0
      ? `Anchoring completed event with ${authorities.join(', ')}...`
      : 'Building receipt...';

    // Anchor completed event
    let completedAnchor = { event_hash: null, anchor_bindings: [], failures: [] };
    if (authorities.length > 0) {
      const completedEvent = {
        type: 'completed',
        envelope_id: envelope.envelope_id,
        doc_digest: envelope.doc_digest,
        role,
        completed_at: msgObj.signed_at,
        signer_credential_id: sigArtifact.credential_id,
        countersigner_credential_id: credInfo.credentialId,
      };
      completedAnchor = await anchorEvent(completedEvent, authorities);
    }

    // Build countersigner JAdES B-T
    const jades = await buildJadesBT({
      assertion,
      spkiPublicKey: credInfo.spkiPublicKey,
      signingMessage,
      docDigest: envelope.doc_digest,
      signedAt: msgObj.signed_at,
      anchorBindings: completedAnchor.anchor_bindings,
      evidenceStrength: assertion.evidenceStrength,
      BE: assertion.BE,
      BS: assertion.BS,
      counter: assertion.counter,
    });

    progress.hidden = true;

    counterArtifact = {
      version: '1',
      envelope_id: envelope.envelope_id,
      doc_digest: envelope.doc_digest,
      role,
      signed_at: msgObj.signed_at,
      credential_id: credInfo.credentialId,
      spki_public_key: credInfo.spkiPublicKey,
      alg: credInfo.alg,
      aaguid: credInfo.aaguid,
      assertion: {
        authenticator_data: assertion.authenticatorData,
        client_data_json: assertion.clientDataJSON,
        signature: assertion.signature,
      },
      evidence_strength: assertion.evidenceStrength,
      BE: assertion.BE,
      BS: assertion.BS,
      counter: assertion.counter,
      completed_event_anchor: completedAnchor,
      signing_message: signingMessage,
    };
    counterJades = jades;

    const evChip = elem('span', {
      class: assertion.evidenceStrength === 'device_bound'
        ? 'evidence-chip device-bound' : 'evidence-chip synced',
      text: assertion.evidenceStrength === 'device_bound' ? 'device-bound' : 'synced passkey',
    });
    const evDisplay = document.getElementById('counter-evidence-display');
    clear(evDisplay); evDisplay.appendChild(evChip);

    const rinfo = document.getElementById('counter-result-info');
    clear(rinfo);
    const evText = `${assertion.evidenceStrength}  BE=${assertion.BE}  BS=${assertion.BS}  counter=${assertion.counter}`;
    const anchorText = `${completedAnchor.anchor_bindings.length} binding(s)${completedAnchor.failures.length > 0 ? `  (${completedAnchor.failures.length} failed)` : ''}`;
    rinfo.appendChild(elem('dt', { text: 'Countersigned by' }));
    rinfo.appendChild(elem('dd', { class: 'plain-text', text: role }));
    rinfo.appendChild(elem('dt', { text: 'Completed at' }));
    rinfo.appendChild(elem('dd', { text: msgObj.signed_at }));
    rinfo.appendChild(elem('dt', { text: 'Evidence strength' }));
    rinfo.appendChild(elem('dd', { class: 'plain-text', text: evText }));
    rinfo.appendChild(elem('dt', { text: 'Completed event anchor' }));
    rinfo.appendChild(elem('dd', { text: anchorText }));

    document.getElementById('counter-result-section').hidden = false;

  } catch (err) {
    btn.disabled = false;
    progress.style.color = 'var(--err)';
    progress.textContent = 'Error: ' + err.message;
  }
});

// ---- Downloads ----
document.getElementById('download-bundle-btn').addEventListener('click', () => {
  if (!counterArtifact || !sigArtifact) return;
  const bundle = {
    version: '1',
    envelope_id: sigArtifact.envelope_id,
    doc_digest: sigArtifact.doc_digest,
    signatures: [sigArtifact, counterArtifact],
  };
  download(JSON.stringify(bundle, null, 2), `anchorproof-complete-${sigArtifact.envelope_id.slice(0, 8)}.json`);
});

document.getElementById('download-counter-jades-btn').addEventListener('click', () => {
  if (!counterJades || !counterArtifact) return;
  download(JSON.stringify(counterJades, null, 2), `anchorproof-jades-countersig-${counterArtifact.envelope_id.slice(0, 8)}.json`);
});

function download(text, name) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}
