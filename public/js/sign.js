// sign.js — Anchorproof signing page logic.
// External module (CSP script-src 'self'); Trusted-Types-safe (no innerHTML — all DOM
// built via createElement + textContent, matching verify.js). Previously inline; the
// estate CSP (script-src 'self' + require-trusted-types-for 'script') blocked the inline
// module entirely, leaving the page dead. Logic is unchanged from the inline version.
import {
  hashFileBuffer, buildSigningMessage, hashEvent,
  createSigningCredential, signMessage, gradeEvidenceStrength,
  anchorEvent, base64ToBytes, bytesToBase64, bytesHex,
} from '/lib/anchorproof.mjs';
import { buildJadesBT } from '/lib/jades.mjs';

// ---- Small DOM helpers (Trusted-Types-safe: text only, never innerHTML) ----
function elem(tag, opts = {}, ...children) {
  const e = document.createElement(tag);
  if (opts.class) e.className = opts.class;
  if (opts.text != null) e.textContent = opts.text;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) e.setAttribute(k, v);
  for (const c of children) if (c) e.appendChild(c);
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

// ---- Parse URL fragment ----
// Format: #h=<sha256hex>&e=<envelope_id>
const fragment = Object.fromEntries(
  location.hash.slice(1).split('&').map((p) => p.split('='))
);
const expectedDigest = fragment.h || null;
const envelopeId = fragment.e || null;

if (!expectedDigest || !envelopeId) {
  document.getElementById('page-subtitle').textContent =
    'No signing request found in this link.';
  document.getElementById('error-banner').hidden = false;
  document.getElementById('error-text').textContent =
    'This page should be opened from a signing link. Go to the create envelope page to start.';
} else {
  // Show envelope banner — envelopeId + expectedDigest are attacker-influenceable URL
  // fragment values, so they go in via textContent, never HTML.
  document.getElementById('envelope-banner').hidden = false;
  const info = document.getElementById('envelope-info');
  clear(info);
  info.appendChild(elem('dt', { text: 'Envelope ID' }));
  info.appendChild(elem('dd', { text: envelopeId }));
  info.appendChild(elem('dt', { text: 'Expected document hash' }));
  info.appendChild(elem('dd', { text: 'sha256:' + expectedDigest }));
}

// ---- Authority list for anchoring the signed event ----
const AUTHORITIES = [
  { id: 'sigstore', name: 'Sigstore TSA', note: 'OpenSSF, ECDSA-P384' },
  { id: 'digicert', name: 'DigiCert', note: 'Commercial CA, RSA' },
  { id: 'freetsa',  name: 'FreeTSA', note: 'Community, RSA' },
];
const authList = document.getElementById('sign-authority-list');
AUTHORITIES.forEach(({ id, name, note }, i) => {
  const row = elem('label', { class: 'provider-row' });
  const cb = elem('input', { attrs: { type: 'checkbox', name: 'sign-auth', value: id } });
  if (i < 2) cb.checked = true;
  row.appendChild(cb);
  row.appendChild(elem('span', { class: 'p-name', text: name }));
  row.appendChild(elem('span', { class: 'p-note', text: note }));
  authList.appendChild(row);
});

// ---- File drop / select ----
let computedDigest = null;
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault(); dropZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) loadFile(f);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) loadFile(fileInput.files[0]); });

async function loadFile(file) {
  document.getElementById('drop-label').textContent = file.name;
  const reader = new FileReader();
  reader.onload = async (e) => {
    computedDigest = await hashFileBuffer(e.target.result);
    showHashStatus();
  };
  reader.readAsArrayBuffer(file);
}

function showHashStatus() {
  const el = document.getElementById('hash-status');
  el.hidden = false;
  clear(el);
  if (!expectedDigest) {
    el.appendChild(elem('span', { class: 'badge badge-ok', text: 'SHA-256 computed' }));
    el.appendChild(document.createTextNode(' '));
    el.appendChild(elem('code', { text: 'sha256:' + computedDigest, attrs: { style: 'font-size:0.8rem' } }));
    document.getElementById('sign-section').hidden = false;
    return;
  }
  if (computedDigest === expectedDigest) {
    el.appendChild(elem('span', { class: 'badge badge-ok', text: 'Hash matches' }));
    el.appendChild(document.createTextNode(' The document is the one described in the envelope.'));
    document.getElementById('sign-section').hidden = false;
  } else {
    el.appendChild(elem('span', { class: 'badge badge-fail', text: 'Hash mismatch' }));
    el.appendChild(document.createTextNode(' This document does not match the envelope. Please check you have the right file.'));
    document.getElementById('sign-section').hidden = true;
  }
}

// ---- Sign ----
let signatureArtifact = null;
let jadesReceipt = null;

document.getElementById('sign-btn').addEventListener('click', async () => {
  if (!computedDigest) return;

  const role = document.getElementById('signer-role').value.trim() || 'Signer';
  const authorities = [...document.querySelectorAll('input[name="sign-auth"]:checked')].map((c) => c.value);

  const btn = document.getElementById('sign-btn');
  const progress = document.getElementById('sign-progress');
  btn.disabled = true;
  progress.hidden = false;
  progress.style.color = 'var(--muted)';

  const envelope = {
    envelope_id: envelopeId || ('local-' + Date.now()),
    doc_digest: 'sha256:' + computedDigest,
  };

  // Build signing message before biometric prompts
  const signingMessage = buildSigningMessage(envelope, role);
  const rpId = location.hostname;

  try {
    // Step 1: MakeCredential (creates a new key pair for this document)
    progress.textContent = 'Creating signing key... (browser prompt 1 of 2)';
    const freshChallenge = new Uint8Array(32);
    crypto.getRandomValues(freshChallenge);
    const credInfo = await createSigningCredential(rpId, role, freshChallenge);

    // Step 2: GetAssertion (signs the message with the key just created)
    progress.textContent = 'Signing the document... (browser prompt 2 of 2)';
    const assertion = await signMessage(credInfo.credentialId, signingMessage, rpId);

    progress.textContent = authorities.length > 0
      ? `Anchoring signed event with ${authorities.join(', ')}...`
      : 'Building receipt...';

    // Parse signing message to extract signed_at
    const msgObj = JSON.parse(signingMessage);

    // Anchor the signed event
    let signedAnchor = { event_hash: null, anchor_bindings: [], failures: [] };
    if (authorities.length > 0) {
      const signedEvent = {
        type: 'signed',
        envelope_id: envelope.envelope_id,
        doc_digest: envelope.doc_digest,
        role,
        signed_at: msgObj.signed_at,
        credential_id: credInfo.credentialId,
      };
      signedAnchor = await anchorEvent(signedEvent, authorities);
    }

    // Build JAdES B-T receipt
    const jades = await buildJadesBT({
      assertion,
      spkiPublicKey: credInfo.spkiPublicKey,
      signingMessage,
      docDigest: envelope.doc_digest,
      signedAt: msgObj.signed_at,
      anchorBindings: signedAnchor.anchor_bindings,
      evidenceStrength: assertion.evidenceStrength,
      BE: assertion.BE,
      BS: assertion.BS,
      counter: assertion.counter,
    });

    progress.hidden = true;

    // Bundle the full artifact
    signatureArtifact = {
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
      signed_event_anchor: signedAnchor,
      signing_message: signingMessage,
    };
    jadesReceipt = jades;

    // Display result — evidence chip
    const evChip = elem('span', {
      class: assertion.evidenceStrength === 'device_bound'
        ? 'evidence-chip device-bound' : 'evidence-chip synced',
      text: assertion.evidenceStrength === 'device_bound' ? 'device-bound' : 'synced passkey',
    });
    const evDisplay = document.getElementById('evidence-display');
    clear(evDisplay); evDisplay.appendChild(evChip);

    // Result info — all values via textContent (role is user-supplied)
    const rinfo = document.getElementById('result-info');
    clear(rinfo);
    const evText = `${assertion.evidenceStrength}${assertion.BE ? ' (BE)' : ''}${assertion.BS ? ' (BS)' : ''}  counter=${assertion.counter}${credInfo.aaguid ? `  AAGUID=${credInfo.aaguid}` : ''}`;
    const anchorText = `${signedAnchor.anchor_bindings.length} binding(s)${signedAnchor.failures.length > 0 ? `  (${signedAnchor.failures.length} failed)` : ''}`;
    rinfo.appendChild(elem('dt', { text: 'Signed by' }));
    rinfo.appendChild(elem('dd', { class: 'plain-text', text: role }));
    rinfo.appendChild(elem('dt', { text: 'Signed at' }));
    rinfo.appendChild(elem('dd', { text: msgObj.signed_at }));
    rinfo.appendChild(elem('dt', { text: 'Evidence strength' }));
    rinfo.appendChild(elem('dd', { class: 'plain-text', text: evText }));
    rinfo.appendChild(elem('dt', { text: 'Signed event anchor' }));
    rinfo.appendChild(elem('dd', { text: anchorText }));

    document.getElementById('result-section').hidden = false;
    document.getElementById('result-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  } catch (err) {
    btn.disabled = false;
    progress.style.color = 'var(--err)';
    progress.textContent = 'Error: ' + err.message;
  }
});

// ---- Downloads ----
document.getElementById('download-artifact-btn').addEventListener('click', () => {
  if (!signatureArtifact) return;
  download(
    JSON.stringify(signatureArtifact, null, 2),
    `anchorproof-sig-${signatureArtifact.envelope_id.slice(0, 8)}.json`,
  );
});

document.getElementById('download-jades-btn').addEventListener('click', () => {
  if (!jadesReceipt) return;
  download(
    JSON.stringify(jadesReceipt, null, 2),
    `anchorproof-jades-${signatureArtifact.envelope_id.slice(0, 8)}.json`,
  );
});

function download(text, name) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}
