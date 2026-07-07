// sign-request.js — Anchorproof create-envelope page logic.
// External module (CSP script-src 'self'); Trusted-Types-safe (no innerHTML — DOM built
// via createElement + textContent). Previously inline; the estate CSP blocked the inline
// module, leaving the page dead. Logic unchanged from the inline version.
import {
  hashFileBuffer, createEnvelope, anchorEvent,
  bytesToBase64,
} from '/lib/anchorproof.mjs';

// ---- Small DOM helper (Trusted-Types-safe: text only) ----
function elem(tag, opts = {}, ...children) {
  const e = document.createElement(tag);
  if (opts.class) e.className = opts.class;
  if (opts.text != null) e.textContent = opts.text;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) e.setAttribute(k, v);
  for (const c of children) if (c) e.appendChild(c);
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

const AUTHORITIES = [
  { id: 'sigstore', name: 'Sigstore TSA', note: 'OpenSSF, ECDSA-P384' },
  { id: 'digicert', name: 'DigiCert', note: 'Commercial CA, RSA' },
  { id: 'freetsa',  name: 'FreeTSA', note: 'Community, RSA' },
  { id: 'github',   name: 'GitHub TSA', note: 'HSM-backed, ECDSA-P384' },
];

// ---- Authority checkboxes ----
const authList = document.getElementById('authority-list');
AUTHORITIES.forEach(({ id, name, note }, i) => {
  const row = elem('label', { class: 'provider-row' });
  const cb = elem('input', { attrs: { type: 'checkbox', name: 'auth', value: id } });
  if (i < 2) cb.checked = true;
  row.appendChild(cb);
  row.appendChild(elem('span', { class: 'p-name', text: name }));
  row.appendChild(elem('span', { class: 'p-note', text: note }));
  authList.appendChild(row);
});

// ---- File drop/select ----
let docDigest = null;
let fileName = '';
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

function setFile(file) {
  fileName = file.name;
  document.getElementById('drop-label').textContent = file.name;
  const reader = new FileReader();
  reader.onload = async (e) => {
    docDigest = await hashFileBuffer(e.target.result);
    document.getElementById('hash-value').textContent = 'sha256:' + docDigest;
    document.getElementById('hash-display').hidden = false;
    document.getElementById('envelope-section').hidden = false;
    updateCreateBtn();
  };
  reader.readAsArrayBuffer(file);
}

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault(); dropZone.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) setFile(f);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });

document.getElementById('copy-hash-btn').addEventListener('click', () => {
  navigator.clipboard.writeText('sha256:' + docDigest).catch(() => {});
});

// ---- Create button state ----
function updateCreateBtn() {
  const checked = document.querySelectorAll('input[name="auth"]:checked').length;
  document.getElementById('create-btn').disabled = !docDigest || checked < 1;
}
authList.addEventListener('change', updateCreateBtn);

// ---- Create envelope ----
let envelopeBundle = null;

document.getElementById('create-btn').addEventListener('click', async () => {
  const signerName = document.getElementById('signer-name').value.trim();
  const message = document.getElementById('message-text').value.trim() || 'Please sign the attached document.';
  const authorities = [...document.querySelectorAll('input[name="auth"]:checked')].map((c) => c.value);

  const btn = document.getElementById('create-btn');
  const progress = document.getElementById('anchor-progress');
  btn.disabled = true;
  progress.hidden = false;
  progress.textContent = 'Creating envelope...';

  try {
    const envelope = createEnvelope({
      docDigest,
      parties: signerName ? [{ role: 'signer', name: signerName }] : [],
      message,
    });

    progress.textContent = `Anchoring request with ${authorities.join(', ')}...`;

    const requestEvent = {
      type: 'request_created',
      envelope_id: envelope.envelope_id,
      doc_digest: envelope.doc_digest,
      created_at: envelope.created_at,
    };

    const anchorResult = await anchorEvent(requestEvent, authorities);

    progress.hidden = true;

    envelopeBundle = {
      envelope,
      request_anchor: anchorResult,
      file_name: fileName,
    };

    // Build deep-link (fragment never sent to server)
    const deepLink = `${location.origin}/sign/sign.html#h=${docDigest}&e=${envelope.envelope_id}`;

    // Render result — all values via textContent (message is user input)
    const info = document.getElementById('envelope-info');
    clear(info);
    info.appendChild(elem('dt', { text: 'Envelope ID' }));
    info.appendChild(elem('dd', { text: envelope.envelope_id }));
    info.appendChild(elem('dt', { text: 'Document hash' }));
    info.appendChild(elem('dd', { text: envelope.doc_digest }));
    info.appendChild(elem('dt', { text: 'Message' }));
    info.appendChild(elem('dd', { class: 'plain-text', text: message }));
    info.appendChild(elem('dt', { text: 'Created' }));
    info.appendChild(elem('dd', { text: envelope.created_at }));
    info.appendChild(elem('dt', { text: 'Anchored' }));
    info.appendChild(elem('dd', { text: `${anchorResult.anchor_bindings.length} binding(s) from ${authorities.join(', ')}` }));

    document.getElementById('result-auth-count').textContent =
      `${anchorResult.anchor_bindings.length} binding${anchorResult.anchor_bindings.length !== 1 ? 's' : ''}`;

    document.getElementById('deeplink-url').textContent = deepLink;

    document.getElementById('result-section').hidden = false;
    document.getElementById('result-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  } catch (err) {
    progress.hidden = true;
    btn.disabled = false;
    progress.hidden = false;
    progress.textContent = 'Error: ' + err.message;
    progress.style.color = 'var(--err)';
  }
});

document.getElementById('copy-link-btn').addEventListener('click', () => {
  const link = document.getElementById('deeplink-url').textContent;
  navigator.clipboard.writeText(link).catch(() => {});
});

document.getElementById('download-envelope-btn').addEventListener('click', () => {
  if (!envelopeBundle) return;
  const json = JSON.stringify(envelopeBundle, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `anchorproof-envelope-${envelopeBundle.envelope.envelope_id.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
});
