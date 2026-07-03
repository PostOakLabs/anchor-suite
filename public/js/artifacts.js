// artifacts.js — Artifact Library page logic.
// Depends on: idb-keyval (globalThis.idbKeyval), @andypf/json-viewer (custom element).
// No inline HTML or innerHTML — DOM-only construction.

import { saveToLibrary, loadLibrary, updateRecord, deleteRecord, subscribeLibrary } from '/lib/library-bridge.mjs';
import { verifyOcgArtifact, verifyOts, verifyRfc3161Tst } from '/lib/verify-runner.mjs';
import { base64ToBytes } from '/js/tst.js';

// ---- sample artifact --------------------------------------------------------
// execution_hash = sha256 of JCS({"output_payload":{...},"policy_parameters":{...}})

const SAMPLE_ARTIFACT = {
  policy_parameters: { tool_id: 'sample-demo' },
  output_payload: { message: 'This is a sample artifact for the Artifact Library demo.' },
  execution_hash: 'sha256:3db3b389cb30bf68415c7464b2e843613796e224ba191513ab0c81d10d84d3cc',
};

// ---- state ------------------------------------------------------------------

let allRecords = [];
let filterText = '';
let selectedKey = null;
let detailVerifyResults = null;

// ---- DOM helpers ------------------------------------------------------------

function el(id) { return document.getElementById(id); }

function makeEl(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function clearEl(node) { node.textContent = ''; }

// ---- toast ------------------------------------------------------------------

function showToast(msg) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  const t = makeEl('div', 'toast', msg);
  document.body.appendChild(t);
  requestAnimationFrame(() => t.classList.add('toast-show'));
  setTimeout(() => { t.classList.remove('toast-show'); setTimeout(() => t.remove(), 300); }, 3000);
}

// ---- storage durability -----------------------------------------------------

async function requestPersist() {
  const bar = el('durability-bar');
  if (!bar) return;
  try {
    const granted = await navigator.storage.persist();
    bar.textContent = granted
      ? 'Storage: persistent. Browser will not evict your library.'
      : 'Storage: best-effort. On iOS Safari, your library may be evicted under storage pressure. Export your artifacts regularly.';
    bar.className = 'durability-bar ' + (granted ? 'dur-ok' : 'dur-warn');
  } catch {
    bar.hidden = true;
  }
}

// ---- library load / refresh -------------------------------------------------

async function refresh() {
  allRecords = await loadLibrary();
  allRecords.sort((a, b) => b.addedAt - a.addedAt);
  render();
}

function onLibraryUpdate() {
  refresh();
}

// ---- filter -----------------------------------------------------------------

function filtered() {
  if (!filterText) return allRecords;
  const q = filterText.toLowerCase();
  return allRecords.filter((r) => {
    if (r.key.toLowerCase().includes(q)) return true;
    if ((r.tags || []).some((t) => t.toLowerCase().includes(q))) return true;
    const eh = r.parsed?.execution_hash || '';
    if (eh.toLowerCase().includes(q)) return true;
    return false;
  });
}

// ---- render -----------------------------------------------------------------

function render() {
  const records = filtered();
  const pinned = records
    .filter((r) => r.pinned)
    .sort((a, b) => (a.pinnedIndex || 0) - (b.pinnedIndex || 0));
  const recent = records.filter((r) => !r.pinned);

  const emptyState = el('empty-state');
  if (emptyState) emptyState.hidden = allRecords.length > 0;

  const pinnedSection = el('pinned-section');
  if (pinnedSection) {
    pinnedSection.hidden = pinned.length === 0;
    const pl = el('pinned-list');
    if (pl) {
      clearEl(pl);
      pinned.forEach((r, idx) => pl.appendChild(makeListItem(r, pinned, idx)));
    }
  }

  const rl = el('recent-list');
  if (rl) {
    clearEl(rl);
    recent.forEach((r) => rl.appendChild(makeListItem(r, null, -1)));
  }

  if (selectedKey) {
    const record = allRecords.find((r) => r.key === selectedKey);
    if (record) renderDetailContent(record);
    else hideDetail();
  }
}

// ---- list item --------------------------------------------------------------

function makeListItem(record, pinnedGroup, idx) {
  const isSelected = record.key === selectedKey;
  const item = makeEl('div', 'lib-item' + (isSelected ? ' lib-item-selected' : ''));
  item.dataset.key = record.key;
  item.setAttribute('tabindex', '0');
  item.setAttribute('role', 'button');
  item.setAttribute('aria-expanded', String(isSelected));

  item.addEventListener('click', (e) => {
    if (e.target.closest('button')) return;
    toggleDetail(record.key);
  });
  item.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleDetail(record.key); }
  });

  // Left column: hash + meta
  const info = makeEl('div', 'lib-item-info');

  const title = makeEl('div', 'lib-item-title');
  const execHash = record.parsed?.execution_hash
    || record.parsed?.anchor_bindings?.[0]?.anchored_hash
    || record.key;
  title.textContent = execHash.length > 24
    ? execHash.slice(0, 14) + '…' + execHash.slice(-8)
    : execHash;
  info.appendChild(title);

  const meta = makeEl('div', 'lib-item-meta');
  meta.appendChild(document.createTextNode(new Date(record.addedAt).toLocaleString()));
  (record.tags || []).slice(0, 5).forEach((tag) => {
    const chip = makeEl('span', 'tag-chip', tag);
    meta.appendChild(chip);
  });
  info.appendChild(meta);
  item.appendChild(info);

  // Right column: action buttons
  const actions = makeEl('div', 'lib-item-actions');

  const pinBtn = makeEl('button', 'btn-icon-sm', record.pinned ? 'Unpin' : 'Pin');
  pinBtn.title = record.pinned ? 'Remove from pinned' : 'Pin to top';
  pinBtn.type = 'button';
  pinBtn.addEventListener('click', async (e) => {
    e.stopPropagation();
    await doPin(record.key, !record.pinned);
  });
  actions.appendChild(pinBtn);

  if (record.pinned && pinnedGroup && pinnedGroup.length > 1) {
    if (idx > 0) {
      const upBtn = makeEl('button', 'btn-icon-sm', 'Up');
      upBtn.title = 'Move up in pinned list';
      upBtn.type = 'button';
      upBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await doMove(record.key, pinnedGroup, idx, -1);
      });
      actions.appendChild(upBtn);
    }
    if (idx < pinnedGroup.length - 1) {
      const downBtn = makeEl('button', 'btn-icon-sm', 'Down');
      downBtn.title = 'Move down in pinned list';
      downBtn.type = 'button';
      downBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await doMove(record.key, pinnedGroup, idx, 1);
      });
      actions.appendChild(downBtn);
    }
  }

  item.appendChild(actions);
  return item;
}

// ---- detail panel -----------------------------------------------------------

function toggleDetail(key) {
  if (selectedKey === key) {
    hideDetail();
  } else {
    selectedKey = key;
    detailVerifyResults = null;
    const record = allRecords.find((r) => r.key === key);
    if (record) {
      const dp = el('detail-panel');
      if (dp) dp.hidden = false;
      renderDetailContent(record);
    }
    render();
  }
}

function hideDetail() {
  selectedKey = null;
  detailVerifyResults = null;
  const dp = el('detail-panel');
  if (dp) dp.hidden = true;
  render();
}

function renderDetailContent(record) {
  const dp = el('detail-panel');
  if (!dp) return;
  clearEl(dp);

  // Header
  const header = makeEl('div', 'detail-header');
  const titleEl = makeEl('h2', 'detail-title');
  const keyDisplay = record.parsed?.execution_hash
    || record.parsed?.anchor_bindings?.[0]?.anchored_hash
    || record.key;
  titleEl.textContent = keyDisplay;
  header.appendChild(titleEl);

  const closeBtn = makeEl('button', 'btn-icon', 'Close');
  closeBtn.type = 'button';
  closeBtn.addEventListener('click', hideDetail);
  header.appendChild(closeBtn);
  dp.appendChild(header);

  // Action buttons
  const actRow = makeEl('div', 'detail-actions');

  const exportBtn = makeEl('button', 'btn btn-sm btn-ghost', 'Export');
  exportBtn.title = 'Download raw artifact file (byte-identical to original)';
  exportBtn.type = 'button';
  exportBtn.addEventListener('click', () => doExport(record));
  actRow.appendChild(exportBtn);

  const copyBtn = makeEl('button', 'btn btn-sm btn-ghost', 'Copy hash');
  copyBtn.type = 'button';
  copyBtn.addEventListener('click', () => doCopyHash(record));
  actRow.appendChild(copyBtn);

  const execHash = record.parsed?.execution_hash;
  if (execHash) {
    const anchorBtn = makeEl('button', 'btn btn-sm btn-ghost', 'Anchor this');
    anchorBtn.title = 'Open Anchor page with this hash pre-filled';
    anchorBtn.type = 'button';
    anchorBtn.addEventListener('click', () => {
      location.href = '/anchor.html#eh=' + encodeURIComponent(execHash);
    });
    actRow.appendChild(anchorBtn);
  }

  // Best-effort: open origin tool deep-link (ainumbers.co tools only)
  const toolId = record.parsed?.policy_parameters?.tool_id;
  if (toolId && typeof toolId === 'string' && /^[a-z0-9_-]+$/i.test(toolId)) {
    const toolBtn = makeEl('button', 'btn btn-sm btn-ghost', 'Open tool');
    toolBtn.title = 'Try to open the origin tool at ainumbers.co (best effort)';
    toolBtn.type = 'button';
    toolBtn.addEventListener('click', () => {
      window.open('https://ainumbers.co/tools/' + toolId + '.html', '_blank', 'noopener,noreferrer');
    });
    actRow.appendChild(toolBtn);
  }

  const deleteBtn = makeEl('button', 'btn btn-sm btn-ghost btn-danger', 'Delete');
  deleteBtn.type = 'button';
  deleteBtn.title = 'Remove from library';
  deleteBtn.addEventListener('click', async () => {
    if (!confirm('Remove this artifact from your library?')) return;
    const key = record.key;
    hideDetail();
    await deleteRecord(key);
    await refresh();
  });
  actRow.appendChild(deleteBtn);

  dp.appendChild(actRow);

  // Badge row section
  const badgeSection = makeEl('div', 'badge-section');
  const badgeLabel = makeEl('div', 'badge-section-label', 'Verification');
  badgeSection.appendChild(badgeLabel);

  const badgeRowEl = makeEl('div', 'badge-row');
  badgeRowEl.id = 'badge-row-inner';
  renderBadgeRow(badgeRowEl, record, detailVerifyResults);
  badgeSection.appendChild(badgeRowEl);

  const reVerifyBtn = makeEl('button', 'btn btn-sm btn-ghost', 'Re-verify');
  reVerifyBtn.type = 'button';
  reVerifyBtn.addEventListener('click', async () => {
    reVerifyBtn.disabled = true;
    reVerifyBtn.textContent = 'Verifying...';
    await doReVerify(record, badgeRowEl);
    reVerifyBtn.disabled = false;
    reVerifyBtn.textContent = 'Re-verify';
  });
  badgeSection.appendChild(reVerifyBtn);
  dp.appendChild(badgeSection);

  // Meta line
  dp.appendChild(makeEl('div', 'detail-meta', 'Added: ' + new Date(record.addedAt).toLocaleString()));

  // JSON viewer
  const jvSection = makeEl('div', 'detail-json');
  const jvLabel = makeEl('div', 'badge-section-label', 'Artifact JSON');
  jvSection.appendChild(jvLabel);
  const jv = document.createElement('andypf-json-viewer');
  jv.setAttribute('data', JSON.stringify(record.parsed));
  jv.setAttribute('expanded', '2');
  jvSection.appendChild(jv);
  dp.appendChild(jvSection);
}

// ---- badge row rendering ----------------------------------------------------

function renderBadgeRow(container, record, results) {
  clearEl(container);
  const isOcg = Boolean(record.parsed?.execution_hash);

  if (!results) {
    if (isOcg) {
      appendBadge(container, '§4 Hash', 'skip');
      appendBadge(container, '§16 Sig', 'skip');
      appendBadge(container, '§18 Proof', 'skip');
    }
    if (Array.isArray(record.parsed?.anchor_bindings)) {
      for (const b of record.parsed.anchor_bindings) {
        appendBadge(container, anchorLabel(b), 'skip');
      }
    }
    if (!isOcg && !Array.isArray(record.parsed?.anchor_bindings)) {
      appendBadge(container, 'not verified', 'skip');
    }
    return;
  }

  if (isOcg) {
    appendBadge(container, '§4 Hash', results.hash?.status || 'skip');
    appendBadge(container, '§16 Sig', results.sig?.status || 'skip');
    appendBadge(container, '§18 Proof', results.proof?.status || 'skip');
  }
  for (const a of (results.anchors || [])) {
    const label = a.type === 'opentimestamps' ? 'OTS' : shortOrigin(a.tsa || a.logOrigin || '');
    const status = a.ok ? 'ok' : (a.status === 'pending' ? 'pending' : 'fail');
    appendBadge(container, label, status);
  }
}

function appendBadge(container, label, status) {
  const cls = 'badge badge-' + (status === 'ok' ? 'ok' : status === 'pending' ? 'pending' : status === 'skip' ? 'skip' : 'fail');
  const b = makeEl('span', cls, label + ': ' + status);
  container.appendChild(b);
}

function anchorLabel(b) {
  if (b.type === 'opentimestamps') return 'OTS';
  return shortOrigin(b.log_origin || '');
}

function shortOrigin(origin) {
  const host = origin.replace(/^https?:\/\//, '').split('/')[0];
  const parts = host.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : host;
}

// ---- re-verify --------------------------------------------------------------

async function doReVerify(record, badgeRowEl) {
  const isOcg = Boolean(record.parsed?.execution_hash);
  let results;
  try {
    if (isOcg) {
      results = await verifyOcgArtifact(record.parsed);
    } else {
      results = { hash: null, sig: null, proof: null, anchors: [] };
      for (const b of (record.parsed?.anchor_bindings || [])) {
        if (b.type === 'rfc3161-tst') {
          const der = base64ToBytes(b.proof);
          const r = await verifyRfc3161Tst(der, b.anchored_hash, b.log_origin);
          results.anchors.push({ type: 'rfc3161-tst', logOrigin: b.log_origin, ...r });
        } else if (b.type === 'opentimestamps') {
          const ots = base64ToBytes(b.proof);
          const r = await verifyOts(ots, b.anchored_hash);
          results.anchors.push({ type: 'opentimestamps', logOrigin: 'bitcoin', ...r });
        }
      }
    }
    detailVerifyResults = results;
    if (badgeRowEl) renderBadgeRow(badgeRowEl, record, results);
  } catch (e) {
    showToast('Verification error: ' + e.message);
  }
}

// ---- pin / move -------------------------------------------------------------

async function doPin(key, pinned) {
  const maxIdx = allRecords
    .filter((r) => r.pinned)
    .reduce((m, r) => Math.max(m, r.pinnedIndex || 0), 0);
  await updateRecord(key, { pinned, pinnedIndex: pinned ? maxIdx + 1 : 0 });
  await refresh();
}

async function doMove(key, pinnedGroup, idx, dir) {
  const targetIdx = idx + dir;
  if (targetIdx < 0 || targetIdx >= pinnedGroup.length) return;
  const a = pinnedGroup[idx];
  const b = pinnedGroup[targetIdx];
  await updateRecord(a.key, { pinnedIndex: b.pinnedIndex || 0 });
  await updateRecord(b.key, { pinnedIndex: a.pinnedIndex || 0 });
  await refresh();
}

// ---- export -----------------------------------------------------------------

function doExport(record) {
  const blob = new Blob([record.rawText], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const prefix = record.key.startsWith('ocg:') ? 'artifact-' : 'anchors-';
  const suffix = record.key.slice(record.key.indexOf(':') + 1, record.key.indexOf(':') + 9);
  a.download = prefix + suffix + '.json';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---- copy hash --------------------------------------------------------------

function doCopyHash(record) {
  const hash = record.parsed?.execution_hash
    || record.parsed?.anchor_bindings?.[0]?.anchored_hash
    || record.key;
  navigator.clipboard?.writeText(hash).catch(() => {});
  showToast('Copied to clipboard');
}

// ---- import -----------------------------------------------------------------

async function doImportFile(file) {
  const text = await file.text();
  await doImportText(text);
}

async function doImportText(text) {
  let parsed;
  try { parsed = JSON.parse(text); } catch {
    showToast('Not valid JSON');
    return;
  }

  const isOcg = typeof parsed?.execution_hash === 'string'
    && parsed?.policy_parameters !== undefined
    && parsed?.output_payload !== undefined;
  const isAnchors = Array.isArray(parsed?.anchor_bindings);

  if (!isOcg && !isAnchors) {
    showToast('Not an OCG artifact or anchors.json');
    return;
  }

  const key = await saveToLibrary(text, parsed);
  if (!key) {
    showToast('Could not save — storage may be unavailable');
    return;
  }
  showToast('Saved to Artifact Library');
  await refresh();
  selectedKey = key;
  detailVerifyResults = null;
  const record = allRecords.find((r) => r.key === key);
  if (record) {
    const dp = el('detail-panel');
    if (dp) dp.hidden = false;
    renderDetailContent(record);
  }
  render();
}

async function doTrySample() {
  const text = JSON.stringify(SAMPLE_ARTIFACT, null, 2);
  await doImportText(text);
}

// ---- init -------------------------------------------------------------------

function setupDropZone() {
  const dz = el('artifacts-drop');
  if (!dz) return;
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', async (e) => {
    e.preventDefault();
    dz.classList.remove('drag-over');
    const files = Array.from(e.dataTransfer?.files || []);
    for (const f of files) if (f.name.endsWith('.json')) await doImportFile(f);
  });
  dz.addEventListener('click', () => el('import-file-input')?.click());
  dz.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); el('import-file-input')?.click(); }
  });
}

function setupButtons() {
  const importBtn = el('import-file-btn');
  if (importBtn) importBtn.addEventListener('click', () => el('import-file-input')?.click());

  const fi = el('import-file-input');
  if (fi) {
    fi.addEventListener('change', async () => {
      const files = Array.from(fi.files || []);
      for (const f of files) await doImportFile(f);
      fi.value = '';
    });
  }

  const pasteBtn = el('paste-json-btn');
  if (pasteBtn) {
    pasteBtn.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) await doImportText(text);
        else showToast('Clipboard is empty');
      } catch {
        showToast('Clipboard access denied. Use the drop zone or file picker.');
      }
    });
  }

  const sampleBtn = el('try-sample-btn');
  if (sampleBtn) sampleBtn.addEventListener('click', doTrySample);
}

function setupFilter() {
  const fi = el('filter-input');
  if (fi) {
    fi.addEventListener('input', () => {
      filterText = fi.value.trim();
      render();
    });
  }
}

async function init() {
  await requestPersist();
  await refresh();
  setupDropZone();
  setupButtons();
  setupFilter();
  subscribeLibrary(onLibraryUpdate);
}

document.addEventListener('DOMContentLoaded', init);
