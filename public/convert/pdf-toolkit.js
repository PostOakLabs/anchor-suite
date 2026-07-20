// CL-03: PDF toolkit (merge / split / extract pages / strip metadata), local-only. pdf-lib
// (vendored, /vendor/pdf-lib.min.js, same-origin, no CDN) does the byte-level PDF work; this
// module hashes both ends of each operation and builds deep-links into the receipt builder
// (art-191). Strip-metadata mode additionally records field/category/action findings and
// deep-links the metadata-sanitization prover (art-193) with those findings prefilled.

if (window.trustedTypes && trustedTypes.createPolicy) {
  trustedTypes.createPolicy('default', { createHTML: (s) => s });
}

const ENGINE_NAME = 'pdf-lib';
const ENGINE_VERSION = '1.17.1';
// SHA-256 of /vendor/pdf-lib.min.js as vendored — baked at build time, matches VENDORED.md.
// Re-derive with sha256sum if the vendored file is ever re-pinned.
const ENGINE_SHA256 = '0f9a5cad07941f0826586c94e089d89b918c46e5c17cf2d5a3c6f666e3bc694f';
const ENGINE_URL = 'https://github.com/Hopding/pdf-lib';

const { PDFDocument } = window.PDFLib;

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function concatBytes(arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of arrays) { out.set(a, o); o += a.length; }
  return out;
}

/* ---------- tabs ---------- */
const TABS = ['merge', 'split', 'extract', 'strip'];
function selectTab(name) {
  TABS.forEach((t) => {
    document.getElementById(`tab-${t}`).classList.toggle('active', t === name);
    document.getElementById(`tab-${t}`).setAttribute('aria-selected', String(t === name));
    document.getElementById(`panel-${t}`).hidden = t !== name;
  });
}
TABS.forEach((t) => document.getElementById(`tab-${t}`).addEventListener('click', () => selectTab(t)));

/* ---------- shared output rendering ---------- */
const outputArea = document.getElementById('output-area');
const outputHeading = document.getElementById('output-heading');
const outputList = document.getElementById('output-list');

function clearOutput(heading) {
  outputHeading.textContent = heading;
  outputList.innerHTML = '';
  outputArea.hidden = false;
}

// Renders one result card: digests, a download button, and receipt deep-link(s).
// receiptFields: fields for the art-191 conversion-receipt-builder deep-link.
// sanitizationFields: optional fields for the art-193 metadata-sanitization-prover deep-link.
function addOutputCard({ label, bytes, mime, downloadName, inputHash, outputHash, receiptFields, sanitizationFields }) {
  const card = document.createElement('div');
  card.className = 'result-card';

  const header = document.createElement('div');
  header.className = 'result-header';
  const name = document.createElement('span');
  name.className = 'result-name';
  name.textContent = label;
  header.appendChild(name);
  card.appendChild(header);

  const row = document.createElement('div');
  row.className = 'output-row';
  const dlBtn = document.createElement('button');
  dlBtn.type = 'button';
  dlBtn.className = 'btn';
  dlBtn.textContent = `Download ${downloadName}`;
  dlBtn.addEventListener('click', () => {
    const blob = new Blob([bytes], { type: mime });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = downloadName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
  });
  row.appendChild(dlBtn);
  card.appendChild(row);

  const inLine = document.createElement('div');
  inLine.className = 'result-line';
  inLine.textContent = `input_sha256: ${inputHash}`;
  card.appendChild(inLine);
  const outLine = document.createElement('div');
  outLine.className = 'result-line';
  outLine.textContent = `output_sha256: ${outputHash}`;
  card.appendChild(outLine);
  const engineLine = document.createElement('div');
  engineLine.className = 'result-line';
  engineLine.textContent = `engine: ${ENGINE_NAME} ${ENGINE_VERSION}`;
  card.appendChild(engineLine);

  const ctaRow = document.createElement('div');
  ctaRow.className = 'receipt-cta-row';
  const receiptLink = document.createElement('a');
  receiptLink.className = 'cta-btn';
  receiptLink.textContent = 'Build a receipt';
  const payload = b64urlEncode(JSON.stringify(receiptFields));
  receiptLink.href = `https://ainumbers.co/chaingraph/art-191-conversion-receipt-builder.html#in=${payload}`;
  ctaRow.appendChild(receiptLink);

  if (sanitizationFields) {
    const sanLink = document.createElement('a');
    sanLink.className = 'cta-btn';
    sanLink.textContent = 'Prove sanitization';
    const sanPayload = b64urlEncode(JSON.stringify(sanitizationFields));
    sanLink.href = `https://ainumbers.co/chaingraph/art-193-metadata-sanitization-prover.html#in=${sanPayload}`;
    ctaRow.appendChild(sanLink);
  }
  card.appendChild(ctaRow);

  outputList.appendChild(card);
}

function showErr(id, msg) {
  const el = document.getElementById(id);
  el.hidden = false;
  el.textContent = msg;
}
function clearErr(id) {
  document.getElementById(id).hidden = true;
}

function wireDropZone(dropId, inputId, onFiles) {
  const drop = document.getElementById(dropId);
  const input = document.getElementById(inputId);
  drop.addEventListener('click', () => input.click());
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') input.click(); });
  input.addEventListener('change', () => { if (input.files.length) onFiles([...input.files]); input.value = ''; });
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('drag-over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag-over'));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    drop.classList.remove('drag-over');
    if (e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]);
  });
}

/* ======================================================================
   MERGE
   ====================================================================== */
let mergeFiles = [];

function renderMergeFileList() {
  const list = document.getElementById('merge-file-list');
  list.innerHTML = '';
  mergeFiles.forEach((f, i) => {
    const li = document.createElement('li');
    li.className = 'file-list-item';
    const nm = document.createElement('span');
    nm.className = 'file-list-name';
    nm.textContent = f.name;
    const order = document.createElement('span');
    order.className = 'file-list-order';
    order.textContent = `#${i + 1}`;
    li.appendChild(nm);
    li.appendChild(order);
    list.appendChild(li);
  });
  document.getElementById('merge-action-row').hidden = mergeFiles.length < 2;
}

wireDropZone('merge-drop', 'merge-file-input', (files) => {
  clearErr('merge-err');
  mergeFiles = mergeFiles.concat(files.filter((f) => f.name.toLowerCase().endsWith('.pdf')));
  renderMergeFileList();
});

document.getElementById('merge-clear-btn').addEventListener('click', () => {
  mergeFiles = [];
  renderMergeFileList();
});

document.getElementById('merge-run-btn').addEventListener('click', async () => {
  clearErr('merge-err');
  try {
    const buffers = [];
    for (const f of mergeFiles) buffers.push(new Uint8Array(await f.arrayBuffer()));

    const merged = await PDFDocument.create();
    for (const bytes of buffers) {
      const src = await PDFDocument.load(bytes);
      const pages = await merged.copyPages(src, src.getPageIndices());
      pages.forEach((p) => merged.addPage(p));
    }
    const outBytes = await merged.save();

    // input_sha256 binds the ordered concatenation of the raw input files, documented as such.
    const inputHash = await sha256Hex(concatBytes(buffers));
    const outputHash = await sha256Hex(outBytes);

    clearOutput('Merged PDF');
    addOutputCard({
      label: `${mergeFiles.length} files merged, in the order added`,
      bytes: outBytes,
      mime: 'application/pdf',
      downloadName: 'merged.pdf',
      inputHash,
      outputHash,
      receiptFields: {
        input_sha256: inputHash,
        output_sha256: outputHash,
        source_format: 'pdf',
        target_format: 'pdf',
        converter_name: ENGINE_NAME,
        converter_version: ENGINE_VERSION,
        converter_engine_sha256: ENGINE_SHA256,
        converter_url: ENGINE_URL,
        input_filename: mergeFiles.map((f) => f.name).join(' + '),
        output_filename: 'merged.pdf',
        parameters: JSON.stringify({ operation: 'merge', input_count: mergeFiles.length }),
      },
    });
  } catch (e) {
    showErr('merge-err', 'Merge failed: ' + e.message);
  }
});

/* ======================================================================
   SPLIT
   ====================================================================== */
let splitFile = null;
let splitDoc = null;
let splitBytes = null;

wireDropZone('split-drop', 'split-file-input', async ([file]) => {
  clearErr('split-err');
  document.getElementById('split-drop-label').textContent = file.name;
  splitBytes = new Uint8Array(await file.arrayBuffer());
  try {
    splitDoc = await PDFDocument.load(splitBytes);
    splitFile = file;
    const count = splitDoc.getPageCount();
    document.getElementById('split-max').textContent = String(count - 1);
    const pageInput = document.getElementById('split-page');
    pageInput.max = String(count - 1);
    pageInput.value = String(Math.max(1, Math.floor(count / 2)));
    document.getElementById('split-field-row').hidden = false;
    document.getElementById('split-action-row').hidden = false;
  } catch (e) {
    showErr('split-err', 'Could not read this PDF: ' + e.message);
  }
});

document.getElementById('split-run-btn').addEventListener('click', async () => {
  clearErr('split-err');
  try {
    const total = splitDoc.getPageCount();
    const n = parseInt(document.getElementById('split-page').value, 10);
    if (!Number.isInteger(n) || n < 1 || n >= total) {
      showErr('split-err', `Split point must be between 1 and ${total - 1}.`);
      return;
    }
    const inputHash = await sha256Hex(splitBytes);

    const partA = await PDFDocument.create();
    const idxA = Array.from({ length: n }, (_, i) => i);
    (await partA.copyPages(splitDoc, idxA)).forEach((p) => partA.addPage(p));
    const bytesA = await partA.save();
    const hashA = await sha256Hex(bytesA);

    const partB = await PDFDocument.create();
    const idxB = Array.from({ length: total - n }, (_, i) => i + n);
    (await partB.copyPages(splitDoc, idxB)).forEach((p) => partB.addPage(p));
    const bytesB = await partB.save();
    const hashB = await sha256Hex(bytesB);

    const base = splitFile.name.replace(/\.pdf$/i, '');
    clearOutput('Split PDF');
    addOutputCard({
      label: `Part A: pages 1-${n}`,
      bytes: bytesA, mime: 'application/pdf', downloadName: `${base}.part-a.pdf`,
      inputHash, outputHash: hashA,
      receiptFields: {
        input_sha256: inputHash, output_sha256: hashA, source_format: 'pdf', target_format: 'pdf',
        converter_name: ENGINE_NAME, converter_version: ENGINE_VERSION,
        converter_engine_sha256: ENGINE_SHA256, converter_url: ENGINE_URL,
        input_filename: splitFile.name, output_filename: `${base}.part-a.pdf`,
        parameters: JSON.stringify({ operation: 'split', split_after_page: n, part: 'a', pages: `1-${n}` }),
      },
    });
    addOutputCard({
      label: `Part B: pages ${n + 1}-${total}`,
      bytes: bytesB, mime: 'application/pdf', downloadName: `${base}.part-b.pdf`,
      inputHash, outputHash: hashB,
      receiptFields: {
        input_sha256: inputHash, output_sha256: hashB, source_format: 'pdf', target_format: 'pdf',
        converter_name: ENGINE_NAME, converter_version: ENGINE_VERSION,
        converter_engine_sha256: ENGINE_SHA256, converter_url: ENGINE_URL,
        input_filename: splitFile.name, output_filename: `${base}.part-b.pdf`,
        parameters: JSON.stringify({ operation: 'split', split_after_page: n, part: 'b', pages: `${n + 1}-${total}` }),
      },
    });
  } catch (e) {
    showErr('split-err', 'Split failed: ' + e.message);
  }
});

/* ======================================================================
   EXTRACT PAGES
   ====================================================================== */
let extractFile = null;
let extractDoc = null;
let extractBytes = null;

function parsePageRange(spec, max) {
  const idxs = [];
  for (const part of spec.split(',').map((s) => s.trim()).filter(Boolean)) {
    const m = part.match(/^(\d+)(?:-(\d+))?$/);
    if (!m) throw new Error(`"${part}" is not a page number or range.`);
    const a = parseInt(m[1], 10);
    const b = m[2] ? parseInt(m[2], 10) : a;
    if (a < 1 || b < 1 || a > max || b > max) throw new Error(`"${part}" is out of range (1-${max}).`);
    if (a <= b) for (let i = a; i <= b; i++) idxs.push(i - 1);
    else for (let i = a; i >= b; i--) idxs.push(i - 1);
  }
  if (!idxs.length) throw new Error('Enter at least one page number or range.');
  return idxs;
}

wireDropZone('extract-drop', 'extract-file-input', async ([file]) => {
  clearErr('extract-err');
  document.getElementById('extract-drop-label').textContent = file.name;
  extractBytes = new Uint8Array(await file.arrayBuffer());
  try {
    extractDoc = await PDFDocument.load(extractBytes);
    extractFile = file;
    document.getElementById('extract-max').textContent = String(extractDoc.getPageCount());
    document.getElementById('extract-field-row').hidden = false;
    document.getElementById('extract-action-row').hidden = false;
  } catch (e) {
    showErr('extract-err', 'Could not read this PDF: ' + e.message);
  }
});

document.getElementById('extract-run-btn').addEventListener('click', async () => {
  clearErr('extract-err');
  try {
    const max = extractDoc.getPageCount();
    const spec = document.getElementById('extract-range').value.trim();
    const idxs = parsePageRange(spec, max);

    const inputHash = await sha256Hex(extractBytes);
    const out = await PDFDocument.create();
    (await out.copyPages(extractDoc, idxs)).forEach((p) => out.addPage(p));
    const outBytes = await out.save();
    const outputHash = await sha256Hex(outBytes);

    const base = extractFile.name.replace(/\.pdf$/i, '');
    clearOutput('Extracted pages');
    addOutputCard({
      label: `${idxs.length} page(s) extracted: ${spec}`,
      bytes: outBytes, mime: 'application/pdf', downloadName: `${base}.extract.pdf`,
      inputHash, outputHash,
      receiptFields: {
        input_sha256: inputHash, output_sha256: outputHash, source_format: 'pdf', target_format: 'pdf',
        converter_name: ENGINE_NAME, converter_version: ENGINE_VERSION,
        converter_engine_sha256: ENGINE_SHA256, converter_url: ENGINE_URL,
        input_filename: extractFile.name, output_filename: `${base}.extract.pdf`,
        parameters: JSON.stringify({ operation: 'extract', pages: spec }),
      },
    });
  } catch (e) {
    showErr('extract-err', 'Extract failed: ' + e.message);
  }
});

/* ======================================================================
   STRIP METADATA
   ====================================================================== */
const INFO_CATEGORY = {
  Title: 'other', Subject: 'other', Keywords: 'other',
  Author: 'author',
  Creator: 'software', Producer: 'software',
  CreationDate: 'timestamp', ModDate: 'timestamp',
};

wireDropZone('strip-drop', 'strip-file-input', async ([file]) => {
  clearErr('strip-err');
  document.getElementById('strip-drop-label').textContent = file.name;
  document.getElementById('strip-none').hidden = true;
  document.getElementById('strip-findings-wrap').hidden = true;
  outputArea.hidden = true;

  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const doc = await PDFDocument.load(bytes);

    const findings = [];
    const infoRef = doc.context.trailerInfo.Info;
    if (infoRef) {
      const infoDict = doc.context.lookup(infoRef);
      if (infoDict && typeof infoDict.keys === 'function') {
        for (const key of infoDict.keys()) {
          const name = key.asString ? key.asString().replace(/^\//, '') : String(key);
          findings.push({ field: name, category: INFO_CATEGORY[name] || 'other', action: 'removed' });
          infoDict.delete(key);
        }
      }
      doc.context.trailerInfo.Info = undefined;
    }
    const metaRef = doc.catalog.get(window.PDFLib.PDFName.of('Metadata'));
    if (metaRef) {
      findings.push({ field: 'Metadata (XMP)', category: 'other', action: 'removed' });
      doc.catalog.delete(window.PDFLib.PDFName.of('Metadata'));
    }

    if (!findings.length) {
      document.getElementById('strip-none').hidden = false;
      return;
    }

    const outBytes = await doc.save();
    const originalHash = await sha256Hex(bytes);
    const sanitizedHash = await sha256Hex(outBytes);

    const tbody = document.getElementById('strip-findings-body');
    tbody.innerHTML = '';
    findings.forEach((f) => {
      const tr = document.createElement('tr');
      [f.field, f.category, f.action].forEach((v) => {
        const td = document.createElement('td');
        td.textContent = v;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    document.getElementById('strip-findings-wrap').hidden = false;

    const base = file.name.replace(/\.pdf$/i, '');
    clearOutput('Metadata stripped');
    addOutputCard({
      label: `${findings.length} metadata field(s) removed`,
      bytes: outBytes, mime: 'application/pdf', downloadName: `${base}.stripped.pdf`,
      inputHash: originalHash, outputHash: sanitizedHash,
      receiptFields: {
        input_sha256: originalHash, output_sha256: sanitizedHash, source_format: 'pdf', target_format: 'pdf',
        converter_name: ENGINE_NAME, converter_version: ENGINE_VERSION,
        converter_engine_sha256: ENGINE_SHA256, converter_url: ENGINE_URL,
        input_filename: file.name, output_filename: `${base}.stripped.pdf`,
        parameters: JSON.stringify({ operation: 'strip_metadata', fields_removed: findings.length }),
      },
      sanitizationFields: {
        findings: findings.map((f) => ({ field: f.field, category: f.category, action: f.action })),
        file_type: 'pdf',
        original_sha256: originalHash,
        sanitized_sha256: sanitizedHash,
      },
    });
  } catch (e) {
    showErr('strip-err', 'Metadata read/strip failed: ' + e.message);
  }
});
