// CL-01: PDF -> Markdown, local-only. pdf.js (vendored, /vendor/pdfjs.min.mjs +
// /vendor/pdfjs.worker.min.mjs, same-origin, no CDN) extracts the text layer; this module
// hashes both ends, applies a font-size heading heuristic to render Markdown, detects
// no-text-layer (scanned) PDFs and shows an honest message instead of guessing, and builds
// the deep-link into the receipt builder (art-191).

import * as pdfjsLib from '/vendor/pdfjs.min.mjs';

// pdf.js instantiates its worker via `new Worker(workerSrc)`. Under this site's
// `require-trusted-types-for 'script'` CSP, that construction must pass through a Trusted
// Types policy; pdf.js itself does not register one, so this page does (same pattern the
// DOCX tool uses for createHTML, extended with createScriptURL for the worker).
if (window.trustedTypes && trustedTypes.createPolicy) {
  trustedTypes.createPolicy('default', {
    createHTML: (s) => s,
    createScript: (s) => s,
    createScriptURL: (s) => s,
  });
}

const ENGINE_NAME = 'pdf.js';
const ENGINE_VERSION = pdfjsLib.version;
// SHA-256 of /vendor/pdfjs.min.mjs as vendored — baked at build time, matches VENDORED.md.
// Re-derive with sha256sum if the vendored file is ever re-pinned.
const ENGINE_SHA256 = '4ba2f15599b03fde8755ad91349920c21dadd3e8fd6b6460a7663d46d4cf21b5';
const ENGINE_URL = 'https://github.com/mozilla/pdf.js';

pdfjsLib.GlobalWorkerOptions.workerSrc = '/vendor/pdfjs.worker.min.mjs';

const dropZone = document.getElementById('drop-zone');
const dropLabel = document.getElementById('drop-label');
const fileInput = document.getElementById('file-input');
const noTextLayerEl = document.getElementById('no-text-layer');
const outputArea = document.getElementById('output-area');
const previewText = document.getElementById('preview-text');
const downloadBtn = document.getElementById('download-btn');
const copyBtn = document.getElementById('copy-btn');
const notesEl = document.getElementById('pdf-notes');
const inHashEl = document.getElementById('in-hash');
const outHashEl = document.getElementById('out-hash');
const engineVersionEl = document.getElementById('engine-version');
const receiptLink = document.getElementById('receipt-link');

engineVersionEl.textContent = ENGINE_VERSION;

let state = null; // { filename, inputHash, md, outHash }

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

// Group a page's text items into lines (by y-position) then paragraphs (by vertical gap),
// tracking each line's dominant font height so headings can be told from body text.
function linesFromTextContent(textContent) {
  const items = textContent.items.filter((it) => typeof it.str === 'string');
  const lines = [];
  let current = null;
  const Y_TOLERANCE = 2;

  for (const item of items) {
    const y = item.transform[5];
    const height = Math.hypot(item.transform[2], item.transform[3]) || item.height || 0;
    if (current && Math.abs(current.y - y) <= Y_TOLERANCE) {
      current.text += item.str;
      current.height = Math.max(current.height, height);
    } else {
      if (current) lines.push(current);
      current = { y, height, text: item.str };
    }
    if (item.hasEOL) { if (current) { lines.push(current); current = null; } }
  }
  if (current) lines.push(current);

  // pdf.js text-content y grows upward from the page bottom; sort top-to-bottom for reading order.
  lines.sort((a, b) => b.y - a.y);
  return lines.filter((l) => l.text.trim().length > 0);
}

function markdownFromPages(pages) {
  const allLines = pages.flat();
  if (allLines.length === 0) return '';

  const heights = allLines.map((l) => l.height).filter((h) => h > 0);
  const bodyHeight = heights.length ? median(heights) : 10;

  const out = [];
  let prevY = null;
  let prevPage = -1;

  pages.forEach((lines, pageIdx) => {
    lines.forEach((line) => {
      const gap = prevPage === pageIdx && prevY !== null ? prevY - line.y : Infinity;
      const ratio = bodyHeight > 0 ? line.height / bodyHeight : 1;
      const text = line.text.trim();
      let rendered;
      if (ratio >= 1.6) rendered = `# ${text}`;
      else if (ratio >= 1.35) rendered = `## ${text}`;
      else if (ratio >= 1.15) rendered = `### ${text}`;
      else rendered = text;

      if (out.length > 0 && (gap === Infinity || gap > line.height * 1.4)) out.push('');
      out.push(rendered);
      prevY = line.y;
      prevPage = pageIdx;
    });
    prevY = null;
  });

  return out.join('\n').trim() + '\n';
}

function median(nums) {
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function extractMarkdown(buf) {
  const loadingTask = pdfjsLib.getDocument({ data: buf });
  const doc = await loadingTask.promise;
  const pages = [];
  let totalChars = 0;

  for (let i = 1; i <= doc.numPages; i++) {
    const page = await doc.getPage(i);
    const textContent = await page.getTextContent();
    const lines = linesFromTextContent(textContent);
    totalChars += lines.reduce((sum, l) => sum + l.text.trim().length, 0);
    pages.push(lines);
  }

  return { md: markdownFromPages(pages), pageCount: doc.numPages, totalChars };
}

function buildReceiptLink() {
  if (!state || !state.outHash) return;
  const base = state.filename.replace(/\.pdf$/i, '');
  const fields = {
    input_sha256: state.inputHash,
    output_sha256: state.outHash,
    source_format: 'pdf',
    target_format: 'md',
    converter_name: ENGINE_NAME,
    converter_version: ENGINE_VERSION,
    converter_engine_sha256: ENGINE_SHA256,
    converter_url: ENGINE_URL,
    input_filename: state.filename,
    output_filename: `${base}.md`,
  };
  const payload = b64urlEncode(JSON.stringify(fields));
  receiptLink.href = `https://ainumbers.co/chaingraph/art-191-conversion-receipt-builder.html#in=${payload}`;
}

async function handleFile(file) {
  if (!file) return;
  dropLabel.textContent = file.name;
  noTextLayerEl.hidden = true;
  outputArea.hidden = true;

  const buf = await file.arrayBuffer();
  const inputHash = await sha256Hex(new Uint8Array(buf));

  const { md, pageCount, totalChars } = await extractMarkdown(buf.slice(0));

  if (totalChars === 0) {
    noTextLayerEl.hidden = false;
    state = null;
    return;
  }

  const outBytes = new TextEncoder().encode(md);
  const outHash = await sha256Hex(outBytes);

  state = { filename: file.name, inputHash, md, outHash };
  inHashEl.textContent = inputHash;
  outHashEl.textContent = outHash;
  notesEl.textContent = `${pageCount} page${pageCount === 1 ? '' : 's'} extracted from the text layer. Layout is approximated from font size, not a semantic document structure.`;
  previewText.textContent = md;

  outputArea.hidden = false;
  buildReceiptLink();
}

dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
fileInput.addEventListener('change', () => handleFile(fileInput.files[0]));
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  handleFile(e.dataTransfer.files[0]);
});

downloadBtn.addEventListener('click', () => {
  if (!state) return;
  const blob = new Blob([state.md], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${state.filename.replace(/\.pdf$/i, '')}.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
});

copyBtn.addEventListener('click', async () => {
  if (!state) return;
  try {
    await navigator.clipboard.writeText(state.md);
    copyBtn.textContent = 'Copied';
    setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
  } catch (e) { /* clipboard permission denied; no-op */ }
});
