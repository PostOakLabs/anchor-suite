// CL-02: DOCX -> Markdown/HTML, local-only. mammoth.js (vendored, /vendor/mammoth.browser.min.js)
// does the DOCX parse; this module hashes both ends, renders a Markdown view with a small
// hand-rolled HTML walker (mammoth ships an HTML converter only, no Markdown output), and
// builds the deep-link into the receipt builder (art-191).

const ENGINE_NAME = 'mammoth.js';
const ENGINE_VERSION = '1.9.1';
// SHA-256 of /vendor/mammoth.browser.min.js as vendored — baked at build time, matches
// VENDORED.md. Re-derive with sha256sum if the vendored file is ever re-pinned.
const ENGINE_SHA256 = '78afc1f7bd08792370110cb54946ea48adb64b35ad21f6126d21f2d8e00d3a00';
const ENGINE_URL = 'https://github.com/mwilliamson/mammoth.js';

if (window.trustedTypes && trustedTypes.createPolicy) {
  trustedTypes.createPolicy('default', { createHTML: (s) => s });
}

const dropZone = document.getElementById('drop-zone');
const dropLabel = document.getElementById('drop-label');
const fileInput = document.getElementById('file-input');
const outputArea = document.getElementById('output-area');
const previewText = document.getElementById('preview-text');
const btnMd = document.getElementById('btn-md');
const btnHtml = document.getElementById('btn-html');
const downloadBtn = document.getElementById('download-btn');
const copyBtn = document.getElementById('copy-btn');
const warningsEl = document.getElementById('mammoth-warnings');
const inHashEl = document.getElementById('in-hash');
const outHashEl = document.getElementById('out-hash');
const engineVersionEl = document.getElementById('engine-version');
const receiptLink = document.getElementById('receipt-link');

engineVersionEl.textContent = ENGINE_VERSION;

let state = null; // { filename, inputHash, html, md, format }

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

// Minimal, deterministic HTML -> Markdown walker for the structural subset mammoth emits
// (headings, paragraphs, lists, emphasis, links, images, blockquote, tables, br, hr, code).
function htmlToMarkdown(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');

  function inline(node) {
    let out = '';
    node.childNodes.forEach((child) => {
      if (child.nodeType === Node.TEXT_NODE) { out += child.textContent; return; }
      if (child.nodeType !== Node.ELEMENT_NODE) return;
      const tag = child.tagName.toLowerCase();
      const inner = inline(child);
      if (tag === 'strong' || tag === 'b') out += `**${inner}**`;
      else if (tag === 'em' || tag === 'i') out += `*${inner}*`;
      else if (tag === 'code') out += `\`${inner}\``;
      else if (tag === 'br') out += '\n';
      else if (tag === 'a') out += `[${inner}](${child.getAttribute('href') || ''})`;
      else if (tag === 'img') out += `![${child.getAttribute('alt') || ''}](${child.getAttribute('src') || ''})`;
      else out += inner;
    });
    return out;
  }

  function block(node, listDepth) {
    let out = '';
    node.childNodes.forEach((child) => {
      if (child.nodeType !== Node.ELEMENT_NODE) return;
      const tag = child.tagName.toLowerCase();
      if (/^h[1-6]$/.test(tag)) {
        out += `${'#'.repeat(Number(tag[1]))} ${inline(child).trim()}\n\n`;
      } else if (tag === 'p') {
        out += `${inline(child).trim()}\n\n`;
      } else if (tag === 'blockquote') {
        out += inline(child).trim().split('\n').map((l) => `> ${l}`).join('\n') + '\n\n';
      } else if (tag === 'hr') {
        out += '---\n\n';
      } else if (tag === 'ul' || tag === 'ol') {
        let i = 0;
        child.querySelectorAll(':scope > li').forEach((li) => {
          i += 1;
          const marker = tag === 'ol' ? `${i}.` : '-';
          out += `${'  '.repeat(listDepth)}${marker} ${inline(li).trim()}\n`;
        });
        out += '\n';
      } else if (tag === 'table') {
        const rows = [...child.querySelectorAll('tr')];
        rows.forEach((row, ri) => {
          const cells = [...row.children].map((c) => inline(c).trim());
          out += `| ${cells.join(' | ')} |\n`;
          if (ri === 0) out += `| ${cells.map(() => '---').join(' | ')} |\n`;
        });
        out += '\n';
      } else {
        out += block(child, listDepth);
      }
    });
    return out;
  }

  return block(doc.body, 0).trim() + '\n';
}

function currentOutputText() {
  if (!state) return '';
  return state.format === 'md' ? state.md : state.html;
}

function currentExtension() {
  return state && state.format === 'md' ? 'md' : 'html';
}

async function renderOutput() {
  previewText.textContent = currentOutputText();
  const outBytes = new TextEncoder().encode(currentOutputText());
  const outHash = await sha256Hex(outBytes);
  outHashEl.textContent = outHash;
  state.outHash = outHash;
  buildReceiptLink();
}

function buildReceiptLink() {
  if (!state || !state.outHash) return;
  const base = state.filename.replace(/\.docx$/i, '');
  const fields = {
    input_sha256: state.inputHash,
    output_sha256: state.outHash,
    source_format: 'docx',
    target_format: state.format,
    converter_name: ENGINE_NAME,
    converter_version: ENGINE_VERSION,
    converter_engine_sha256: ENGINE_SHA256,
    converter_url: ENGINE_URL,
    input_filename: state.filename,
    output_filename: `${base}.${currentExtension()}`,
  };
  const payload = b64urlEncode(JSON.stringify(fields));
  receiptLink.href = `https://ainumbers.co/chaingraph/art-191-conversion-receipt-builder.html#in=${payload}`;
}

function setFormat(fmt) {
  if (!state) return;
  state.format = fmt;
  btnMd.classList.toggle('active', fmt === 'md');
  btnHtml.classList.toggle('active', fmt === 'html');
  renderOutput();
}

async function handleFile(file) {
  if (!file) return;
  dropLabel.textContent = file.name;
  const buf = await file.arrayBuffer();
  const inputHash = await sha256Hex(new Uint8Array(buf));

  const result = await window.mammoth.convertToHtml({ arrayBuffer: buf });
  const md = htmlToMarkdown(result.value);

  state = { filename: file.name, inputHash, html: result.value, md, format: 'md' };
  inHashEl.textContent = inputHash;
  warningsEl.textContent = result.messages.length
    ? `mammoth reported ${result.messages.length} conversion note(s): ${result.messages.map((m) => m.message).join('; ')}`
    : '';

  outputArea.hidden = false;
  btnMd.classList.add('active');
  btnHtml.classList.remove('active');
  await renderOutput();
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

btnMd.addEventListener('click', () => setFormat('md'));
btnHtml.addEventListener('click', () => setFormat('html'));

downloadBtn.addEventListener('click', () => {
  if (!state) return;
  const blob = new Blob([currentOutputText()], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${state.filename.replace(/\.docx$/i, '')}.${currentExtension()}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
});

copyBtn.addEventListener('click', async () => {
  if (!state) return;
  try {
    await navigator.clipboard.writeText(currentOutputText());
    copyBtn.textContent = 'Copied';
    setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
  } catch (e) { /* clipboard permission denied; no-op */ }
});
