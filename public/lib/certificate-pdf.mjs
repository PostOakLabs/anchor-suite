// certificate-pdf.mjs — downloadable verification certificate (one-page PDF),
// the anchor-suite sibling of helm's auditor-pdf.mjs content model. Rendered
// client-side with the already-vendored pdf-lib (/vendor/pdf-lib.min.js), which
// is lazy-loaded on first button press (its ~525KB never loads for users who
// only download anchors.json).
//
// Determinism discipline (same as convert/pdf-toolkit.html): the PDF is a pure
// function of the receipt bytes plus the pinned vendored engine. No generation
// clock, no locale. The document dates are derived from the receipt's own
// gen_time (or a fixed epoch when the receipt is entirely pending), so the
// certificate's own sha256 is quotable.

const ENGINE_NAME = 'pdf-lib';
const ENGINE_VERSION = '1.17.1';
// SHA-256 of /vendor/pdf-lib.min.js as vendored, matches VENDORED.md and the
// ENGINE_SHA256 constant in convert/pdf-toolkit.js. Re-derive if re-pinned.
const ENGINE_SHA256 = '0f9a5cad07941f0826586c94e089d89b918c46e5c17cf2d5a3c6f666e3bc694f';

const FIXED_EPOCH_ISO = '1970-01-01T00:00:00.000Z';
const PAGE_W = 612;  // US Letter, points
const PAGE_H = 792;
const MARGIN = 54;

// ---- engine lazy-load -------------------------------------------------------

let pdfLibPromise = null;

// The estate CSP pins `trusted-types default`, so same-origin script URLs set
// from JS must go through the document's default policy (same pattern as
// convert/pdf-toolkit.js, which creates the default policy for createHTML).
// The only URL ever passed is the constant vendored engine path.
function toTrustedScriptUrl(url) {
  const tt = globalThis.trustedTypes;
  if (!tt) return url;
  const dp = tt.defaultPolicy;
  if (dp && dp.createScriptURL) return dp.createScriptURL(url);
  if (!dp && tt.createPolicy) {
    const p = tt.createPolicy('default', { createScriptURL: (s) => s });
    return p.createScriptURL(url);
  }
  throw new Error('No Trusted Types policy can authorize the engine URL');
}

// Injects the same-origin vendored engine on first use. CSP script-src 'self'
// permits same-origin script elements; no header change is needed.
function ensurePdfLib() {
  if (globalThis.PDFLib) return Promise.resolve(globalThis.PDFLib);
  if (!pdfLibPromise) {
    pdfLibPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = toTrustedScriptUrl('/vendor/pdf-lib.min.js');
      s.onload = () => (globalThis.PDFLib ? resolve(globalThis.PDFLib) : reject(new Error('PDF engine loaded but PDFLib is missing')));
      s.onerror = () => { pdfLibPromise = null; reject(new Error('Could not load the PDF engine from /vendor/pdf-lib.min.js')); };
      document.head.appendChild(s);
    });
  }
  return pdfLibPromise;
}

// ---- receipt -> certificate lines (the whole certificate text, in order) ----

// A binding's state on paper. PENDING IS PENDING: a pending binding is printed
// as pending and is never upgraded to stamped (HELM-P3-SEC-3 discipline).
function bindingStatus(b) {
  if (b?.type === 'opentimestamps') return { state: 'pending', note: 'pending (bitcoin confirmation)' };
  if (b?.type === 'c2sp-tlog-pending-v1') return { state: 'pending', note: 'pending (transparency log inclusion)' };
  if (b?.type === 'rfc3161-tst' && b.gen_time) return { state: 'stamped', note: b.gen_time + ' UTC' };
  return { state: 'pending', note: 'pending' };
}

function authorityHost(b) {
  const origin = b?.log_origin || '';
  if (b?.type === 'opentimestamps') return 'OpenTimestamps (bitcoin)';
  if (b?.type === 'c2sp-tlog-pending-v1') return 'Sigsum (transparency log)';
  return origin.replace(/^https?:\/\//, '').split('/')[0] || 'unknown';
}

// Builds every line of the certificate, top to bottom. Exported so the gates
// and any test can assert on exactly what the PDF says without parsing PDF.
export function certificateLines(input) {
  const lines = [];
  const batch = input.kind === 'batch';
  const digest = 'sha256:' + input.anchoredHash;

  lines.push({ text: 'Verification certificate', style: 'title' });
  lines.push({ text: 'Issued by anchor.ainumbers.co', style: 'sub' });
  lines.push({ text: 'Post Oak Labs never sees your document. The timestamp authorities listed below are the issuers.', style: 'body' });
  lines.push({ text: '', style: 'gap' });

  if (batch) {
    lines.push({ text: 'Batch Merkle root', style: 'label' });
    lines.push({ text: 'sha256:' + input.rootHex, style: 'mono' });
    lines.push({ text: 'Items in batch (tree size): ' + input.treeSize, style: 'body' });
    lines.push({ text: '', style: 'gap' });
    lines.push({ text: 'Anchored item', style: 'label' });
    lines.push({ text: digest, style: 'mono' });
    if (input.itemLabel) lines.push({ text: 'Label: ' + input.itemLabel, style: 'body' });
    const inc = input.merkleInclusion;
    if (inc) {
      lines.push({ text: 'Inclusion path: leaf index ' + inc.index + ' of ' + inc.tree_size + ' items, ' +
        (inc.path ? inc.path.length : 0) + '-step ' + (inc.algorithm || 'sha256') + ' path', style: 'body' });
      lines.push({ text: 'The full path is in batch-anchors.json; it proves this item was in this exact batch.', style: 'small' });
    }
    if (Array.isArray(input.items)) {
      lines.push({ text: 'Inclusion path summary (full paths in batch-anchors.json):', style: 'body' });
      for (const it of input.items) {
        const e = it.merkle_inclusion || {};
        const name = it.label ? ' ' + it.label : '';
        lines.push({ text: ' #' + e.index + name + ' sha256:' + String(it.hash).replace(/^sha256:/, '').slice(0, 16) + '... - ' +
          (e.path ? e.path.length : 0) + '-step path, tree of ' + (e.tree_size || input.treeSize), style: 'mono' });
      }
    }
  } else {
    lines.push({ text: 'Anchored digest', style: 'label' });
    lines.push({ text: digest, style: 'mono' });
  }
  lines.push({ text: '', style: 'gap' });

  lines.push({ text: 'Timestamp authorities', style: 'label' });
  for (const b of input.bindings) {
    const st = bindingStatus(b);
    const policy = b?.policy_oid ? '  policy ' + b.policy_oid : '';
    lines.push({ text: authorityHost(b) + policy, style: 'mono' });
    lines.push({ text: '  ' + st.note, style: 'mono' });
  }
  lines.push({ text: '', style: 'gap' });

  lines.push({ text: 'What this certificate shows', style: 'label' });
  const stampedCount = input.bindings.filter((b) => bindingStatus(b).state === 'stamped').length;
  lines.push({ text: stampedCount > 0
    ? 'Verified: ' + stampedCount + ' of ' + input.bindings.length + ' authority stamp(s) carry a signed timestamp.'
    : 'Verified: no signed timestamps yet.', style: 'body' });
  const pendingCount = input.bindings.length - stampedCount;
  if (pendingCount > 0) {
    lines.push({ text: 'Pending: ' + pendingCount + ' binding(s) are pending and prove submission only. Pending is not stamped.', style: 'body' });
  }
  lines.push({ text: '', style: 'gap' });

  lines.push({ text: 'Verify independently', style: 'label' });
  lines.push({ text: 'openssl ts -verify -digest <file digest> -in tst.der -CAfile <root.pem>', style: 'mono' });
  lines.push({ text: 'or open anchor.ainumbers.co/verify.html and load the receipt.', style: 'body' });
  lines.push({ text: '', style: 'gap' });

  lines.push({ text: 'engine: ' + ENGINE_NAME + ' ' + ENGINE_VERSION + ' sha256:' + ENGINE_SHA256, style: 'small' });
  lines.push({ text: 'This certificate is generated deterministically from the receipt; the same receipt always produces this same PDF.', style: 'small' });
  return lines;
}

// A PDF date derived from the receipt itself (earliest gen_time), so two runs
// over the same receipt never differ. Entirely-pending receipts fall back to a
// fixed epoch rather than the wall clock (pdf-lib stamps ModDate with "now"
// unless both dates are set explicitly).
function receiptDateIso(bindings) {
  const times = bindings.map((b) => b?.gen_time).filter((t) => typeof t === 'string' && /Z$/.test(t)).sort();
  return times[0] || FIXED_EPOCH_ISO;
}

// Pure renderer: takes the PDFLib namespace (vendored UMD) and the receipt
// input, returns Promise<Uint8Array>. No DOM, no clock — runnable in Node.
export async function renderCertificate(PDFLib, input) {
  const { PDFDocument, StandardFonts, rgb } = PDFLib;
  const doc = await PDFDocument.create();
  doc.setTitle('Verification certificate');
  doc.setCreator('anchor.ainumbers.co');
  doc.setProducer(ENGINE_NAME + ' ' + ENGINE_VERSION);
  const when = new Date(receiptDateIso(input.bindings));
  doc.setCreationDate(when);
  doc.setModificationDate(when);

  const page = doc.addPage([PAGE_W, PAGE_H]);
  const helv = await doc.embedFont(StandardFonts.Helvetica);
  const helvBold = await doc.embedFont(StandardFonts.HelveticaBold);
  const courier = await doc.embedFont(StandardFonts.Courier);

  const ink = rgb(0.1, 0.1, 0.12);
  const mid = rgb(0.35, 0.35, 0.38);
  const style = {
    title: { font: helvBold, size: 18, lead: 26, color: ink },
    sub:   { font: helv, size: 11, lead: 16, color: mid },
    label: { font: helvBold, size: 10, lead: 14, color: ink },
    body:  { font: helv, size: 10, lead: 14, color: ink },
    small: { font: helv, size: 8, lead: 11, color: mid },
    mono:  { font: courier, size: 9, lead: 12, color: ink },
    gap:   { font: helv, size: 6, lead: 10, color: ink },
  };

  let y = PAGE_H - MARGIN;
  for (const line of certificateLines(input)) {
    const s = style[line.style] || style.body;
    y -= s.lead;
    if (line.text) {
      // Simple wrap for body/small prose; mono lines are kept short by design.
      let text = line.text;
      const maxW = PAGE_W - 2 * MARGIN;
      if ((s.font === helv || s.font === helvBold) && s.font.widthOfTextAtSize(text, s.size) > maxW) {
        const words = text.split(' ');
        text = '';
        for (const w of words) {
          const cand = text ? text + ' ' + w : w;
          if (s.font.widthOfTextAtSize(cand, s.size) > maxW) {
            page.drawText(text, { x: MARGIN, y, size: s.size, font: s.font, color: s.color });
            y -= s.lead;
            text = w;
          } else text = cand;
        }
      }
      page.drawText(text, { x: MARGIN, y, size: s.size, font: s.font, color: s.color });
    }
  }

  return doc.save();
}

// Browser entry point: lazy-loads the engine on first press, renders, hands
// back bytes. anchor.js owns the button and the triggerDownload call.
export async function buildCertificatePdf(input) {
  const PDFLib = await ensurePdfLib();
  return renderCertificate(PDFLib, input);
}
