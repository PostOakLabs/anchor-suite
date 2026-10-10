// anchor-webmcp.js — WebMCP page-level tool registration for /anchor.html.
// ANCHOR-WEBMCP-1 (AGENT-REACH-BUILD-SPEC §3.9 pattern, art-220 pilot shape).
//
// This whole file is ONE marker-delimited registration block:
//   /* WEBMCP:BEGIN ... */ ... /* WEBMCP:END */
// It is an external module (not inline) because the estate CSP is
// script-src 'self' — scripts/check-no-inline-scripts.mjs enforces that.
//
// Two tools, namespaced to the anchor origin (https://anchor.ainumbers.co):
//   anchor_hash            — drives THIS PAGE's existing Stamp flow for one hex
//                            SHA-256 digest against one timestamp authority.
//                            This IS network egress: the hash (never file bytes)
//                            is sent to the selected public RFC 3161 timestamp
//                            authority, exactly as when a human clicks Stamp.
//                            readOnlyHint: false, openWorldHint: true — truthful.
//   verify_anchor_binding  — OFFLINE verification of a binding this page (or the
//                            /mcp worker) produced: DER parse, message-imprint
//                            check, TSA signature chain to the pinned roots.
//                            readOnlyHint: true. No network access.
//
// The tool names intentionally mirror the worker's /mcp tools (same operation,
// same name, two surfaces: browser page vs server endpoint).

/* WEBMCP:BEGIN row=ANCHOR-WEBMCP-1 tools=anchor_hash,verify_anchor_binding origin=https://anchor.ainumbers.co */
import { verifyTstBinding } from '/js/tst.js';

const AUTHORITIES = ['sigstore', 'sigsum', 'digicert', 'sectigo', 'freetsa', 'github', 'opentimestamps'];

const mc = document.modelContext ?? (('modelContext' in navigator) ? navigator.modelContext : null);
if (mc) {
  mc.registerTool({
    name: 'anchor_hash',
    description: 'Timestamp one hex SHA-256 digest with one public RFC 3161 authority using this page\'s own Stamp flow. EGRESS: this sends the hash itself (never file bytes) over the network to the selected timestamp authority (Sigstore, Sigsum, DigiCert, Sectigo, FreeTSA, GitHub, or OpenTimestamps) — the same user-initiated egress as clicking Stamp. Returns the authority outcome; the full binding lands in the page output as usual.',
    inputSchema: {
      type: 'object',
      required: ['sha256', 'authority'],
      properties: {
        sha256: { type: 'string', pattern: '^(sha256:)?[0-9a-fA-F]{64}$', description: 'Hex SHA-256 digest, with or without the "sha256:" prefix.' },
        authority: { type: 'string', enum: AUTHORITIES, description: 'Exactly one timestamp authority to stamp with.' }
      }
    },
    annotations: { readOnlyHint: false, openWorldHint: true },
    execute: async function (params) {
      const hex = String(params.sha256 || '').replace(/^sha256:/i, '').toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('sha256 must be a 64-hex-char SHA-256 digest (optionally "sha256:"-prefixed); received ' + JSON.stringify(params.sha256) + '.');
      const authority = String(params.authority || '');
      if (!AUTHORITIES.includes(authority)) throw new Error('authority must be one of ' + AUTHORITIES.join(', ') + '; received ' + JSON.stringify(params.authority) + '.');

      const byId = (id) => document.getElementById(id);

      // Single-file mode only (batch stamps a Merkle root, not this hash).
      if (!byId('mode-btn-single')?.classList.contains('active')) byId('mode-btn-single')?.click();

      // Set the hash through the page's own input path (updates its state + UI).
      const input = byId('hash-input');
      if (!input) throw new Error('anchor page hash input not found.');
      input.value = 'sha256:' + hex;
      input.dispatchEvent(new Event('input', { bubbles: false }));

      // Stamp ONLY the requested authority: snapshot, isolate, restore.
      const boxes = AUTHORITIES.map((id) => byId('cb-' + id)).filter(Boolean);
      const snapshot = boxes.map((cb) => cb.checked);
      for (const cb of boxes) cb.checked = false;
      const target = byId('cb-' + authority);
      if (!target) throw new Error('authority checkbox missing for ' + authority + '.');
      target.checked = true;

      const stampBtn = byId('stamp-btn');
      if (!stampBtn) throw new Error('anchor page stamp button not found.');
      stampBtn.click();

      const status = byId('pstatus-' + authority);
      const deadline = Date.now() + 45000;
      while (Date.now() < deadline) {
        const cls = status?.className || '';
        if (cls.includes('ok') || cls.includes('err')) break;
        await new Promise((r) => setTimeout(r, 250));
      }
      const detail = status ? status.textContent : 'no status element';
      const outcome = status?.className?.includes('err') ? 'failed' : (status?.className?.includes('ok') ? 'stamped' : 'timeout');

      for (let i = 0; i < boxes.length; i++) boxes[i].checked = snapshot[i];

      return { tool: 'anchor_hash', anchored_hash: 'sha256:' + hex, authority: authority, outcome: outcome, detail: detail, note: outcome === 'stamped' ? 'Binding available in the page output and Artifact Library.' : undefined };
    }
  });

  mc.registerTool({
    name: 'verify_anchor_binding',
    description: 'Verify an RFC 3161 anchor binding OFFLINE: parses the DER timestamp token, checks its message imprint against the anchored SHA-256 hash, and verifies the TSA signature chain to this site\'s pinned roots. No network access — safe and side-effect free.',
    inputSchema: {
      type: 'object',
      required: ['binding'],
      properties: {
        binding: {
          type: 'object',
          description: 'An anchor_bindings entry: { anchored_hash: "sha256:<hex>", proof: <base64 DER TimeStampResp/Token>, ... }.',
          required: ['anchored_hash', 'proof'],
          properties: {
            anchored_hash: { type: 'string', description: '"sha256:" + 64 hex chars.' },
            proof: { type: 'string', description: 'Base64 DER of the RFC 3161 TimeStampResp or TimeStampToken.' }
          }
        }
      }
    },
    annotations: { readOnlyHint: true },
    execute: async function (params) {
      const binding = params && params.binding;
      if (!binding || typeof binding !== 'object') throw new Error('binding must be an anchor_bindings entry object with anchored_hash and proof.');
      return verifyTstBinding(binding);
    }
  });
}
/* WEBMCP:END */
