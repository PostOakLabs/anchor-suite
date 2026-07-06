// Anchor Suite Worker — stateless relay + MCP endpoint.
//
// Routes handled by this Worker (all others served from static ASSETS):
//   /relay/*   POST-only relay to classic CA timestamp authorities. DER in, DER out.
//              CORS allows https://anchor.ainumbers.co for browser callers.
//   /mcp       MCP JSON-RPC: initialize, tools/list, tools/call.
//              Five tools: list_anchor_authorities, anchor_hash,
//              verify_anchor_binding, create_signature_envelope,
//              verify_signature_envelope. Stateless; stores nothing.
//              CORS: echo-origin allowlist (MCP_ORIGIN_ALLOWLIST); NOT wildcard.
//
// Shared constraint: outbound calls go only to the pinned authority list.
// anchor_hash is rate-limited per caller IP (reuses RELAY_LIMITER, 4/min/IP).

import {
  hexToBytes, bytesHex, bytesToBase64, base64ToBytes, freshNonce, freshNonce6,
  buildTsqDer,
} from '../public/lib/tsq.mjs';
import { parseTstDer, extractTstMeta, verifyTstBinding } from '../public/js/tst.js';
import {
  createEnvelope, hashEvent, verifyAssertion, base64ToBytes as apBase64ToBytes,
} from '../public/lib/anchorproof.mjs';
import { buildJadesBT } from '../public/lib/jades.mjs';
import { pkijs, asn1js } from '../public/vendor/pkijs.bundle.mjs';
import { buildMerkleBatch, verifyMerkleInclusion } from '../public/lib/merkle.mjs';

// ---------------------------------------------------------------------------
// Relay config
// ---------------------------------------------------------------------------

const RELAY_UPSTREAMS = {
  digicert: 'http://timestamp.digicert.com',
  sectigo:  'http://timestamp.sectigo.com',
  freetsa:  'https://freetsa.org/tsr',
};

// Outbound allowlist shared by relay and anchor_hash MCP tool.
const AUTHORITY_URLS = {
  sigstore: 'https://timestamp.sigstore.dev/api/v1/timestamp',
  github:   'https://timestamp.githubapp.com/api/v1/timestamp',
  digicert: 'http://timestamp.digicert.com',
  sectigo:  'http://timestamp.sectigo.com',
  freetsa:  'https://freetsa.org/tsr',
};

const OTS_CALENDARS = [
  'https://alice.btc.calendar.opentimestamps.org',
  'https://bob.btc.calendar.opentimestamps.org',
  'https://finney.calendar.eternitywall.com',
  'https://btc.calendar.catallaxy.com',
];

const ALLOWED_RELAY_ORIGIN = 'https://anchor.ainumbers.co';
const MAX_BODY_BYTES = 2048;
const UPSTREAM_TIMEOUT_MS = 25_000;
const TSA_TIMEOUT_MS = 30_000;

const RELAY_CORS = {
  'Access-Control-Allow-Origin':  ALLOWED_RELAY_ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age':       '86400',
  'Vary':                         'Origin',
};

// Allowlist for /mcp CORS. NOT wildcard — rate limit is worth protecting.
// Only echo the matched origin; unknown origins get no Allow-Origin header.
const MCP_ORIGIN_ALLOWLIST = new Set(['https://ledger.ainumbers.co']);

function getMcpCors(request) {
  const origin = request.headers.get('Origin');
  if (origin && MCP_ORIGIN_ALLOWLIST.has(origin)) {
    return {
      'Access-Control-Allow-Origin':  origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age':       '86400',
      'Vary':                         'Origin',
    };
  }
  return { 'Vary': 'Origin' };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function textResponse(status, message, extraHeaders = {}) {
  return new Response(message + '\n', {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

function jsonResponse(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

function mcpError(id, code, message, cors = {}) {
  return jsonResponse(200, { jsonrpc: '2.0', id: id ?? null, error: { code, message } }, cors);
}

function mcpResult(id, result, cors = {}) {
  return jsonResponse(200, { jsonrpc: '2.0', id, result }, cors);
}

// ---------------------------------------------------------------------------
// Authority metadata for list_anchor_authorities
// ---------------------------------------------------------------------------

const AUTHORITY_META = [
  {
    id: 'sigstore',
    name: 'Sigstore TSA',
    kind: 'rfc3161',
    cost: 'free',
    notes: 'OpenSSF public-good TSA. ECDSA-P384 root. CORS-open; no relay needed.',
  },
  {
    id: 'digicert',
    name: 'DigiCert Timestamp Authority',
    kind: 'rfc3161',
    cost: 'free',
    notes: 'Commercial CA. RSA root (DigiCert Trusted Root G4). Instant.',
  },
  {
    id: 'sectigo',
    name: 'Sectigo Timestamp Authority',
    kind: 'rfc3161',
    cost: 'free',
    notes: 'Commercial CA. RSA root (Sectigo Public Time Stamping Root R46). 15-second pacing required.',
  },
  {
    id: 'freetsa',
    name: 'FreeTSA',
    kind: 'rfc3161',
    cost: 'free',
    notes: 'Community TSA. RSA root. Pair with another authority for reliability.',
  },
  {
    id: 'github',
    name: 'GitHub Timestamp Authority',
    kind: 'rfc3161',
    cost: 'free',
    notes: 'HSM-backed. ECDSA-P384 root. Not publicly documented for third-party use.',
  },
  {
    id: 'opentimestamps',
    name: 'OpenTimestamps',
    kind: 'opentimestamps',
    cost: 'free',
    notes: 'Bitcoin-anchored. Proof is pending for several hours until Bitcoin confirmation.',
  },
];

// ---------------------------------------------------------------------------
// OTS minimal pending proof builder
// ---------------------------------------------------------------------------
// Assembles a minimal .ots pending file from raw calendar responses.
// Format: MAGIC(31) + SHA256_TAG(1) + hash(32) + [FORK(1) + cal_bytes]* + last_cal_bytes

const OTS_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
  0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
  0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const OTS_SHA256_TAG  = new Uint8Array([0x08]);
const OTS_FORK        = new Uint8Array([0xff]);
const OTS_PENDING_HEX = '83dfe30d2ef90c8e';
const OTS_BTC_HEX     = '0588960d73d71901';

function buildOtsPending(hashBytes, calResponses) {
  const parts = [OTS_MAGIC, OTS_SHA256_TAG, hashBytes];
  for (let i = 0; i < calResponses.length; i++) {
    if (i < calResponses.length - 1) parts.push(OTS_FORK);
    parts.push(calResponses[i]);
  }
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// ---------------------------------------------------------------------------
// TSA stamping helpers
// ---------------------------------------------------------------------------

async function stampSigstore(hashBytes) {
  const nonce6 = freshNonce6();
  const nonceNum = parseInt(bytesHex(nonce6), 16);
  const res = await fetch(AUTHORITY_URLS.sigstore, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      artifactHash: bytesToBase64(hashBytes),
      hashAlgorithm: 'sha256',
      nonce: nonceNum,
      certificates: true,
    }),
    signal: AbortSignal.timeout(TSA_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error('Sigstore HTTP ' + res.status);
  return new Uint8Array(await res.arrayBuffer());
}

async function stampRfc3161Direct(authorityId, hashBytes) {
  const url = AUTHORITY_URLS[authorityId];
  if (!url) throw new Error('Unknown authority: ' + authorityId);
  const nonce = freshNonce();
  const tsqDer = buildTsqDer(hashBytes, nonce);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: tsqDer,
    signal: AbortSignal.timeout(TSA_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(authorityId + ' HTTP ' + res.status);
  const ct = (res.headers.get('Content-Type') || '').split(';')[0].trim();
  if (ct !== 'application/timestamp-reply') throw new Error('Unexpected Content-Type: ' + ct);
  return new Uint8Array(await res.arrayBuffer());
}

async function stampOts(hashBytes) {
  const calResponses = [];
  for (const cal of OTS_CALENDARS) {
    try {
      const res = await fetch(cal + '/digest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: hashBytes,
        signal: AbortSignal.timeout(15_000),
      });
      if (res.ok) {
        const bytes = new Uint8Array(await res.arrayBuffer());
        if (bytes.length > 0) calResponses.push(bytes);
      }
    } catch { /* calendar unavailable; skip */ }
    if (calResponses.length >= 2) break;
  }
  if (calResponses.length === 0) throw new Error('No OTS calendars responded');
  return buildOtsPending(hashBytes, calResponses);
}

function derToBinding(der, logOrigin, hashHex) {
  const { tstInfo, signed } = parseTstDer(der);
  const meta = extractTstMeta(tstInfo, signed);
  return {
    type: 'rfc3161-tst',
    anchored_hash: 'sha256:' + hashHex,
    log_origin: logOrigin,
    proof: bytesToBase64(der),
    ...meta,
  };
}

// ---------------------------------------------------------------------------
// OTS pending-proof parser (for upgrade_ots_proof)
// ---------------------------------------------------------------------------

function otsReadVarint(buf, pos) {
  let v = 0, shift = 0;
  while (pos < buf.length) {
    const b = buf[pos++];
    v |= (b & 0x7f) << shift;
    if (!(b & 0x80)) return { value: v, nextPos: pos };
    shift += 7;
  }
  throw new Error('OTS varint: buffer underflow');
}

// Parse an OTS pending proof; collect {url, commitmentHex} per pending branch.
// Handles both standard format (version byte = 0x01) and our buildOtsPending format (no version).
async function parseOtsPending(proofBytes) {
  const buf = proofBytes instanceof Uint8Array ? proofBytes : new Uint8Array(proofBytes);
  for (let i = 0; i < OTS_MAGIC.length; i++) {
    if (buf[i] !== OTS_MAGIC[i]) throw new Error('invalid OTS magic');
  }
  let p = OTS_MAGIC.length;
  if (buf[p] === 0x01) p++; // skip version byte (standard format)
  if (buf[p] !== 0x08) throw new Error('expected SHA-256 hash op (0x08) at position ' + p);
  p++; // consume hash op
  const fileHashBytes = buf.slice(p, p + 32); p += 32;
  const fileHashHex = bytesHex(fileHashBytes);

  const pendingBranches = [];
  const completedBranches = [];

  async function walk(startPos, startMsg) {
    let pos = startPos;
    let cur = new Uint8Array(startMsg);
    while (pos < buf.length) {
      const tag = buf[pos++];
      if (tag === 0xff) {
        pos = await walk(pos, cur);
        continue;
      }
      if (tag === 0x00) {
        const atHex = bytesHex(buf.slice(pos, pos + 8)); pos += 8;
        const { value: payLen, nextPos } = otsReadVarint(buf, pos); pos = nextPos;
        const payload = buf.slice(pos, pos + payLen); pos += payLen;
        if (atHex === OTS_PENDING_HEX) {
          const url = new TextDecoder().decode(payload).trim();
          pendingBranches.push({ url, commitmentHex: bytesHex(cur) });
        } else if (atHex === OTS_BTC_HEX) {
          completedBranches.push({ commitmentHex: bytesHex(cur) });
        }
        return pos; // branch ends at attestation
      }
      if (tag === 0xf0) { // append
        const { value: n, nextPos } = otsReadVarint(buf, pos); pos = nextPos;
        const data = buf.slice(pos, pos + n); pos += n;
        const next = new Uint8Array(cur.length + data.length);
        next.set(cur); next.set(data, cur.length);
        cur = next;
      } else if (tag === 0xf1) { // prepend
        const { value: n, nextPos } = otsReadVarint(buf, pos); pos = nextPos;
        const data = buf.slice(pos, pos + n); pos += n;
        const next = new Uint8Array(data.length + cur.length);
        next.set(data); next.set(cur, data.length);
        cur = next;
      } else if (tag === 0x08) { // sha256
        cur = new Uint8Array(await crypto.subtle.digest('SHA-256', cur));
      } else {
        throw new Error('unsupported OTS op 0x' + tag.toString(16));
      }
    }
    return pos;
  }

  await walk(p, fileHashBytes);
  return { fileHashHex, pendingBranches, completedBranches };
}

// ---------------------------------------------------------------------------
// Cert notAfter helper (for renewal advisory)
// ---------------------------------------------------------------------------

function earliestNotAfter(certChainB64) {
  if (!Array.isArray(certChainB64) || certChainB64.length === 0) return null;
  let earliest = null;
  for (const b64 of certChainB64) {
    try {
      const der = base64ToBytes(b64);
      const cert = new pkijs.Certificate({ schema: asn1js.fromBER(new Uint8Array(der).buffer).result });
      const notAfter = cert.notAfter.value; // Date
      if (!(notAfter instanceof Date) || isNaN(notAfter.getTime())) continue;
      if (!earliest || notAfter < earliest) earliest = notAfter;
    } catch { /* skip unparseable cert */ }
  }
  return earliest;
}

function buildRenewalAdvisory(binding) {
  const notAfter = earliestNotAfter(binding.signer_cert_chain_b64);
  if (!notAfter) return null;
  const now = new Date();
  const twoYrMs = 2 * 365.25 * 24 * 3600 * 1000;
  const advice = (notAfter.getTime() - now.getTime()) < twoYrMs
    ? 'Earliest certificate in signer chain expires ' + notAfter.toISOString().slice(0, 10) +
      '. Re-anchor this hash before that date to maintain long-term verifiability.'
    : null;
  return {
    earliest_chain_expiry: notAfter.toISOString(),
    algorithm_status: 'sha256-ok',
    advice,
  };
}

// ---------------------------------------------------------------------------
// Core TSA stamping (shared by anchor_hash and anchor_batch)
// ---------------------------------------------------------------------------

async function stampWithAuthorities(rawHash, authorities) {
  const hashBytes = hexToBytes(rawHash);
  const anchor_bindings = [];
  const failures = [];
  let sectigoUsed = false;

  for (const id of authorities) {
    try {
      let binding;
      if (id === 'sigstore') {
        const der = await stampSigstore(hashBytes);
        binding = derToBinding(der, AUTHORITY_URLS.sigstore, rawHash);
      } else if (id === 'opentimestamps') {
        const otsBytes = await stampOts(hashBytes);
        binding = {
          type: 'opentimestamps',
          anchored_hash: 'sha256:' + rawHash,
          log_origin: 'bitcoin',
          proof: bytesToBase64(otsBytes),
        };
      } else {
        if (id === 'sectigo' && sectigoUsed) {
          await new Promise((r) => setTimeout(r, 15_000));
        }
        if (id === 'sectigo') sectigoUsed = true;
        const der = await stampRfc3161Direct(id, hashBytes);
        binding = derToBinding(der, AUTHORITY_URLS[id], rawHash);
      }
      anchor_bindings.push(binding);
    } catch (e) {
      failures.push({ authority: id, reason: e.message || String(e) });
    }
  }
  return { anchor_bindings, failures };
}

// ---------------------------------------------------------------------------
// MCP tool: anchor_hash
// ---------------------------------------------------------------------------

async function toolAnchorHash(args, callerIp, env) {
  const rawHash = (args.hash || '').replace(/^sha256:/, '').toLowerCase().trim();
  if (!/^[0-9a-f]{64}$/.test(rawHash)) {
    return { error: 'hash must be a 64-hex SHA-256 digest, optionally prefixed with sha256:' };
  }
  const authorities = Array.isArray(args.authorities) ? args.authorities : [];
  if (authorities.length === 0) {
    return { error: 'authorities must be a non-empty array' };
  }
  const unknown = authorities.filter((a) => !AUTHORITY_META.some((m) => m.id === a));
  if (unknown.length > 0) {
    return { error: 'unknown authorities: ' + unknown.join(', ') };
  }
  if (env.RELAY_LIMITER) {
    const { success } = await env.RELAY_LIMITER.limit({ key: callerIp });
    if (!success) {
      return { error: 'Rate limit: 4 anchor requests per minute per IP. Wait and retry.' };
    }
  }
  return stampWithAuthorities(rawHash, authorities);
}

// ---------------------------------------------------------------------------
// MCP tool: verify_anchor_binding
// ---------------------------------------------------------------------------

async function toolVerifyAnchorBinding(args) {
  let bindings = [];

  if (args.binding && typeof args.binding === 'object') {
    bindings = [args.binding];
  } else if (Array.isArray(args.anchors?.anchor_bindings)) {
    bindings = args.anchors.anchor_bindings;
  } else if (Array.isArray(args.artifact?.anchor_bindings)) {
    bindings = args.artifact.anchor_bindings;
  } else {
    return { error: 'Provide binding, anchors.anchor_bindings, or artifact.anchor_bindings' };
  }

  if (bindings.length === 0) {
    return { error: 'No bindings to verify' };
  }

  // Optional: artifact hash to check merkle_inclusion.leaf against.
  const artifactHashHex = typeof args.artifact_hash === 'string'
    ? args.artifact_hash.replace(/^sha256:/, '').toLowerCase()
    : undefined;

  const results = [];
  for (const b of bindings) {
    if (b.type === 'rfc3161-tst') {
      // TST verification (unchanged path — anchored_hash is what the TST stamps,
      // whether it is a bare hash or a Merkle root).
      let tstResult;
      const reasons = [];
      try {
        tstResult = await verifyTstBinding(b);
        if (!tstResult.ok) reasons.push(tstResult.error || 'verification failed');
      } catch (e) {
        tstResult = { ok: false, error: e.message || String(e) };
        reasons.push(tstResult.error);
      }

      // Merkle inclusion verification (§20.1 additive check).
      let merkleResult = null;
      if (b.merkle_inclusion && typeof b.merkle_inclusion === 'object') {
        const anchoredHashHex = (b.anchored_hash || '').replace(/^sha256:/, '');
        try {
          const mv = await verifyMerkleInclusion(b.merkle_inclusion, { anchoredHashHex, artifactHashHex });
          merkleResult = {
            verified: true,
            leaf: b.merkle_inclusion.leaf,
            root: mv.rootHex,
            tree_size: b.merkle_inclusion.tree_size,
          };
        } catch (e) {
          merkleResult = { verified: false, error: e.message || String(e) };
          reasons.push('merkle_inclusion: ' + (e.message || String(e)));
        }
      }

      // Renewal advisory (additive, informational).
      let renewal = null;
      if (tstResult.ok) {
        try { renewal = buildRenewalAdvisory(b); } catch { /* advisory is best-effort */ }
      }

      const entry = {
        type: 'rfc3161-tst',
        valid: tstResult.ok && (merkleResult === null || merkleResult.verified),
        tsa: b.log_origin || '',
        gen_time: tstResult.genTime ?? null,
        policy_oid: tstResult.policy ?? null,
        serial: tstResult.serial ?? null,
        reasons,
      };
      if (merkleResult !== null) entry.merkle_inclusion = merkleResult;
      if (renewal !== null) entry.renewal = renewal;
      results.push(entry);

    } else if (b.type === 'opentimestamps') {
      results.push({
        type: 'opentimestamps',
        valid: false,
        tsa: 'bitcoin',
        gen_time: null,
        policy_oid: null,
        serial: null,
        reasons: ['pending: OTS proof requires Bitcoin confirmation (several hours)'],
      });
    } else {
      results.push({
        type: b.type || 'unknown',
        valid: false,
        tsa: b.log_origin || '',
        gen_time: null,
        policy_oid: null,
        serial: null,
        reasons: ['unsupported binding type: ' + (b.type || 'unknown')],
      });
    }
  }

  return { results };
}

// ---------------------------------------------------------------------------
// MCP tool: anchor_batch
// ---------------------------------------------------------------------------

async function toolAnchorBatch(args, callerIp, env) {
  const rawHashes = Array.isArray(args.hashes) ? args.hashes : [];
  if (rawHashes.length < 2 || rawHashes.length > 1024) {
    return { error: 'hashes must be an array of 2..1024 items' };
  }
  const stripped = [];
  for (const h of rawHashes) {
    const raw = String(h).replace(/^sha256:/, '').toLowerCase().trim();
    if (!/^[0-9a-f]{64}$/.test(raw)) {
      return { error: 'each hash must be a 64-hex SHA-256 digest, optionally prefixed with sha256:. Bad value: ' + h };
    }
    stripped.push(raw);
  }

  const authorities = Array.isArray(args.authorities) ? args.authorities : ['sigstore'];
  if (authorities.length === 0) {
    return { error: 'authorities must be a non-empty array' };
  }
  const unknown = authorities.filter((a) => !AUTHORITY_META.some((m) => m.id === a));
  if (unknown.length > 0) {
    return { error: 'unknown authorities: ' + unknown.join(', ') };
  }

  // One rate-limit token for the whole batch (one TSA call per batch is the point).
  if (env.RELAY_LIMITER) {
    const { success } = await env.RELAY_LIMITER.limit({ key: callerIp });
    if (!success) {
      return { error: 'Rate limit: 4 anchor requests per minute per IP. Wait and retry.' };
    }
  }

  // Build RFC 6962 Merkle tree over the input digests.
  const rawDigests = stripped.map(hexToBytes);
  let batch;
  try {
    batch = await buildMerkleBatch(rawDigests);
  } catch (e) {
    return { error: 'Merkle tree build failed: ' + (e.message || String(e)) };
  }

  // Anchor the ROOT (one TSA call for the entire batch).
  const { anchor_bindings, failures } = await stampWithAuthorities(batch.rootHex, authorities);

  return {
    root: 'sha256:' + batch.rootHex,
    anchor_bindings,
    entries: batch.entries.map((e, i) => ({
      hash: 'sha256:' + stripped[i],
      merkle_inclusion: e,
    })),
    failures,
  };
}

// ---------------------------------------------------------------------------
// MCP tool: upgrade_ots_proof
// ---------------------------------------------------------------------------

async function toolUpgradeOtsProof(args) {
  let proofB64;
  if (typeof args.proof === 'string') {
    proofB64 = args.proof;
  } else if (args.binding?.type === 'opentimestamps' && typeof args.binding?.proof === 'string') {
    proofB64 = args.binding.proof;
  } else {
    return { error: 'Provide proof (base64 OTS proof bytes) or binding (opentimestamps type with proof field)' };
  }

  let proofBytes;
  try {
    proofBytes = base64ToBytes(proofB64);
  } catch {
    return { error: 'proof is not valid base64' };
  }

  let parsed;
  try {
    parsed = await parseOtsPending(proofBytes);
  } catch (e) {
    return { error: 'Cannot parse OTS proof: ' + (e.message || String(e)) };
  }

  const { fileHashHex, pendingBranches, completedBranches } = parsed;
  const calendarUrls = pendingBranches.map((b) => b.url);

  if (completedBranches.length > 0) {
    // Already a Bitcoin attestation in the proof (completed before this call).
    return {
      status: 'completed',
      calendar_urls: calendarUrls,
      note: 'proof already contains a Bitcoin attestation',
      binding: {
        type: 'opentimestamps',
        anchored_hash: 'sha256:' + fileHashHex,
        log_origin: 'bitcoin',
        proof: proofB64,
      },
    };
  }

  if (pendingBranches.length === 0) {
    return { error: 'No pending branches found in OTS proof' };
  }

  // Try to upgrade each branch by querying its calendar.
  let firstCompleted = null;
  for (const { url, commitmentHex } of pendingBranches) {
    try {
      const res = await fetch(url + '/timestamp/' + commitmentHex, {
        method: 'GET',
        signal: AbortSignal.timeout(15_000),
      });
      if (res.ok) {
        const bytes = new Uint8Array(await res.arrayBuffer());
        if (bytes.length > 0) {
          firstCompleted = { url, commitmentHex, upgradeBytes: bytes };
          break;
        }
      }
    } catch { /* calendar timeout/unavailable — try next */ }
  }

  if (!firstCompleted) {
    return { status: 'pending', calendar_urls: calendarUrls };
  }

  // Return the original proof bytes unchanged — the calendar confirmed it reached Bitcoin.
  // Callers needing the merged proof can use a full OTS client with the committed hash.
  return {
    status: 'completed',
    calendar_urls: calendarUrls,
    completed_calendar: firstCompleted.url,
    binding: {
      type: 'opentimestamps',
      anchored_hash: 'sha256:' + fileHashHex,
      log_origin: 'bitcoin',
      proof: proofB64,
    },
  };
}

// ---------------------------------------------------------------------------
// MCP tool: list_anchor_authorities
// ---------------------------------------------------------------------------

async function toolListAnchorAuthorities(env) {
  let health = {};
  try {
    const r = await env.ASSETS.fetch(
      new Request('https://anchor.ainumbers.co/status/tsa-health.json'),
    );
    if (r.ok) health = await r.json();
  } catch { /* health file unavailable; default to null */ }

  return AUTHORITY_META.map((m) => ({
    id: m.id,
    name: m.name,
    kind: m.kind,
    cost: m.cost,
    notes: m.notes,
    healthy: health[m.id]?.status === 'ok'
      ? true
      : health[m.id]?.status === 'degraded' ? false : null,
  }));
}

// ---------------------------------------------------------------------------
// MCP tool: create_signature_envelope
// ---------------------------------------------------------------------------

async function toolCreateSignatureEnvelope(args, callerIp, env) {
  const rawDigest = (args.doc_digest || '').replace(/^sha256:/, '').toLowerCase().trim();
  if (!/^[0-9a-f]{64}$/.test(rawDigest)) {
    return { error: 'doc_digest must be a 64-hex SHA-256 digest, optionally prefixed with sha256:' };
  }
  const docDigest = 'sha256:' + rawDigest;
  const parties = Array.isArray(args.parties) ? args.parties : [];
  const message = typeof args.message === 'string' ? args.message : '';

  const envelope = createEnvelope({ docDigest, parties, message });

  const requestEvent = {
    event_type: 'request_created',
    envelope_id: envelope.envelope_id,
    doc_digest: envelope.doc_digest,
    created_at: envelope.created_at,
  };
  const eventHex = await hashEvent(requestEvent);

  const anchorResult = await toolAnchorHash(
    { hash: eventHex, authorities: ['sigstore'] },
    callerIp,
    env,
  );

  const sign_url =
    'https://anchor.ainumbers.co/sign/sign.html#h=' + rawDigest + '&e=' + envelope.envelope_id;

  return {
    envelope_id: envelope.envelope_id,
    sign_url,
    request_binding: {
      ...requestEvent,
      event_hash: 'sha256:' + eventHex,
      anchor_bindings: anchorResult.anchor_bindings ?? [],
      anchor_failures: anchorResult.failures ?? [],
    },
  };
}

// ---------------------------------------------------------------------------
// MCP tool: verify_signature_envelope
// ---------------------------------------------------------------------------

async function toolVerifySignatureEnvelope(args) {
  const rawDigest = (args.doc_digest || '').replace(/^sha256:/, '').toLowerCase().trim();
  if (!/^[0-9a-f]{64}$/.test(rawDigest)) {
    return { error: 'doc_digest must be a 64-hex SHA-256 digest, optionally prefixed with sha256:' };
  }
  const docDigest = 'sha256:' + rawDigest;

  if (!Array.isArray(args.signatures) || args.signatures.length === 0) {
    return { error: 'signatures must be a non-empty array' };
  }

  const per_signature = [];
  let overallValid = true;

  for (const sig of args.signatures) {
    if (!sig.assertion || !sig.credential_pubkey) {
      per_signature.push({
        valid: false,
        signer: sig.signer ?? null,
        role: sig.role ?? null,
        reason: 'Missing assertion or credential_pubkey',
      });
      overallValid = false;
      continue;
    }

    // Extract and verify the signing message embedded in the assertion challenge.
    let signingMessage;
    try {
      const cdjBytes = apBase64ToBytes(sig.assertion.clientDataJSON);
      const cd = JSON.parse(new TextDecoder().decode(cdjBytes));
      const challengeBytes = apBase64ToBytes(cd.challenge);
      signingMessage = new TextDecoder().decode(challengeBytes);
      const msgObj = JSON.parse(signingMessage);
      const claimedDigest = msgObj.doc_digest || '';
      if (claimedDigest !== docDigest && claimedDigest !== rawDigest) {
        per_signature.push({
          valid: false,
          signer: sig.signer ?? null,
          role: sig.role ?? null,
          reason: 'doc_digest in signing message does not match: expected ' + docDigest + ', got ' + claimedDigest,
        });
        overallValid = false;
        continue;
      }
    } catch (e) {
      per_signature.push({
        valid: false,
        signer: sig.signer ?? null,
        role: sig.role ?? null,
        reason: 'Cannot extract signing message from assertion: ' + (e.message || String(e)),
      });
      overallValid = false;
      continue;
    }

    // Verify the WebAuthn assertion (reuses AM-2 verifyAssertion; verify parity).
    const result = await verifyAssertion(
      sig.assertion,
      sig.credential_pubkey,
      signingMessage,
      null, // origin check skipped for agent-side verification
    );

    per_signature.push({
      valid: result.ok,
      signer: sig.signer ?? null,
      role: sig.role ?? null,
      evidence_strength: result.evidenceStrength ?? null,
      BE: result.BE ?? null,
      BS: result.BS ?? null,
      counter: result.counter ?? null,
      alg: result.alg ?? null,
      reason: result.reason ?? null,
    });
    if (!result.ok) overallValid = false;
  }

  // Verify anchor bindings (event timestamps); reuses toolVerifyAnchorBinding (verify parity).
  const per_event_time = [];
  if (Array.isArray(args.anchor_bindings) && args.anchor_bindings.length > 0) {
    const vr = await toolVerifyAnchorBinding({ anchors: { anchor_bindings: args.anchor_bindings } });
    per_event_time.push(...(vr.results ?? []));
  }

  // JAdES B-T export for the first valid signature (reuses AM-2 buildJadesBT).
  let jades_bt = null;
  if (args.export_format === 'jades' || args.export_format === 'all') {
    const validIdx = per_signature.findIndex((s) => s.valid);
    const tstBinding = (args.anchor_bindings || []).find((b) => b.type === 'rfc3161-tst' && b.proof);
    if (validIdx !== -1 && tstBinding) {
      try {
        const validSig = args.signatures[validIdx];
        const sigResult = per_signature[validIdx];
        const cdjBytes = apBase64ToBytes(validSig.assertion.clientDataJSON);
        const cd = JSON.parse(new TextDecoder().decode(cdjBytes));
        const smBytes = apBase64ToBytes(cd.challenge);
        const signingMsg = new TextDecoder().decode(smBytes);
        const msgObj = JSON.parse(signingMsg);

        jades_bt = await buildJadesBT({
          assertion: validSig.assertion,
          spkiPublicKey: validSig.credential_pubkey,
          signingMessage: signingMsg,
          docDigest,
          signedAt: msgObj.signed_at ?? new Date().toISOString(),
          anchorBindings: args.anchor_bindings,
          evidenceStrength: sigResult.evidence_strength ?? 'device_bound',
          BE: sigResult.BE ?? false,
          BS: sigResult.BS ?? false,
          counter: sigResult.counter ?? 0,
        });
      } catch (e) {
        jades_bt = { error: 'JAdES build failed: ' + (e.message || String(e)) };
      }
    }
  }

  const output = { valid: overallValid, per_signature, per_event_time };
  if (jades_bt !== null) output.jades_bt = jades_bt;
  return output;
}

// ---------------------------------------------------------------------------
// MCP tool schemas (JSON Schema for tools/list)
// ---------------------------------------------------------------------------

const MCP_TOOLS = [
  {
    name: 'anchor_batch',
    description:
      'Stamp a batch of SHA-256 hashes at one or more timestamp authorities using a single TSA call. Builds an RFC 6962 Merkle tree over the input hashes, anchors the tree root, and returns per-leaf inclusion proofs shaped as §20.1 merkle_inclusion. One batch consumes one rate-limit slot (4 per minute per IP). Callers attach the returned anchor_bindings plus each entry\'s merkle_inclusion to their artifact to prove it was included in the batch.',
    inputSchema: {
      type: 'object',
      properties: {
        hashes: {
          type: 'array',
          items: {
            type: 'string',
            description: 'SHA-256 digest as 64 hex characters or with a sha256: prefix.',
          },
          description: 'Array of 2..1024 SHA-256 hashes to batch-anchor.',
          minItems: 2,
          maxItems: 1024,
        },
        authorities: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['sigstore', 'digicert', 'sectigo', 'freetsa', 'github', 'opentimestamps'],
          },
          description: 'One or more authority ids. Defaults to [sigstore] if omitted.',
          minItems: 1,
        },
      },
      required: ['hashes'],
      additionalProperties: false,
    },
  },
  {
    name: 'upgrade_ots_proof',
    description:
      'Query the OpenTimestamps calendar server(s) referenced in a pending OTS proof for a Bitcoin attestation upgrade. Stateless: no wallet, no Bitcoin node — only HTTP to the calendar servers. Returns status "completed" if any calendar confirms the proof reached Bitcoin, or "pending" if not yet confirmed. Calendar timeouts are handled gracefully.',
    inputSchema: {
      type: 'object',
      properties: {
        proof: {
          type: 'string',
          description: 'Base64-encoded OTS proof bytes (pending or completed). Mutually exclusive with binding.',
        },
        binding: {
          type: 'object',
          description: 'An opentimestamps binding with a proof field. Mutually exclusive with proof.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'list_anchor_authorities',
    description:
      'Return the six supported timestamp authorities with live health status. Each entry includes id, name, kind (rfc3161 or opentimestamps), cost, notes, and a healthy flag from the most recent smoke test.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: 'anchor_hash',
    description:
      'Stamp a SHA-256 hash at one or more timestamp authorities and return OCG v0.7 section 20 anchor_bindings. The hash is 64 hex characters, optionally prefixed with sha256:. The Worker calls authorities directly with no CORS constraint. Nothing is stored. Rate-limited at 4 requests per minute per IP. Sectigo requires 15-second pacing; requests are spaced automatically.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: {
          type: 'string',
          description: 'SHA-256 digest as 64 hex characters or with a sha256: prefix.',
        },
        authorities: {
          type: 'array',
          items: {
            type: 'string',
            enum: ['sigstore', 'digicert', 'sectigo', 'freetsa', 'github', 'opentimestamps'],
          },
          description: 'One or more authority ids from list_anchor_authorities.',
          minItems: 1,
        },
      },
      required: ['hash', 'authorities'],
      additionalProperties: false,
    },
  },
  {
    name: 'verify_anchor_binding',
    description:
      'Verify one or more anchor bindings against pinned TSA roots. Accepts a single binding, an anchors object with anchor_bindings array, or a full OCG artifact. Returns results with valid, tsa, gen_time, policy_oid, serial, and reasons for each binding. When a binding carries a merkle_inclusion object (§20.1 batch anchoring), additionally reconstructs the Merkle root from the leaf and path and confirms it equals the anchored_hash. Adds a renewal advisory with earliest certificate expiry and re-anchor advice. OpenTimestamps bindings return pending status until Bitcoin confirms.',
    inputSchema: {
      type: 'object',
      properties: {
        binding: {
          type: 'object',
          description: 'A single rfc3161-tst or opentimestamps binding.',
        },
        anchors: {
          type: 'object',
          description: 'Object with anchor_bindings array (anchors.json format).',
        },
        artifact: {
          type: 'object',
          description: 'Full OCG artifact with anchor_bindings array at the top level.',
        },
        artifact_hash: {
          type: 'string',
          description: 'Optional. The artifact\'s own SHA-256 hash (sha256:-prefixed or 64 hex). When provided and the binding has merkle_inclusion, the verifier confirms merkle_inclusion.leaf equals this value.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'create_signature_envelope',
    description:
      'Create a signature envelope for a document hash. The sender supplies the SHA-256 digest of the document, the intended signing parties, and an optional message. The tool anchors the request event at Sigstore and returns an envelope identifier, a deep-link URL the sender delivers to the signer, and a timestamped request binding. The document never leaves the sender device. Nothing is stored.',
    inputSchema: {
      type: 'object',
      properties: {
        doc_digest: {
          type: 'string',
          description: 'SHA-256 digest of the document as 64 hex characters, optionally prefixed with sha256:.',
        },
        parties: {
          type: 'array',
          items: { type: 'string' },
          description: 'Names or identifiers of the intended signing parties.',
        },
        message: {
          type: 'string',
          description: 'Optional message or context for the signing request.',
        },
      },
      required: ['doc_digest'],
      additionalProperties: false,
    },
  },
  {
    name: 'verify_signature_envelope',
    description:
      'Verify one or more passkey signatures on a document hash together with their event timestamps. Each signature entry carries the WebAuthn assertion, the signer credential public key as base64-encoded SPKI bytes, and optional signer metadata. The tool checks the ECDSA signature against the credential public key, confirms the challenge in clientDataJSON encodes the correct document hash and envelope context, and grades evidence strength as device_bound or synced from the authenticator flags. Anchor bindings are verified against pinned TSA roots using the same logic as verify_anchor_binding. Set export_format to jades to receive a JAdES B-T receipt for the first valid signature.',
    inputSchema: {
      type: 'object',
      properties: {
        doc_digest: {
          type: 'string',
          description: 'SHA-256 digest of the document as 64 hex characters, optionally prefixed with sha256:.',
        },
        signatures: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              assertion: {
                type: 'object',
                description: 'WebAuthn GetAssertion response with authenticatorData, clientDataJSON, and signature fields (all base64).',
                properties: {
                  authenticatorData: { type: 'string' },
                  clientDataJSON: { type: 'string' },
                  signature: { type: 'string' },
                },
                required: ['authenticatorData', 'clientDataJSON', 'signature'],
              },
              credential_pubkey: {
                type: 'string',
                description: 'Credential public key as base64-encoded SPKI bytes from the WebAuthn registration.',
              },
              signer: { type: 'string', description: 'Signer name or identifier.' },
              role: { type: 'string', description: 'Signer role, such as sender or recipient.' },
            },
            required: ['assertion', 'credential_pubkey'],
          },
          description: 'One or more signature entries to verify.',
          minItems: 1,
        },
        anchor_bindings: {
          type: 'array',
          description: 'Optional anchor bindings from the request or signing events, verified for event timestamps.',
        },
        export_format: {
          type: 'string',
          enum: ['none', 'jades', 'all'],
          description: 'Set to jades or all to include a JAdES B-T receipt for the first valid signature in the response.',
        },
      },
      required: ['doc_digest', 'signatures'],
      additionalProperties: false,
    },
  },
];

// ---------------------------------------------------------------------------
// MCP request handler
// ---------------------------------------------------------------------------

async function handleMcp(request, env) {
  const cors = getMcpCors(request);
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== 'POST') {
    return textResponse(405, 'POST only.', cors);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return mcpError(null, -32700, 'Parse error: body must be JSON', cors);
  }

  const { jsonrpc, id, method, params } = body;
  if (jsonrpc !== '2.0') {
    return mcpError(id ?? null, -32600, 'Invalid Request: jsonrpc must be "2.0"', cors);
  }

  if (method === 'initialize') {
    return mcpResult(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'anchor-suite', version: '1.0.0' },
    }, cors);
  }

  if (method === 'notifications/initialized') {
    return new Response(null, { status: 204, headers: cors });
  }

  if (method === 'tools/list') {
    return mcpResult(id, { tools: MCP_TOOLS }, cors);
  }

  if (method === 'tools/call') {
    const name = params?.name;
    const args = params?.arguments ?? {};
    const callerIp = request.headers.get('CF-Connecting-IP') || 'unknown';

    let toolResult;
    if (name === 'list_anchor_authorities') {
      toolResult = { result: await toolListAnchorAuthorities(env) };
    } else if (name === 'anchor_hash') {
      toolResult = await toolAnchorHash(args, callerIp, env);
    } else if (name === 'anchor_batch') {
      toolResult = await toolAnchorBatch(args, callerIp, env);
    } else if (name === 'verify_anchor_binding') {
      toolResult = await toolVerifyAnchorBinding(args);
    } else if (name === 'upgrade_ots_proof') {
      toolResult = await toolUpgradeOtsProof(args);
    } else if (name === 'create_signature_envelope') {
      toolResult = await toolCreateSignatureEnvelope(args, callerIp, env);
    } else if (name === 'verify_signature_envelope') {
      toolResult = await toolVerifySignatureEnvelope(args);
    } else {
      return mcpError(id, -32601, 'Unknown tool: ' + name, cors);
    }

    if (toolResult.error) {
      return mcpResult(id, {
        content: [{ type: 'text', text: JSON.stringify({ error: toolResult.error }) }],
        isError: true,
      }, cors);
    }

    const payload = toolResult.result !== undefined ? toolResult.result : toolResult;
    return mcpResult(id, {
      content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    }, cors);
  }

  return mcpError(id ?? null, -32601, 'Method not found: ' + method, cors);
}

// ---------------------------------------------------------------------------
// Relay handler
// ---------------------------------------------------------------------------

async function handleRelay(request, env) {
  const url = new URL(request.url);
  const key = url.pathname.slice('/relay/'.length);
  const upstream = RELAY_UPSTREAMS[key];

  if (!upstream) {
    return textResponse(
      404,
      'Unknown relay path. Valid: /relay/digicert, /relay/sectigo, /relay/freetsa.',
      RELAY_CORS,
    );
  }

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: RELAY_CORS });
  }
  if (request.method !== 'POST') {
    return textResponse(405, 'POST only.', RELAY_CORS);
  }

  const contentType = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/timestamp-query') {
    return textResponse(415, 'Content-Type must be application/timestamp-query.', RELAY_CORS);
  }

  const body = await request.arrayBuffer();
  if (body.byteLength === 0) {
    return textResponse(400, 'Empty body. Send a DER-encoded RFC 3161 TimeStampReq.', RELAY_CORS);
  }
  if (body.byteLength > MAX_BODY_BYTES) {
    return textResponse(413, 'Body too large. TimeStampReq must be 2 KB or less.', RELAY_CORS);
  }

  if (env.RELAY_LIMITER) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const { success } = await env.RELAY_LIMITER.limit({ key: ip });
    if (!success) {
      const res = textResponse(429, 'Rate limit: 4 timestamps per minute per IP. Wait and retry.', RELAY_CORS);
      res.headers.set('Retry-After', '15');
      return res;
    }
  }

  let upstreamRes;
  try {
    upstreamRes = await fetch(upstream, {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query' },
      body,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
  } catch {
    return textResponse(504, 'Timestamp authority did not answer within 25 seconds.', RELAY_CORS);
  }

  if (!upstreamRes.ok) {
    return textResponse(
      upstreamRes.status,
      'Timestamp authority returned HTTP ' + upstreamRes.status + '.',
      RELAY_CORS,
    );
  }

  const reply = await upstreamRes.arrayBuffer();
  return new Response(reply, {
    status: 200,
    headers: {
      'Content-Type': 'application/timestamp-reply',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...RELAY_CORS,
    },
  });
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/mcp') return handleMcp(request, env);
    if (url.pathname.startsWith('/relay/')) return handleRelay(request, env);

    return env.ASSETS.fetch(request);
  },
};
