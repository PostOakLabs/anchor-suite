// anchorproof.mjs — Anchorproof core: hash, envelope, WebAuthn sign/verify, evidence grading.
// reused by AM-3 MCP tools

// ---- Byte utilities ----------------------------------------------------------

export function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64.replace(/[\r\n\s]/g, '').replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64urlToBytes(b64url) {
  return base64ToBytes(b64url.replace(/-/g, '+').replace(/_/g, '/'));
}

export function bytesHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex) {
  const h = hex.replace(/^sha256:/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// ---- Random IDs --------------------------------------------------------------

export function randomId() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return bytesHex(bytes);
}

// ---- Local document hashing (browser + Node.js) -----------------------------

export async function hashFileBuffer(arrayBuffer) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', arrayBuffer);
  return bytesHex(new Uint8Array(digest));
}

export async function hashBytes(bytes) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return bytesHex(new Uint8Array(digest));
}

export async function hashText(str) {
  const bytes = new TextEncoder().encode(str);
  return hashBytes(bytes);
}

// ---- Envelope ----------------------------------------------------------------

export function createEnvelope({ docDigest, parties = [], message = '' }) {
  const digest = docDigest.startsWith('sha256:') ? docDigest : 'sha256:' + docDigest;
  return {
    envelope_id: randomId(),
    doc_digest: digest,
    parties,
    message,
    created_at: new Date().toISOString(),
  };
}

// Build the canonical signing message for a signer.
// This JSON string becomes the WebAuthn challenge.
export function buildSigningMessage(envelope, role) {
  return JSON.stringify({
    doc_digest: envelope.doc_digest,
    envelope_id: envelope.envelope_id,
    role,
    signed_at: new Date().toISOString(),
  });
}

// Convert a signing message string to a Uint8Array challenge for WebAuthn.
export function messageToChallenge(messageJson) {
  return new TextEncoder().encode(messageJson);
}

// ---- Event hashing (for anchoring) ------------------------------------------

export async function hashEvent(eventObj) {
  const json = JSON.stringify(eventObj);
  return hashText(json);
}

// ---- WebAuthn passkey operations (browser only) ------------------------------

// Create a new signing credential using MakeCredential.
// The credential public key (SPKI) is returned for later verification.
// challenge: a random challenge (not the signing message; just freshness).
export async function createSigningCredential(rpId, displayName, challenge) {
  const userId = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const challengeBytes = typeof challenge === 'string'
    ? new TextEncoder().encode(challenge)
    : challenge;

  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: challengeBytes,
      rp: { id: rpId, name: 'Anchorproof' },
      user: {
        id: userId,
        name: displayName || 'signer',
        displayName: displayName || 'Signer',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256 (P-256)
        { type: 'public-key', alg: -257 },  // RS256 fallback
      ],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'preferred',
      },
      timeout: 120000,
    },
  });

  const spkiBuffer = cred.response.getPublicKey();
  const alg = cred.response.getPublicKeyAlgorithm();
  const authData = new Uint8Array(cred.response.getAuthenticatorData());
  const aaguid = extractAaguid(authData);
  const { BE, BS } = readAuthDataFlags(authData);

  return {
    credentialId: bytesToBase64url(new Uint8Array(cred.rawId)),
    spkiPublicKey: bytesToBase64(new Uint8Array(spkiBuffer)),
    alg,
    aaguid,
    BE,
    BS,
  };
}

// Sign a message with an existing passkey using GetAssertion.
// messageJson becomes the WebAuthn challenge; clientDataJSON.challenge verifies it.
export async function signMessage(credentialIdBase64url, messageJson, rpId) {
  const credIdBytes = base64urlToBytes(credentialIdBase64url);
  const challenge = messageToChallenge(messageJson);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: credIdBytes.buffer, type: 'public-key' }],
      userVerification: 'required',
      rpId,
      timeout: 120000,
    },
  });

  const authData = new Uint8Array(assertion.response.authenticatorData);
  const cdj = new Uint8Array(assertion.response.clientDataJSON);
  const sig = new Uint8Array(assertion.response.signature);
  const { evidenceStrength, BE, BS, counter } = gradeEvidenceStrength(authData);

  return {
    credentialId: credentialIdBase64url,
    authenticatorData: bytesToBase64(authData),
    clientDataJSON: bytesToBase64(cdj),
    signature: bytesToBase64(sig),
    evidenceStrength,
    BE,
    BS,
    counter,
  };
}

// ---- Evidence-strength grading -----------------------------------------------

// Read the WebAuthn authenticatorData flags byte (offset 32).
export function readAuthDataFlags(authDataBytes) {
  const flags = authDataBytes[32];
  return {
    UP: !!(flags & 0x01),
    UV: !!(flags & 0x04),
    BE: !!(flags & 0x08),  // Backup Eligible
    BS: !!(flags & 0x10),  // Backup State (currently synced)
    AT: !!(flags & 0x40),  // Attested credential data
    ED: !!(flags & 0x80),  // Extension data
  };
}

// Grade evidence strength from authenticatorData bytes.
// device_bound: key cannot be cloned (BE=0) or not yet synced (BE=1, BS=0)
// synced: key is a cloud passkey, cloneable by design (BE=1, BS=1)
export function gradeEvidenceStrength(authDataBytes) {
  const { BE, BS } = readAuthDataFlags(authDataBytes);
  const counter = new DataView(
    authDataBytes.buffer,
    authDataBytes.byteOffset + 33,
    4,
  ).getUint32(0, false);
  return {
    evidenceStrength: (BE && BS) ? 'synced' : 'device_bound',
    BE,
    BS,
    counter,
  };
}

// Extract AAGUID from authenticatorData (only present when AT flag is set).
// Returns a UUID-formatted string, or null.
export function extractAaguid(authDataBytes) {
  const { AT } = readAuthDataFlags(authDataBytes);
  if (!AT || authDataBytes.length < 53) return null;
  const hex = bytesHex(authDataBytes.slice(37, 53));
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ---- DER ECDSA to P1363 format -----------------------------------------------

// SubtleCrypto ECDSA verify expects raw P1363 format (r||s, each coordBytes wide).
// WebAuthn assertions carry DER-encoded signatures (SEQUENCE { INTEGER r, INTEGER s }).
export function derEcdsaToP1363(der, coordBytes = 32) {
  let off = 0;
  if (der[off++] !== 0x30) throw new Error('Expected SEQUENCE tag 0x30');
  // Skip sequence length (may be multi-byte BER)
  if (der[off] & 0x80) { const n = der[off] & 0x7f; off += 1 + n; } else { off++; }

  function readInt() {
    if (der[off++] !== 0x02) throw new Error('Expected INTEGER tag 0x02');
    let len;
    if (der[off] & 0x80) {
      const n = der[off] & 0x7f; off++;
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | der[off++];
    } else { len = der[off++]; }
    let bytes = der.slice(off, off + len);
    off += len;
    while (bytes.length > coordBytes && bytes[0] === 0) bytes = bytes.slice(1);
    return bytes;
  }

  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(coordBytes * 2);
  out.set(r, coordBytes - r.length);
  out.set(s, coordBytes * 2 - s.length);
  return out;
}

// ---- Assertion verification (browser + Node.js) ------------------------------

// Verify a WebAuthn GetAssertion response against a stored credential public key.
//
// assertion: { authenticatorData (base64), clientDataJSON (base64), signature (base64) }
// spkiBase64: credential public key as base64-encoded SPKI bytes
// expectedMessage: the original signing message JSON string (was the challenge)
// expectedOrigin: e.g. "https://anchor.ainumbers.co" (null to skip origin check)
//
// Returns { ok, evidenceStrength, BE, BS, counter, alg } or { ok:false, reason }
export async function verifyAssertion(assertion, spkiBase64, expectedMessage, expectedOrigin) {
  const authData = base64ToBytes(assertion.authenticatorData);
  const cdj = base64ToBytes(assertion.clientDataJSON);
  const sig = base64ToBytes(assertion.signature);
  const spki = base64ToBytes(spkiBase64);

  // Validate clientDataJSON
  let cd;
  try { cd = JSON.parse(new TextDecoder().decode(cdj)); }
  catch { return { ok: false, reason: 'Cannot parse clientDataJSON' }; }

  if (cd.type !== 'webauthn.get') {
    return { ok: false, reason: `clientDataJSON.type must be "webauthn.get", got "${cd.type}"` };
  }
  if (expectedOrigin && cd.origin !== expectedOrigin) {
    return { ok: false, reason: `Origin mismatch: expected "${expectedOrigin}", got "${cd.origin}"` };
  }

  // clientDataJSON.challenge must be base64url(utf8(expectedMessage))
  const expectedChallB64url = bytesToBase64url(new TextEncoder().encode(expectedMessage));
  if (cd.challenge !== expectedChallB64url) {
    return { ok: false, reason: 'Challenge mismatch: signed message does not match' };
  }

  // verifyData = authenticatorData || SHA-256(clientDataJSON)
  const cdjHash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', cdj));
  const verifyData = concatBytes(authData, cdjHash);

  // Try EC P-256 first (ES256), then RSA (RS256 fallback)
  const keyAttempts = [
    { import: { name: 'ECDSA', namedCurve: 'P-256' }, verify: { name: 'ECDSA', hash: 'SHA-256' }, p1363: true, algName: 'ES256' },
    { import: { name: 'ECDSA', namedCurve: 'P-384' }, verify: { name: 'ECDSA', hash: 'SHA-384' }, p1363: true, algName: 'ES384' },
    { import: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verify: { name: 'RSASSA-PKCS1-v1_5' }, p1363: false, algName: 'RS256' },
  ];

  for (const kp of keyAttempts) {
    let key;
    try { key = await globalThis.crypto.subtle.importKey('spki', spki.buffer, kp.import, false, ['verify']); }
    catch { continue; }

    let sigBytes = sig;
    if (kp.p1363) {
      try { sigBytes = derEcdsaToP1363(sig, kp.algName === 'ES384' ? 48 : 32); }
      catch { sigBytes = sig; }
    }

    try {
      const valid = await globalThis.crypto.subtle.verify(kp.verify, key, sigBytes, verifyData);
      if (!valid) return { ok: false, reason: 'Signature invalid' };
      const { evidenceStrength, BE, BS, counter } = gradeEvidenceStrength(authData);
      return { ok: true, evidenceStrength, BE, BS, counter, alg: kp.algName };
    } catch (e) {
      return { ok: false, reason: 'Verify error: ' + e.message };
    }
  }

  return { ok: false, reason: 'Cannot import credential public key (unsupported algorithm)' };
}

// ---- SPKI to JWK (for JAdES receipt) -----------------------------------------

export async function spkiToJwk(spkiBase64) {
  const spki = base64ToBytes(spkiBase64);
  for (const params of [
    { name: 'ECDSA', namedCurve: 'P-256' },
    { name: 'ECDSA', namedCurve: 'P-384' },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  ]) {
    try {
      const key = await globalThis.crypto.subtle.importKey('spki', spki.buffer, params, true, ['verify']);
      return globalThis.crypto.subtle.exportKey('jwk', key);
    } catch { continue; }
  }
  throw new Error('Cannot import SPKI key: unsupported algorithm');
}

// ---- Anchor event via /mcp --------------------------------------------------

// Hash an event object and anchor it via anchor_hash.
// Returns { event_hash, anchor_bindings, failures }
export async function anchorEvent(eventObj, authorities, mcpBase = '') {
  const eventHex = await hashEvent(eventObj);
  const body = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: 'anchor_hash',
      arguments: { hash: eventHex, authorities },
    },
  };

  const res = await fetch(mcpBase + '/mcp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) throw new Error('MCP request failed: HTTP ' + res.status);
  const json = await res.json();
  if (json.error) throw new Error('MCP error: ' + json.error.message);

  const text = json.result?.content?.[0]?.text;
  if (!text) throw new Error('Unexpected MCP response shape');
  const result = JSON.parse(text);

  return {
    event_hash: 'sha256:' + eventHex,
    anchor_bindings: result.anchor_bindings || [],
    failures: result.failures || [],
  };
}
