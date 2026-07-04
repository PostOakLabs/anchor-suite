// tsq.mjs — shared TimeStampReq builder. Imported by the browser (anchor.js)
// and the Worker (src/worker.mjs). Single canonical implementation; no fork.
//
// Functions here cover only building — byte helpers, nonce generation, DER TSQ
// construction, and the Sigstore JSON request shape. Parsing and verification
// live in tst.js (which imports from here) so they share the same pkijs setup.

import { pkijs, asn1js } from '../vendor/pkijs.bundle.mjs';

pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({ name: 'webcrypto', crypto: globalThis.crypto }));

export const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

// ---- byte helpers -----------------------------------------------------------

export function hexToBytes(hex) {
  const h = hex.replace(/^sha256:/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function bytesToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64ToBytes(b64) {
  const bin = atob(b64.replace(/[\r\n\s]/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---- nonce generation -------------------------------------------------------

export function freshNonce(byteLen = 8) {
  const n = new Uint8Array(byteLen);
  crypto.getRandomValues(n);
  n[0] &= 0x7f; // ensure the DER INTEGER is positive
  return n;
}

// 6-byte nonce that safely fits in a JS Number (for Sigstore JSON).
export function freshNonce6() {
  const n = new Uint8Array(6);
  crypto.getRandomValues(n);
  n[0] &= 0x7f;
  return n;
}

// ---- DER TimeStampReq builder -----------------------------------------------

export function buildTsqDer(hashBytes, nonceBytes) {
  const tsq = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({
        algorithmId: OID_SHA256,
        algorithmParams: new asn1js.Null(),
      }),
      hashedMessage: new asn1js.OctetString({ valueHex: hashBytes.buffer }),
    }),
    nonce: new asn1js.Integer({ valueHex: nonceBytes.buffer }),
    certReq: true,
  });
  return tsq.toSchema().toBER(false);
}

// ---- Sigstore JSON request body builder ------------------------------------

export function buildSigstoreBody(hashBytes, nonceNum) {
  return JSON.stringify({
    artifactHash: bytesToBase64(hashBytes),
    hashAlgorithm: 'sha256',
    nonce: nonceNum,
    certificates: true,
  });
}
