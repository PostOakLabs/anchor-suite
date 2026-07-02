// tst.js — shared RFC 3161 TST helpers for anchor.html and verify.html.
// No framework, no build step. Imports pkijs + pinned roots from vendor/.
// Only function that touches the network: none. All callers supply DER bytes.

import { pkijs, asn1js } from '/vendor/pkijs.bundle.mjs';
import { PINNED_ROOTS, PINNED_CHAINS } from '/vendor/roots/roots.mjs';

// Tell pkijs to use the browser's native WebCrypto (ECDSA P-384 + RSA both work).
pkijs.setEngine('webcrypto', new pkijs.CryptoEngine({ name: 'webcrypto', crypto: globalThis.crypto }));

export const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
export const OID_EKU = '2.5.29.37';
export const OID_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';

// ---- byte helpers --------------------------------------------------------

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

// ---- PEM helpers ----------------------------------------------------------

export function pemToCert(block) {
  const b64 = block.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s/g, '');
  const der = base64ToBytes(b64);
  return new pkijs.Certificate({ schema: asn1js.fromBER(new Uint8Array(der).buffer).result });
}

export function pemToCerts(text) {
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  return blocks.map(pemToCert);
}

// Stringify a RelativeDistinguishedName for subject comparison (cross-signed root removal).
export function dnOf(rdn) {
  return rdn.typesAndValues.map((t) => `${t.type}=${t.value.valueBlock.value}`).join('|');
}

// ---- nonce generation -----------------------------------------------------

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

// ---- TSQ building ---------------------------------------------------------

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

// ---- authority detection --------------------------------------------------

export function detectAuthority(logOrigin) {
  if (!logOrigin) return null;
  const u = logOrigin.toLowerCase();
  if (u.includes('sigstore.dev')) return 'sigstore';
  if (u.includes('githubapp.com')) return 'github';
  if (u.includes('digicert.com')) return 'digicert';
  if (u.includes('sectigo.com')) return 'sectigo';
  if (u.includes('freetsa.org')) return 'freetsa';
  return null;
}

// ---- TST parsing (common to anchor and verify) ----------------------------

// Parse a DER TimeStampResp or TimeStampToken and return { signed, tstInfo, tstInfoDer }.
//
// pkijs.ContentInfo.content returns a raw asn1js Sequence (not a parsed SignedData)
// in the browser bundle, so we navigate the ASN.1 tree directly.
//
// Two wire formats:
//   TimeStampResp  = SEQUENCE { PKIStatusInfo, ContentInfo }  (relay CAs, GitHub)
//   TimeStampToken = ContentInfo = SEQUENCE { OID, [0] { SignedData } }  (Sigstore JSON API)
//
// Detect by first child: ObjectIdentifier → ContentInfo; Sequence → TimeStampResp.
export function parseTstDer(derBytes) {
  let tsrAsn;
  try {
    const parsed = asn1js.fromBER(new Uint8Array(derBytes).buffer);
    if (parsed.offset === -1) throw new Error('ASN.1 decode failed');
    tsrAsn = parsed.result;
  } catch (e) {
    throw new Error('Not a valid DER timestamp token: ' + e.message);
  }

  let sdAsn;
  const firstChild = tsrAsn.valueBlock.value[0];
  if (firstChild.constructor.name === 'ObjectIdentifier') {
    // ContentInfo format: SEQUENCE { OID, [0] EXPLICIT { SignedData } }
    sdAsn = tsrAsn.valueBlock.value[1].valueBlock.value[0];
  } else {
    // TimeStampResp format: SEQUENCE { PKIStatusInfo, ContentInfo { OID, [0]{ SignedData } } }
    const statusInt = firstChild.valueBlock.value[0].valueBlock.valueDec;
    if (![0, 1].includes(statusInt)) {
      throw new Error('TSA refused the request (PKIStatus ' + statusInt + ')');
    }
    const ciAsn = tsrAsn.valueBlock.value[1];
    sdAsn = ciAsn.valueBlock.value[1].valueBlock.value[0];
  }

  let signed;
  try {
    signed = new pkijs.SignedData({ schema: sdAsn });
  } catch (e) {
    throw new Error('Could not parse SignedData: ' + e.message);
  }

  const eContent = signed.encapContentInfo?.eContent;
  if (!eContent) throw new Error('SignedData missing encapContentInfo.eContent');
  const tstInfoDer = new Uint8Array(eContent.valueBlock.valueHexView);

  let tstInfo;
  try {
    tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(tstInfoDer.buffer).result });
  } catch (e) {
    throw new Error('Could not parse TSTInfo: ' + e.message);
  }

  return { signed, tstInfo, tstInfoDer };
}

// Extract anchor_binding metadata from a parsed TST.
export function extractTstMeta(tstInfo, signed) {
  const serial = bytesHex(new Uint8Array(tstInfo.serialNumber.valueBlock.valueHexView));
  const genTime = tstInfo.genTime.toISOString();
  const policyOid = tstInfo.policy;
  const certs = signed.certificates || [];
  const signer_cert_chain_b64 = certs.map((c) => {
    const der = c.toSchema().toBER(false);
    return bytesToBase64(new Uint8Array(der));
  });
  return { serial, gen_time: genTime, policy_oid: policyOid, signer_cert_chain_b64 };
}

// ---- Full TST verification (used by verify.js) ----------------------------
//
// Strategy:
//   1. Parse DER → TSTInfo.
//   2. Check messageImprint against expectedHashHex (our primary responsibility).
//   3. Drop cross-signed root certs from token chain (DigiCert/Sectigo gotcha).
//   4. Call signed.verify() passing tstInfoDer as `data` so pkijs can confirm the
//      CMS message-digest signed attribute matches hash(tstInfoDer), then verify
//      the RSA/ECDSA signature and chain to the pinned root.
//   5. Check id-kp-timeStamping EKU on signer cert.
//
// Returns { ok:true, genTime, policy, serial, authority } or { ok:false, error }.

export async function verifyTstBinding(binding) {
  const hashHex = (binding.anchored_hash || '').replace('sha256:', '');
  if (!hashHex || hashHex.length !== 64) {
    return { ok: false, error: 'Missing or malformed anchored_hash' };
  }

  let derBytes;
  try {
    derBytes = base64ToBytes(binding.proof);
  } catch (e) {
    return { ok: false, error: 'proof is not valid base64' };
  }

  let signed, tstInfo, tstInfoDer;
  try {
    ({ signed, tstInfo, tstInfoDer } = parseTstDer(derBytes));
  } catch (e) {
    return { ok: false, error: e.message };
  }

  // Step 2 — imprint check (hash-only, no original message needed)
  const imprint = bytesHex(new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView));
  if (imprint !== hashHex) {
    return { ok: false, error: `Hash mismatch: token stamps ${imprint}, receipt claims ${hashHex}` };
  }

  // Step 3 — select root
  const authority = detectAuthority(binding.log_origin);
  if (!authority || !PINNED_ROOTS[authority]) {
    return { ok: false, error: 'Unknown authority; no pinned root: ' + binding.log_origin };
  }
  const root = pemToCert(PINNED_ROOTS[authority]);
  const rootSubject = dnOf(root.subject);

  let tokenCerts = (signed.certificates || []).filter((c) => dnOf(c.subject) !== rootSubject);
  if (PINNED_CHAINS[authority]) {
    const extras = pemToCerts(PINNED_CHAINS[authority]).filter((c) => dnOf(c.subject) !== rootSubject);
    tokenCerts = [...tokenCerts, ...extras];
  }
  signed.certificates = tokenCerts;

  // Step 4 — CMS signature + chain.
  // pkijs.SignedData.verify() has a TSTInfo-specific branch: when eContentType =
  // id-ct-TSTInfo, it calls tstInfo.verify({ data }) expecting the original pre-hash
  // bytes (not the hash). We only have the hash, so that branch can't pass. Imprint
  // was already verified manually in step 2. Temporarily swap eContentType to bypass
  // the TSTInfo branch; pkijs still validates the CMS messageDigest + signature over
  // signedAttrs + cert chain against the pinned root.
  const origType = signed.encapContentInfo.eContentType;
  signed.encapContentInfo.eContentType = '1.2.840.113549.1.7.1'; // id-data
  let result;
  try {
    result = await signed.verify({
      signer: 0,
      trustedCerts: [root],
      extendedMode: true,
      checkChain: true,
    });
  } catch (e) {
    return { ok: false, error: 'CMS verification failed: ' + (e?.message || String(e)) };
  } finally {
    signed.encapContentInfo.eContentType = origType;
  }

  if (!result.signatureVerified) {
    return { ok: false, error: 'CMS signature is not valid' };
  }

  // Step 5 — EKU
  const signerCert = result.signerCertificate;
  const eku = (signerCert.extensions || []).find((x) => x.extnID === OID_EKU);
  if (!eku?.parsedValue?.keyPurposes?.includes(OID_TIMESTAMPING)) {
    return { ok: false, error: 'Signer certificate lacks id-kp-timeStamping EKU' };
  }

  return {
    ok: true,
    genTime: tstInfo.genTime.toISOString(),
    policy: tstInfo.policy,
    serial: bytesHex(new Uint8Array(tstInfo.serialNumber.valueBlock.valueHexView)),
    authority,
  };
}
