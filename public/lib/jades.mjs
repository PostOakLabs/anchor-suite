// jades.mjs — JAdES B-T receipt builder and verifier.
//
// JAdES B-T (ETSI TS 119 182-1) is the JSON member of the eIDAS AdES family,
// built on JWS/JOSE. B-T = a signature plus a trusted RFC 3161 timestamp
// proving it existed at an attested time.
//
// Anchorproof adaptation: the signing key is a WebAuthn passkey credential,
// not a CA-issued certificate. The signature field carries the authenticator's
// ECDSA assertion. Standard JWS signature input (base64url(protected).base64url(payload))
// does NOT apply; instead verify: ECDSA over authenticatorData||SHA-256(clientDataJSON)
// where clientDataJSON.challenge == base64url(payload). This is documented in
// header.anchorproof.verificationNote and is explicit in every receipt.
//
// reused by AM-3 MCP tools

import {
  bytesToBase64, base64ToBytes, bytesToBase64url, base64urlToBytes,
  hexToBytes, spkiToJwk, verifyAssertion,
} from './anchorproof.mjs';

// Build a JAdES B-T receipt.
//
// params:
//   assertion        { authenticatorData, clientDataJSON, signature } (all base64)
//   spkiPublicKey    base64 SPKI bytes of the credential public key
//   signingMessage   the original message JSON string that was signed
//   docDigest        "sha256:<hex>" for the document
//   signedAt         ISO-8601 signing time
//   anchorBindings   array of v0.7 §20 anchor_bindings for this event
//   evidenceStrength 'device_bound' | 'synced'
//   BE, BS, counter  evidence detail fields
//
// Returns a JAdES B-T object in JWS JSON Serialization.
export async function buildJadesBT(params) {
  const {
    assertion,
    spkiPublicKey,
    signingMessage,
    docDigest = '',
    signedAt,
    anchorBindings = [],
    evidenceStrength = 'device_bound',
    BE = false,
    BS = false,
    counter = 0,
  } = params;

  const jwk = await spkiToJwk(spkiPublicKey);

  // Map JWK to JOSE alg string
  let alg = 'ES256';
  if (jwk.kty === 'RSA') alg = 'RS256';
  else if (jwk.crv === 'P-384') alg = 'ES384';

  // Encode document digest for sigD (omit if absent)
  const docDigestHex = docDigest.replace(/^sha256:/, '');
  const sigDEntry = docDigestHex ? [{
    sigD: {
      mId: 'http://uri.etsi.org/19182/ObjectIdByURLHash',
      pars: [{
        uri: 'urn:anchorproof:document',
        hashValue: bytesToBase64url(hexToBytes(docDigestHex)),
        hashM: 'S256',
      }],
    },
  }] : [];

  // Protected header: JAdES B baseline signed properties
  const protectedHeader = {
    alg,
    typ: 'jose+json',
    jwk,
    etsiU: [
      { sigT: { val: signedAt } },
      ...sigDEntry,
    ],
  };

  const protectedB64url = bytesToBase64url(new TextEncoder().encode(JSON.stringify(protectedHeader)));
  const payloadB64url = bytesToBase64url(new TextEncoder().encode(signingMessage));

  // The signature bytes are the raw ECDSA assertion from the authenticator.
  // Verification uses the WebAuthn assertion check, not standard JWS.
  const signatureB64url = bytesToBase64url(base64ToBytes(assertion.signature));

  // Collect RFC 3161 TST tokens from anchor_bindings
  const tstTokens = anchorBindings
    .filter((b) => b.type === 'rfc3161-tst' && b.proof)
    .map((b) => ({ val: bytesToBase64url(base64ToBytes(b.proof)) }));

  // Unprotected header: Anchorproof WebAuthn data + JAdES B-T unsigned props
  const unprotectedHeader = {
    anchorproof: {
      version: '1',
      verificationNote:
        'WebAuthn assertion. Verify ECDSA over authenticatorData||SHA-256(clientDataJSON) using the jwk in the protected header. clientDataJSON.challenge must equal base64url(payload).',
      authenticatorData: assertion.authenticatorData,
      clientDataJSON: assertion.clientDataJSON,
      evidenceStrength,
      BE,
      BS,
      counter,
    },
    ...(tstTokens.length > 0 ? {
      etsiU: [{ sigTst: { tstTokens } }],
    } : {}),
  };

  return {
    payload: payloadB64url,
    protected: protectedB64url,
    header: unprotectedHeader,
    signature: signatureB64url,
  };
}

// Verify the WebAuthn assertion in a JAdES B-T receipt.
// TST verification is done separately by verify-runner.mjs (verify parity).
//
// Returns { ok, signatureResult, tstCount, evidenceStrength, reason? }
export async function verifyJadesBT(jades, expectedOrigin) {
  // Decode protected header
  let protectedHeader;
  try {
    const protectedJson = new TextDecoder().decode(base64urlToBytes(jades.protected));
    protectedHeader = JSON.parse(protectedJson);
  } catch {
    return { ok: false, reason: 'Cannot decode protected header' };
  }

  // Extract Anchorproof-specific assertion data from unprotected header
  const ap = jades.header?.anchorproof;
  if (!ap) return { ok: false, reason: 'Missing anchorproof data in header' };

  // The payload is the signing message
  let signingMessage;
  try {
    signingMessage = new TextDecoder().decode(base64urlToBytes(jades.payload));
  } catch {
    return { ok: false, reason: 'Cannot decode payload' };
  }

  // Re-derive SPKI from the JWK in the protected header
  let spkiBase64;
  try {
    const importParams = protectedHeader.alg === 'ES256'
      ? { name: 'ECDSA', namedCurve: 'P-256' }
      : protectedHeader.alg === 'ES384'
        ? { name: 'ECDSA', namedCurve: 'P-384' }
        : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };

    const key = await globalThis.crypto.subtle.importKey('jwk', protectedHeader.jwk, importParams, true, ['verify']);
    const spkiBuffer = await globalThis.crypto.subtle.exportKey('spki', key);
    spkiBase64 = bytesToBase64(new Uint8Array(spkiBuffer));
  } catch (e) {
    return { ok: false, reason: 'Cannot import JWK from protected header: ' + e.message };
  }

  // Verify the WebAuthn assertion
  const sigResult = await verifyAssertion(
    {
      authenticatorData: ap.authenticatorData,
      clientDataJSON: ap.clientDataJSON,
      signature: bytesToBase64(base64urlToBytes(jades.signature)),
    },
    spkiBase64,
    signingMessage,
    expectedOrigin || null,
  );

  const tstCount = (jades.header?.etsiU || [])
    .flatMap((e) => e.sigTst?.tstTokens || [])
    .length;

  return {
    ok: sigResult.ok,
    signatureResult: sigResult,
    tstCount,
    evidenceStrength: ap.evidenceStrength,
    reason: sigResult.reason || null,
  };
}
