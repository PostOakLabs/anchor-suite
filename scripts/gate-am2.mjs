// gate-am2.mjs — Anchorproof AM-2 end-to-end gate.
// Tests: byte utils, hashing, envelope, evidence-strength, DER<->P1363,
// verifyAssertion (device_bound + synced), buildJadesBT + verifyJadesBT.
// Set LIVE_ANCHOR=1 to also call the live Worker /mcp anchor_hash endpoint.

import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  hashFileBuffer, hashText, createEnvelope, buildSigningMessage,
  gradeEvidenceStrength, derEcdsaToP1363, verifyAssertion, anchorEvent,
  bytesToBase64, base64ToBytes, bytesToBase64url, base64urlToBytes,
  bytesHex, hexToBytes, concatBytes,
} from '../public/lib/anchorproof.mjs';

import { buildJadesBT, verifyJadesBT } from '../public/lib/jades.mjs';

// ---- helpers ---------------------------------------------------------------

let _failed = 0;
function pass(label) { console.log(`  PASS  ${label}`); }
function fail(label, reason) { console.error(`  FAIL  ${label}: ${reason || '?'}`); _failed++; }
function section(s) { console.log(`\n${s}`); }
function check(label, condition, reason = '') {
  condition ? pass(label) : fail(label, reason);
}

// Build minimal authenticatorData (37 bytes):
// [0..31] rpIdHash, [32] flags, [33..36] signCount (big-endian uint32)
function buildAuthData({ BE = false, BS = false, UP = true, UV = true, counter = 1 } = {}) {
  const data = new Uint8Array(37);
  let flags = 0;
  if (UP) flags |= 0x01;
  if (UV) flags |= 0x04;
  if (BE) flags |= 0x08;
  if (BS) flags |= 0x10;
  data[32] = flags;
  new DataView(data.buffer).setUint32(33, counter, false);
  return data;
}

// Build synthetic clientDataJSON for webauthn.get.
// challenge = base64url(UTF-8(messageJson)), which is what navigator.credentials.get sets.
function buildClientDataJSON(messageJson, origin = 'https://anchor.ainumbers.co') {
  return JSON.stringify({
    type: 'webauthn.get',
    challenge: bytesToBase64url(new TextEncoder().encode(messageJson)),
    origin,
  });
}

// Convert P1363 (r||s, 32 bytes each) to DER SEQUENCE{INTEGER r, INTEGER s}.
// Real WebAuthn authenticators return DER; SubtleCrypto signs to P1363.
function p1363ToDer(p1363) {
  const r = p1363.slice(0, 32);
  const s = p1363.slice(32, 64);

  function encodeInt(coordBytes) {
    // Strip leading zeros (keep at least one byte)
    let start = 0;
    while (start < coordBytes.length - 1 && coordBytes[start] === 0) start++;
    let val = coordBytes.slice(start);
    // DER INTEGER: prepend 0x00 if high bit set (would be interpreted as negative)
    if (val[0] & 0x80) val = concatBytes(new Uint8Array([0x00]), val);
    return concatBytes(new Uint8Array([0x02, val.length]), val);
  }

  const rDer = encodeInt(r);
  const sDer = encodeInt(s);
  const body = concatBytes(rDer, sDer);
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

// Sign authenticatorData||SHA-256(clientDataJSON) with the private key,
// return a synthetic assertion object with DER-encoded signature.
async function synthSign(privateKey, authData, cdjBytes) {
  const cdjHash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', cdjBytes));
  const verifyData = concatBytes(authData, cdjHash);
  const p1363 = new Uint8Array(await globalThis.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, privateKey, verifyData,
  ));
  return {
    authenticatorData: bytesToBase64(authData),
    clientDataJSON: bytesToBase64(cdjBytes),
    signature: bytesToBase64(p1363ToDer(p1363)),
  };
}

// ---- main ------------------------------------------------------------------

async function run() {
  // 1. Byte utilities
  section('1. Byte utilities');

  const hexStr = '0123456789abcdef';
  const hexBytes = hexToBytes(hexStr);
  check('hexToBytes/bytesHex roundtrip', bytesHex(hexBytes) === hexStr);

  const b64 = bytesToBase64(hexBytes);
  check('bytesToBase64/base64ToBytes roundtrip', bytesHex(base64ToBytes(b64)) === hexStr);

  const b64url = bytesToBase64url(hexBytes);
  check('bytesToBase64url/base64urlToBytes roundtrip', bytesHex(base64urlToBytes(b64url)) === hexStr);

  // 2. Hashing
  section('2. Hashing');

  const emptyHash = await hashText('');
  check(
    'SHA-256("") known vector',
    emptyHash === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );

  const docHash = await hashFileBuffer(new TextEncoder().encode('anchorproof gate test document').buffer);
  check('hashFileBuffer returns 64-char hex', docHash.length === 64 && /^[0-9a-f]+$/.test(docHash));

  // 3. Envelope
  section('3. Envelope');

  const env = createEnvelope({ docDigest: docHash, parties: ['alice@example.com'], message: 'Please sign' });
  check('envelope_id is 32-char hex', typeof env.envelope_id === 'string' && env.envelope_id.length === 32);
  check('doc_digest has sha256: prefix', env.doc_digest.startsWith('sha256:'));
  check('created_at is ISO', env.created_at.includes('T'));

  const sigMsg = buildSigningMessage(env, 'signer');
  const msgObj = JSON.parse(sigMsg);
  check('signing message: doc_digest matches', msgObj.doc_digest === env.doc_digest);
  check('signing message: envelope_id matches', msgObj.envelope_id === env.envelope_id);
  check('signing message: role is signer', msgObj.role === 'signer');
  check('signing message: signed_at present', typeof msgObj.signed_at === 'string');

  // 4. Evidence-strength grading
  section('4. Evidence-strength grading (flag permutations)');

  const eg1 = gradeEvidenceStrength(buildAuthData({ BE: false, BS: false, counter: 0 }));
  check('BE=0,BS=0 → device_bound', eg1.evidenceStrength === 'device_bound');
  check('BE=0,BS=0 → counter=0', eg1.counter === 0);

  const eg2 = gradeEvidenceStrength(buildAuthData({ BE: true, BS: false, counter: 5 }));
  check('BE=1,BS=0 → device_bound', eg2.evidenceStrength === 'device_bound');

  const eg3 = gradeEvidenceStrength(buildAuthData({ BE: true, BS: true, counter: 99 }));
  check('BE=1,BS=1 → synced', eg3.evidenceStrength === 'synced');
  check('BE=1,BS=1 → counter=99', eg3.counter === 99);

  // 5. DER ECDSA ↔ P1363 roundtrip
  section('5. DER ECDSA <-> P1363');

  const kp = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
  );

  const testData = new TextEncoder().encode('roundtrip test');
  const p1363Sig = new Uint8Array(await globalThis.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, testData,
  ));

  const derSig = p1363ToDer(p1363Sig);
  check('DER starts with 0x30', derSig[0] === 0x30);

  const p1363Back = derEcdsaToP1363(derSig);
  check('P1363→DER→P1363 roundtrip exact', bytesHex(p1363Back) === bytesHex(p1363Sig));

  const roundtripOk = await globalThis.crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, p1363Back, testData,
  );
  check('recovered P1363 verifies with SubtleCrypto', roundtripOk);

  // 6. verifyAssertion — device_bound path
  section('6. verifyAssertion (device_bound, ES256)');

  const spkiBuf = await globalThis.crypto.subtle.exportKey('spki', kp.publicKey);
  const spkiBase64 = bytesToBase64(new Uint8Array(spkiBuf));

  const origin = 'https://anchor.ainumbers.co';
  const authDataDB = buildAuthData({ BE: false, BS: false, counter: 42 });
  const cdjDB = new TextEncoder().encode(buildClientDataJSON(sigMsg, origin));
  const assertionDB = await synthSign(kp.privateKey, authDataDB, cdjDB);

  const verDB = await verifyAssertion(assertionDB, spkiBase64, sigMsg, origin);
  check('verifyAssertion ok', verDB.ok, verDB.reason || '');
  check('evidenceStrength device_bound', verDB.evidenceStrength === 'device_bound');
  check('alg ES256', verDB.alg === 'ES256');
  check('counter=42', verDB.counter === 42);

  // tampered message → fail
  const verBadMsg = await verifyAssertion(assertionDB, spkiBase64, sigMsg + 'TAMPERED', origin);
  check('tampered message rejected', !verBadMsg.ok);

  // wrong origin → fail
  const verBadOrigin = await verifyAssertion(assertionDB, spkiBase64, sigMsg, 'https://evil.com');
  check('wrong origin rejected', !verBadOrigin.ok);

  // 7. buildJadesBT + verifyJadesBT
  section('7. JAdES B-T build and verify');

  const jades = await buildJadesBT({
    assertion: assertionDB,
    spkiPublicKey: spkiBase64,
    signingMessage: sigMsg,
    docDigest: 'sha256:' + docHash,
    signedAt: new Date().toISOString(),
    anchorBindings: [],
    evidenceStrength: 'device_bound',
    BE: false,
    BS: false,
    counter: 42,
  });

  check('jades.payload is string', typeof jades.payload === 'string');
  check('jades.protected is string', typeof jades.protected === 'string');
  check('jades.signature is string', typeof jades.signature === 'string');
  check('jades.header.anchorproof present', !!jades.header?.anchorproof);

  const protHdr = JSON.parse(new TextDecoder().decode(base64urlToBytes(jades.protected)));
  check('protected.alg is ES256', protHdr.alg === 'ES256');
  check('protected.typ is jose+json', protHdr.typ === 'jose+json');
  check('protected.jwk present', !!protHdr.jwk);
  check('protected.etsiU present', Array.isArray(protHdr.etsiU));

  const jadVer = await verifyJadesBT(jades, null);
  check('verifyJadesBT ok', jadVer.ok, jadVer.reason || '');
  check('verifyJadesBT evidenceStrength device_bound', jadVer.evidenceStrength === 'device_bound');
  check('verifyJadesBT tstCount=0 (no live anchor)', jadVer.tstCount === 0);

  // Tamper payload → verify must fail
  const tampered = { ...jades, payload: bytesToBase64url(new TextEncoder().encode('TAMPERED')) };
  const jadVerTampered = await verifyJadesBT(tampered, null);
  check('tampered payload rejected by verifyJadesBT', !jadVerTampered.ok);

  // 8. Full synced-passkey path
  section('8. verifyAssertion + JAdES — synced passkey (BE=1,BS=1)');

  const authDataSync = buildAuthData({ BE: true, BS: true, counter: 1 });
  const cdjSync = new TextEncoder().encode(buildClientDataJSON(sigMsg, origin));
  const assertionSync = await synthSign(kp.privateKey, authDataSync, cdjSync);

  const verSync = await verifyAssertion(assertionSync, spkiBase64, sigMsg, origin);
  check('synced: verifyAssertion ok', verSync.ok, verSync.reason || '');
  check('synced: evidenceStrength synced', verSync.evidenceStrength === 'synced');

  const jadesSync = await buildJadesBT({
    assertion: assertionSync,
    spkiPublicKey: spkiBase64,
    signingMessage: sigMsg,
    docDigest: 'sha256:' + docHash,
    signedAt: new Date().toISOString(),
    anchorBindings: [],
    evidenceStrength: 'synced',
    BE: true,
    BS: true,
    counter: 1,
  });

  const jadVerSync = await verifyJadesBT(jadesSync, null);
  check('synced: verifyJadesBT ok', jadVerSync.ok, jadVerSync.reason || '');
  check('synced: evidenceStrength synced in receipt', jadVerSync.evidenceStrength === 'synced');

  // 9. Optional live anchor_hash via /mcp
  section('9. Live anchor_hash via /mcp (LIVE_ANCHOR=1 to enable)');

  if (process.env.LIVE_ANCHOR === '1') {
    const mcpBase = process.env.MCP_BASE || 'https://anchor.ainumbers.co';
    console.log(`  Calling ${mcpBase}/mcp anchor_hash ...`);
    try {
      const testEvent = {
        type: 'gate-am2-test',
        doc_digest: 'sha256:' + docHash,
        signed_at: new Date().toISOString(),
      };
      const result = await anchorEvent(testEvent, ['sigstore'], mcpBase);
      check('live: event_hash returned', typeof result.event_hash === 'string');
      check('live: anchor_bindings is array', Array.isArray(result.anchor_bindings));
      if (result.anchor_bindings.length > 0) {
        const b = result.anchor_bindings[0];
        check('live: binding has type', typeof b.type === 'string');
        check('live: binding has proof', typeof b.proof === 'string');
        console.log(`  binding[0]: type=${b.type}  gen_time=${b.gen_time || '(pending)'}`);
      }
      if (result.failures?.length) {
        console.log(`  failures: ${JSON.stringify(result.failures)}`);
      }
    } catch (e) {
      fail('live anchor_hash', e.message);
    }
  } else {
    console.log('  Skipped (set LIVE_ANCHOR=1 and optionally MCP_BASE=https://anchor.ainumbers.co)');
  }

  // Summary
  console.log('');
  if (_failed > 0) {
    console.error(`gate-am2: FAIL — ${_failed} check(s) failed`);
    process.exit(1);
  } else {
    console.log('gate-am2: PASS — all checks green');
    console.log('');
    console.log('evidence_strength variants exercised: device_bound, synced');
    console.log('JAdES B-T: built and verified, tamper detection confirmed');
  }
}

run().catch((e) => {
  console.error('gate-am2: unhandled error:', e);
  process.exit(1);
});
