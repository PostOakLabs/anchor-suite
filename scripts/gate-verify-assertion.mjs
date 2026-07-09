// gate-verify-assertion.mjs — Suite A/C negative-path gate for the WebAuthn
// assertion verifier (public/lib/anchorproof.mjs verifyAssertion), the shared
// verify path behind MCP tool verify_signature_envelope (src/worker.mjs:818).
//
// WHY THIS GATE EXISTS
// --------------------
// Smoke feeds the verifier ONE known-good assertion and asserts valid=true.
// A verifier that never says "invalid" is untested, not correct. This gate
// builds a genuine P-256 WebAuthn assertion at runtime, proves the happy path
// (valid=true), then runs a battery of mutations that MUST each be rejected.
//
// SPECIFICALLY it proves the DER->P1363 fallback in anchorproof.mjs cannot
// validate a genuinely wrong signature:
//
//     if (kp.p1363) {
//       try { sigBytes = derEcdsaToP1363(sig, ...); }
//       catch { sigBytes = sig; }        // <-- the fallback under audit
//     }
//     const valid = await crypto.subtle.verify(kp.verify, key, sigBytes, verifyData);
//
// The fallback only changes the accepted ENCODING (DER vs raw P1363). The final
// arbiter is crypto.subtle.verify, which returns true only for a cryptographically
// correct signature over verifyData. Cases 6 and 7 below drive the fallback branch
// with (a) a correct raw-P1363 signature -> valid=true (encoding tolerance, still
// correct crypto) and (b) 64 random bytes that are NOT a valid DER structure ->
// fallback -> valid=false. If (b) ever returned true, that is the P0.
//
// Deterministic: outcome is fixed (good verifies, every mutation rejects). The
// keypair is generated fresh each run but the pass/fail verdict does not depend
// on which key.

import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  verifyAssertion,
  bytesToBase64,
  bytesToBase64url,
  concatBytes,
} from '../public/lib/anchorproof.mjs';

let _failed = 0;
function pass(label) { console.log(`  PASS  ${label}`); }
function fail(label, reason) { console.error(`  FAIL  ${label}: ${reason || '?'}`); _failed++; }
function section(s) { console.log(`\n${s}`); }

const ORIGIN = 'https://anchor.ainumbers.co';

// ---- helpers ----------------------------------------------------------------

// Convert a raw P1363 (r||s) ECDSA signature to DER SEQUENCE{INTEGER r, INTEGER s}.
// This is what a real WebAuthn authenticator emits; SubtleCrypto sign() emits P1363.
function p1363ToDer(p1363) {
  const half = p1363.length / 2;
  const enc = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++; // strip leading zeros
    let b = bytes.slice(i);
    if (b[0] & 0x80) b = Uint8Array.from([0, ...b]); // prepend 0 if high bit set (positive int)
    return Uint8Array.from([0x02, b.length, ...b]);
  };
  const r = enc(p1363.slice(0, half));
  const s = enc(p1363.slice(half));
  const body = Uint8Array.from([...r, ...s]);
  return Uint8Array.from([0x30, body.length, ...body]);
}

// Build a genuine WebAuthn GetAssertion response over `signingMessage`, signed by `privKey`.
async function buildAssertion(privKey, signingMessage, { origin = ORIGIN } = {}) {
  const challengeB64url = bytesToBase64url(new TextEncoder().encode(signingMessage));
  const clientData = JSON.stringify({ type: 'webauthn.get', challenge: challengeB64url, origin });
  const cdjBytes = new TextEncoder().encode(clientData);

  // authenticatorData: rpIdHash(32) | flags(1) | signCount(4). flags = UP|UV = 0x05.
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('anchor.ainumbers.co')));
  const authData = new Uint8Array(37);
  authData.set(rpIdHash, 0);
  authData[32] = 0x05;             // UP + UV, BE=0 BS=0 -> device_bound
  authData[36] = 0x2a;             // signCount = 42

  const cdjHash = new Uint8Array(await crypto.subtle.digest('SHA-256', cdjBytes));
  const verifyData = concatBytes(authData, cdjHash);

  const p1363 = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, verifyData));
  const der = p1363ToDer(p1363);

  return {
    authData,
    cdjBytes,
    p1363,
    assertionDer: {
      authenticatorData: bytesToBase64(authData),
      clientDataJSON: bytesToBase64(cdjBytes),
      signature: bytesToBase64(der),
    },
    assertionRaw: {
      authenticatorData: bytesToBase64(authData),
      clientDataJSON: bytesToBase64(cdjBytes),
      signature: bytesToBase64(p1363),
    },
  };
}

async function run() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const spkiB64 = bytesToBase64(spki);

  // wrong key (different signer)
  const kp2 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

  const MSG = JSON.stringify({ doc_digest: 'sha256:' + 'ab'.repeat(32), envelope_id: 'env-1', role: 'signer', signed_at: '2026-07-09T00:00:00Z' });
  const built = await buildAssertion(kp.privateKey, MSG);

  section('1. HAPPY PATH — genuine DER-encoded assertion must VERIFY');
  {
    const r = await verifyAssertion(built.assertionDer, spkiB64, MSG, ORIGIN);
    if (r.ok && r.alg === 'ES256' && r.evidenceStrength === 'device_bound') pass(`valid=true alg=${r.alg} evidence=${r.evidenceStrength}`);
    else fail('happy path did not verify', JSON.stringify(r));
  }

  section('2. TAMPER SIGNATURE — flip one byte of DER sig must REJECT');
  {
    const der = base64ToBytesLocal(built.assertionDer.signature);
    der[der.length - 1] ^= 0x01;
    const bad = { ...built.assertionDer, signature: bytesToBase64Local(der) };
    const r = await verifyAssertion(bad, spkiB64, MSG, ORIGIN);
    if (!r.ok) pass(`rejected: ${r.reason}`);
    else fail('tampered signature ACCEPTED — false pass', JSON.stringify(r));
  }

  section('3. WRONG KEY — verify against a different signer must REJECT');
  {
    const spki2 = bytesToBase64Local(new Uint8Array(await crypto.subtle.exportKey('spki', kp2.publicKey)));
    const r = await verifyAssertion(built.assertionDer, spki2, MSG, ORIGIN);
    if (!r.ok) pass(`rejected: ${r.reason}`);
    else fail('wrong-key signature ACCEPTED — false pass', JSON.stringify(r));
  }

  section('4. REPLAY / SUBSTITUTION — valid sig, but verifier told a DIFFERENT message must REJECT');
  {
    const otherMsg = JSON.stringify({ doc_digest: 'sha256:' + 'cd'.repeat(32), envelope_id: 'env-1', role: 'signer', signed_at: '2026-07-09T00:00:00Z' });
    const r = await verifyAssertion(built.assertionDer, spkiB64, otherMsg, ORIGIN);
    if (!r.ok && /challenge/i.test(r.reason || '')) pass(`rejected: ${r.reason}`);
    else fail('substituted-message assertion ACCEPTED — false pass', JSON.stringify(r));
  }

  section('5. ORIGIN MISMATCH — assertion signed for another origin must REJECT');
  {
    const r = await verifyAssertion(built.assertionDer, spkiB64, MSG, 'https://evil.example');
    if (!r.ok && /origin/i.test(r.reason || '')) pass(`rejected: ${r.reason}`);
    else fail('origin mismatch ACCEPTED — false pass', JSON.stringify(r));
  }

  section('6. FALLBACK, correct crypto — raw P1363 sig (non-DER) must VERIFY (encoding tolerance)');
  {
    // Raw P1363 does not start with 0x30, so derEcdsaToP1363 throws -> catch -> sigBytes = sig.
    // Correct crypto -> subtle.verify returns true. Proves the fallback branch is exercised.
    const r = await verifyAssertion(built.assertionRaw, spkiB64, MSG, ORIGIN);
    if (r.ok) pass('raw-P1363 correct signature verified via fallback branch');
    else fail('fallback rejected a correct raw-P1363 signature', JSON.stringify(r));
  }

  section('7. FALLBACK, wrong crypto — 64 random bytes via fallback must REJECT (the P0 test)');
  {
    // 64 bytes that are NOT valid DER (first byte != 0x30) force the catch->sigBytes=sig
    // fallback. If crypto.subtle.verify accepted these, the fallback would validate a
    // genuinely wrong signature. It must return valid=false.
    let ok = true;
    for (let trial = 0; trial < 8; trial++) {
      const garbage = new Uint8Array(64);
      crypto.getRandomValues(garbage);
      garbage[0] = 0x11; // guarantee != 0x30 so the DER parse throws and we hit the fallback
      const bad = { ...built.assertionRaw, signature: bytesToBase64Local(garbage) };
      const r = await verifyAssertion(bad, spkiB64, MSG, ORIGIN);
      if (r.ok) { ok = false; fail(`trial ${trial}: fallback ACCEPTED random 64 bytes — P0 FALSE-ACCEPT`, JSON.stringify(r)); break; }
    }
    if (ok) pass('fallback rejected random 64-byte signatures across 8 trials — no false-accept');
  }

  section('8. TAMPER authenticatorData — flip a byte (breaks verifyData) must REJECT');
  {
    const ad = base64ToBytesLocal(built.assertionDer.authenticatorData);
    ad[0] ^= 0x01;
    const bad = { ...built.assertionDer, authenticatorData: bytesToBase64Local(ad) };
    const r = await verifyAssertion(bad, spkiB64, MSG, ORIGIN);
    if (!r.ok) pass(`rejected: ${r.reason}`);
    else fail('tampered authenticatorData ACCEPTED — false pass', JSON.stringify(r));
  }

  section('9. MALFORMED clientDataJSON — must ERROR cleanly, not crash or accept');
  {
    const bad = { ...built.assertionDer, clientDataJSON: bytesToBase64Local(new TextEncoder().encode('{not json')) };
    const r = await verifyAssertion(bad, spkiB64, MSG, ORIGIN);
    if (!r.ok && /clientDataJSON/i.test(r.reason || '')) pass(`rejected: ${r.reason}`);
    else fail('malformed clientDataJSON not rejected cleanly', JSON.stringify(r));
  }

  console.log('');
  if (_failed > 0) {
    console.error(`gate-verify-assertion: FAIL — ${_failed} check(s) failed`);
    process.exit(1);
  }
  console.log('gate-verify-assertion: PASS — all negative-path checks green');
  console.log('DER->P1363 fallback confirmed: cannot validate a genuinely wrong signature.');
}

// local base64 helpers (avoid importing internals not exported)
function base64ToBytesLocal(b64) {
  const bin = atob(b64.replace(/[\r\n\s]/g, '').replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToBase64Local(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

run().catch((e) => { console.error('gate-verify-assertion: unhandled error:', e); process.exit(1); });
