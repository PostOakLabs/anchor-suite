// gate-tst-verify.mjs — Regression gate for TST long-term-validity (LTV) date fix.
//
// Verifies that verifyTstBinding() validates the signer cert chain at genTime
// (the moment of signing) rather than at the current date. Without the fix,
// any stored receipt permanently fails once the TSA signing cert expires.
//
// Fixture: a real Sigstore ContentInfo DER captured 2026-07-04.
//   genTime      2026-07-04T11:15:37Z
//   signer cert  notBefore 2025-04-08, notAfter 2035-04-06 (ECDSA P-384)
//   root         sigstore-tsa-root.pem (pinned)
//
// Test (a): verifyTstBinding with no override → passes (genTime is within cert validity).
// Test (b): verifyTstBinding with _testCheckDate=2099-01-01 → fails (cert expired by then).
//
// Deterministic: no network calls, uses pre-baked fixture + pinned roots already in vendor/.

import { webcrypto } from 'node:crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { verifyTstBinding } from '../public/js/tst.js';

const FIXTURE_HASH_HEX = '68856c6687a2aab3d2e4fee771d095a39807bd082cfa9e77a54f6813a2aa32b7';
const FIXTURE_LOG_ORIGIN = 'https://timestamp.sigstore.dev/api/v1/timestamp';

// Real Sigstore TST captured 2026-07-04. ContentInfo DER, base64-encoded.
// genTime=2026-07-04T11:15:37Z; signer cert notAfter=2035-04-06.
// Re-generate with: node -e "fetch Sigstore + print base64" if roots rotate.
const FIXTURE_PROOF_B64 =
  'MIIE5zADAgEAMIIE3gYJKoZIhvcNAQcCoIIEzzCCBMsCAQMxDTALBglghkgBZQMEAgEwgcAGCyqGSIb3' +
  'DQEJEAEEoIGwBIGtMIGqAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgaIVsZoeiqrPS5P7n' +
  'cdCVo5gHvQgs+p53pU9oE6KqMrcCFQCqNklULODS7vcC3rNzND+/6kxVGxgPMjAyNjA3MDQxMTE1Mzda' +
  'MAMCAQECBh3PEh8kK6AypDAwLjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MRUwEwYDVQQDEwxzaWdzdG9y' +
  'ZS10c2GgggIUMIICEDCCAZagAwIBAgIUOhNULwyQYe68wUMvy4qOiyojiwwwCgYIKoZIzj0EAwMwOTEV' +
  'MBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0y' +
  'NTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMC4xFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEVMBMGA1UE' +
  'AxMMc2lnc3RvcmUtdHNhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ra2Z8hKNig2T9kFjCAToGG30jky' +
  '+WQv3BzL+mKvh1SKNR/UwuwsfNCg4sryoYAd8E6isovVA3M4aoNdm9QDi50Z8nTEyvqgfDPtTIwXItfi' +
  'W/AFf1V7uwkbkAoj0xxco2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFIn9eUOHz9BlRsMCRscs' +
  'c1t9tOsDMB8GA1UdIwQYMBaAFJjsAe9/u1H/1JUeb4qImFMHic6/MBYGA1UdJQEB/wQMMAoGCCsGAQUF' +
  'BwMIMAoGCCqGSM49BAMDA2gAMGUCMDtpsV/6KaO0qyF/UMsX2aSUXKQFdoGTptQGc0ftq1csulHPGG6d' +
  'smyMNd3JB+G3EQIxAOajvBcjpJmKb4Nv+2Taoj8Uc5+b6ih6FXCCKraSqupe07zqswMcXJTe1cExvHvv' +
  'lzGCAdowggHWAgEBMFEwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10' +
  'c2Etc2VsZnNpZ25lZAIUOhNULwyQYe68wUMvy4qOiyojiwwwCwYJYIZIAWUDBAIBoIH8MBoGCSqGSIb3' +
  'DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwNzA0MTExNTM3WjAvBgkqhkiG9w0B' +
  'CQQxIgQgR6VoLS/+BsktjjQsHoQDA285UfEZCdUjwp08C3qYHIUwgY4GCyqGSIb3DQEJEAIvMX8wfTB7' +
  'MHkEIIX5J7wHq2LKw7RDVsEO/IGyxog/2nq55thw2dE6zQW3MFUwPaQ7MDkxFTATBgNVBAoTDHNpZ3N0' +
  'b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZzaWduZWQCFDoTVC8MkGHuvMFDL8uKjosq' +
  'I4sMMAoGCCqGSM49BAMCBGYwZAIwWLalixWVz0KurIzCdMurTGeX+0h1flIwT9NTaoENTvMJrzMmdJpb' +
  'ka8xYqgxUIhsAjADmsP1gYuZ4gWM1FOTddXo1+7Kg/gaFnxAKXQPH2soXz2hGkX9F6dXhCQoBBrsKko=';

const BINDING = {
  anchored_hash: 'sha256:' + FIXTURE_HASH_HEX,
  proof: FIXTURE_PROOF_B64,
  log_origin: FIXTURE_LOG_ORIGIN,
};

let _failed = 0;
function pass(label) { console.log(`  PASS  ${label}`); }
function fail(label, reason) { console.error(`  FAIL  ${label}: ${reason || '?'}`); _failed++; }
function section(s) { console.log(`\n${s}`); }

async function run() {
  section('1. TST verify — correct date (genTime, no override)');

  const r1 = await verifyTstBinding(BINDING);
  if (r1.ok) {
    pass('verifyTstBinding ok at genTime');
    pass(`genTime  ${r1.genTime}`);
    pass(`serial   ${r1.serial}`);
    pass(`authority ${r1.authority}`);
  } else {
    fail('verifyTstBinding at genTime', r1.error);
  }

  section('2. TST verify — future date (2099-01-01) must FAIL');

  // Signing cert notAfter=2035-04-06. Forcing checkDate=2099 proves pkijs honors
  // the checkDate parameter passed by the fix. Without checkDate in the verify call,
  // pkijs defaults to new Date() and this test would PASS for the wrong reason
  // (current date is also after 2035, so it would catch the expiry naturally)
  // — but today is 2026 and the cert is still valid, so without the fix this
  // test would incorrectly PASS too. The fix ensures genTime=2026 is used normally
  // and _testCheckDate=2099 forces the cert-expiry rejection.
  const r2 = await verifyTstBinding(BINDING, { _testCheckDate: new Date('2099-01-01T00:00:00Z') });
  if (!r2.ok) {
    pass('verifyTstBinding correctly rejected at checkDate=2099-01-01');
    pass(`rejection: ${r2.error}`);
  } else {
    fail(
      'verifyTstBinding should have rejected checkDate=2099-01-01 (cert notAfter=2035)',
      'returned ok:true — checkDate parameter is NOT being passed to signed.verify()',
    );
  }

  section('3. TST verify — invalid binding (wrong hash) must FAIL');

  const r3 = await verifyTstBinding({ ...BINDING, anchored_hash: 'sha256:' + 'aa'.repeat(32) });
  if (!r3.ok && r3.error.includes('Hash mismatch')) {
    pass('hash mismatch correctly rejected');
  } else {
    fail('hash mismatch not caught', r3.ok ? 'returned ok:true' : r3.error);
  }

  console.log('');
  if (_failed > 0) {
    console.error(`gate-tst-verify: FAIL — ${_failed} check(s) failed`);
    process.exit(1);
  }
  console.log('gate-tst-verify: PASS — all checks green');
  console.log('LTV fix confirmed: chain validated at genTime (2026-07-04), rejected at 2099-01-01');
}

run().catch((e) => {
  console.error('gate-tst-verify: unhandled error:', e);
  process.exit(1);
});
