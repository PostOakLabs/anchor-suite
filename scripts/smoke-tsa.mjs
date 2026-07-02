// smoke-tsa.mjs — stamp a fixed test hash at every authority and verify each
// token locally against the pinned roots (ANCHOR-SUITE-BUILD-SPEC §6).
//
// Modes:
//   direct (default)  POST straight to the upstream TSAs (Node has no CORS).
//                     Used pre-deploy and for local runs.
//   --relay           Route DigiCert/Sectigo/FreeTSA through the LIVE relay at
//                     https://anchor.ainumbers.co/relay/* and preflight-check
//                     CORS. Used post-deploy and on the schedule.
//
// Exit discipline:
//   Third-party outage (HTTP error, timeout, TSA rejection)  -> provider marked
//   "degraded" in public/status/tsa-health.json, exit 0.
//   Relay or code failure (relay 4xx/5xx of our own making, missing CORS,
//   a well-formed timestamp reply that fails pinned-root verification)
//   -> exit 1, which blocks deploy.
//
// Flags: --relay, --no-write (skip health-file write)

import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { createHash, randomBytes } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { pkijs, asn1js } from '../public/vendor/pkijs.bundle.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOTS_DIR = join(HERE, '..', 'public', 'vendor', 'roots');
const HEALTH_PATH = join(HERE, '..', 'public', 'status', 'tsa-health.json');

const RELAY_MODE = process.argv.includes('--relay');
const WRITE_HEALTH = !process.argv.includes('--no-write');
const RELAY_BASE = process.env.RELAY_BASE || 'https://anchor.ainumbers.co';
const ALLOWED_ORIGIN = 'https://anchor.ainumbers.co';
const THROTTLE_MS = Number(process.env.SMOKE_THROTTLE_MS || 2000);

pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node', crypto: globalThis.crypto }));

// Fixed test vector; the nonce below is fresh per request.
const TEST_MESSAGE = 'anchor-suite TSA smoke test vector v1';
const TEST_HASH = createHash('sha256').update(TEST_MESSAGE).digest();

const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_EKU = '2.5.29.37';
const OID_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const pem = (name) => readFileSync(join(ROOTS_DIR, name), 'utf8');
const pemBlocks = (text) => text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
function pemToCert(block) {
  const b64 = block.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s/g, '');
  const der = Buffer.from(b64, 'base64');
  return new pkijs.Certificate({ schema: asn1js.fromBER(new Uint8Array(der).buffer).result });
}

function buildTsqDer(nonceBytes) {
  const tsq = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256, algorithmParams: new asn1js.Null() }),
      hashedMessage: new asn1js.OctetString({ valueHex: new Uint8Array(TEST_HASH).buffer }),
    }),
    nonce: new asn1js.Integer({ valueHex: nonceBytes.buffer }),
    certReq: true,
  });
  return tsq.toSchema().toBER(false);
}

function freshNonce() {
  const n = new Uint8Array(randomBytes(8));
  n[0] &= 0x7f; // keep the INTEGER positive
  return n;
}

function nonceEquals(tstNonce, expected) {
  if (!tstNonce) return false;
  const got = BigInt('0x' + (Buffer.from(tstNonce.valueBlock.valueHexView).toString('hex') || '0'));
  return got === expected;
}

// Full local verification of a DER TimeStampResp against a pinned root.
// Returns { ok, detail } and throws ONLY on code bugs.
async function verifyTst(respDer, { nonce, rootName, chainName }) {
  let tsr;
  try {
    tsr = new pkijs.TimeStampResp({ schema: asn1js.fromBER(new Uint8Array(respDer).buffer).result });
  } catch (e) {
    return { ok: false, kind: 'malformed', detail: 'response is not a DER TimeStampResp: ' + e.message };
  }
  if (![0, 1].includes(tsr.status.status)) {
    return { ok: false, kind: 'provider', detail: `TSA refused the request (PKIStatus ${tsr.status.status})` };
  }
  const signed = new pkijs.SignedData({ schema: tsr.timeStampToken.content });

  // Chain building: token certs plus any pinned intermediates, anchored ONLY
  // at the pinned root. DigiCert and Sectigo tokens include a CROSS-SIGNED
  // variant of their root (G4 signed by Assured ID, R46 signed by USERTrust);
  // left in place it drags the path search toward an anchor we do not pin.
  // Drop every cert whose subject matches the pinned root subject so the path
  // terminates at the pinned self-signed anchor instead.
  const dnOf = (rdn) => rdn.typesAndValues.map((t) => `${t.type}=${t.value.valueBlock.value}`).join('|');
  const root = pemToCert(pem(rootName));
  const rootSubject = dnOf(root.subject);
  let chainCerts = (signed.certificates || []).filter((c) => dnOf(c.subject) !== rootSubject);
  if (chainName) {
    chainCerts = [...chainCerts, ...pemBlocks(pem(chainName)).map(pemToCert).filter((c) => dnOf(c.subject) !== rootSubject)];
  }
  signed.certificates = chainCerts;

  let verifyResult;
  try {
    // For a TSTInfo token pkijs demands the ORIGINAL message as `data`: it
    // recomputes the imprint hash from it and then verifies the CMS signature.
    // The smoke harness owns the test message, so it can. (A hash-only flow,
    // like verify.html with a pasted digest, must check the imprint manually.)
    verifyResult = await signed.verify({
      signer: 0,
      data: new TextEncoder().encode(TEST_MESSAGE).slice().buffer,
      trustedCerts: [root],
      extendedMode: true,
      checkChain: true,
    });
  } catch (e) {
    const msg = e?.message || e?.code || JSON.stringify(e);
    return { ok: false, kind: 'verify', detail: 'CMS/chain verification failed: ' + msg };
  }
  if (!verifyResult.signatureVerified) {
    return { ok: false, kind: 'verify', detail: 'CMS signature did not verify' };
  }

  const signerCert = verifyResult.signerCertificate;
  const eku = (signerCert.extensions || []).find((x) => x.extnID === OID_EKU);
  if (!eku?.parsedValue?.keyPurposes?.includes(OID_TIMESTAMPING)) {
    return { ok: false, kind: 'verify', detail: 'signer certificate lacks the id-kp-timeStamping EKU' };
  }

  const eContent = signed.encapContentInfo.eContent;
  const tstDer = new Uint8Array(eContent.valueBlock.valueHexView);
  const tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(tstDer.buffer).result });

  const imprint = Buffer.from(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);
  if (!imprint.equals(TEST_HASH)) {
    return { ok: false, kind: 'verify', detail: 'messageImprint does not match the test hash' };
  }
  if (nonce !== null && !nonceEquals(tstInfo.nonce, nonce)) {
    return { ok: false, kind: 'verify', detail: 'nonce was not echoed back' };
  }
  const skewMs = Math.abs(tstInfo.genTime.getTime() - Date.now());
  if (skewMs > 15 * 60 * 1000) {
    return { ok: false, kind: 'verify', detail: `genTime is ${Math.round(skewMs / 1000)}s from local clock` };
  }
  return {
    ok: true,
    detail: `genTime ${tstInfo.genTime.toISOString()}, policy ${tstInfo.policy}, serial ${Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString('hex')}`,
  };
}

async function fetchWithRetry(url, init, attempts = 2) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) });
    } catch (e) {
      lastErr = e;
      if (i + 1 < attempts) await sleep(5000);
    }
  }
  throw lastErr;
}

// ---------------- providers ----------------

const results = {}; // key -> { status: 'ok'|'degraded', detail, blocking?: string }

async function rfc3161Provider(key, { directUrl, relayPath, rootName, chainName }) {
  const nonceBytes = freshNonce();
  const nonce = BigInt('0x' + Buffer.from(nonceBytes).toString('hex'));
  const url = RELAY_MODE && relayPath ? RELAY_BASE + relayPath : directUrl;
  const via = RELAY_MODE && relayPath ? 'relay' : 'direct';
  let res;
  try {
    res = await fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query' },
      body: buildTsqDer(nonceBytes),
    });
  } catch (e) {
    if (via === 'relay') return { status: 'degraded', blocking: `relay unreachable: ${e.message}`, via };
    return { status: 'degraded', detail: `unreachable: ${e.message}`, via };
  }

  const ct = (res.headers.get('content-type') || '').split(';')[0].trim();
  if (res.status === 200 && ct === 'application/timestamp-reply') {
    const body = Buffer.from(await res.arrayBuffer());
    const v = await verifyTst(body, { nonce, rootName, chainName });
    if (v.ok) return { status: 'ok', detail: v.detail, via };
    if (v.kind === 'provider') return { status: 'degraded', detail: v.detail, via };
    // A 200 timestamp-reply that fails local verification is a pin or code
    // problem on our side, or relay corruption. Deploy-blocking either way.
    return { status: 'degraded', blocking: `verification failed on a well-formed reply: ${v.detail}`, via };
  }

  if (via === 'relay') {
    // Our worker only emits these for caller mistakes; upstream failures pass
    // the upstream status through with a plain body. Distinguish by status.
    if ([400, 404, 405, 413, 415, 429].includes(res.status)) {
      return { status: 'degraded', blocking: `relay rejected our request: HTTP ${res.status}`, via };
    }
    return { status: 'degraded', detail: `upstream failure via relay: HTTP ${res.status}`, via };
  }
  return { status: 'degraded', detail: `HTTP ${res.status} (${ct || 'no content-type'})`, via };
}

async function sigstoreProvider() {
  // 6-byte nonce: the JSON field is a Number, so it must stay inside the
  // 2^53 safe-integer range or the echoed value cannot compare equal.
  const nonceBytes = new Uint8Array(randomBytes(6));
  nonceBytes[0] &= 0x7f;
  const nonce = BigInt('0x' + Buffer.from(nonceBytes).toString('hex'));
  let res;
  try {
    res = await fetchWithRetry('https://timestamp.sigstore.dev/api/v1/timestamp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        artifactHash: TEST_HASH.toString('base64'),
        hashAlgorithm: 'sha256',
        nonce: Number(nonce),
        certificates: true,
      }),
    });
  } catch (e) {
    return { status: 'degraded', detail: `unreachable: ${e.message}`, via: 'direct' };
  }
  if (res.status !== 200 && res.status !== 201) {
    return { status: 'degraded', detail: `HTTP ${res.status}`, via: 'direct' };
  }
  const body = Buffer.from(await res.arrayBuffer());
  const v = await verifyTst(body, { nonce, rootName: 'sigstore-tsa-root.pem', chainName: 'sigstore-tsa-certchain.pem' });
  if (v.ok) return { status: 'ok', detail: v.detail, via: 'direct' };
  if (v.kind === 'provider') return { status: 'degraded', detail: v.detail, via: 'direct' };
  return { status: 'degraded', blocking: `verification failed on a well-formed reply: ${v.detail}`, via: 'direct' };
}

async function otsProvider() {
  const calendars = [
    'https://alice.btc.calendar.opentimestamps.org',
    'https://bob.btc.calendar.opentimestamps.org',
    'https://finney.calendar.eternitywall.com',
    'https://btc.calendar.catallaxy.com',
  ];
  let ok = 0;
  const notes = [];
  for (const cal of calendars) {
    try {
      const res = await fetchWithRetry(`${cal}/digest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: TEST_HASH,
      }, 1);
      const body = Buffer.from(await res.arrayBuffer());
      if (res.status === 200 && body.length > 0) ok++;
      else notes.push(`${new URL(cal).hostname}: HTTP ${res.status}`);
    } catch (e) {
      notes.push(`${new URL(cal).hostname}: ${e.message}`);
    }
  }
  const detail = `${ok}/${calendars.length} calendars answered` + (notes.length ? ` (${notes.join('; ')})` : '');
  return { status: ok >= 2 ? 'ok' : 'degraded', detail, via: 'direct', calendars_ok: ok, calendars_total: calendars.length };
}

// ---------------- run ----------------

console.log(`smoke-tsa: mode=${RELAY_MODE ? 'relay' : 'direct'}  hash=sha256:${TEST_HASH.toString('hex')}`);

if (RELAY_MODE) {
  // CORS preflight against the live relay. A wrong or missing allow-origin
  // header breaks the entire product page, so this is deploy-blocking.
  const pre = await fetchWithRetry(`${RELAY_BASE}/relay/digicert`, {
    method: 'OPTIONS',
    headers: { Origin: ALLOWED_ORIGIN, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'Content-Type' },
  });
  const acao = pre.headers.get('access-control-allow-origin');
  if (pre.status !== 204 || acao !== ALLOWED_ORIGIN) {
    console.error(`BLOCKING: relay CORS preflight wrong (HTTP ${pre.status}, allow-origin=${acao})`);
    process.exit(1);
  }
  console.log('relay CORS preflight ok');
}

results.sigstore = await sigstoreProvider();
await sleep(THROTTLE_MS);
results.digicert = await rfc3161Provider('digicert', {
  directUrl: 'http://timestamp.digicert.com',
  relayPath: '/relay/digicert',
  rootName: 'digicert-trusted-root-g4.pem',
});
await sleep(Math.max(THROTTLE_MS, 15_000)); // Sectigo politeness: one request, well spaced
results.sectigo = await rfc3161Provider('sectigo', {
  directUrl: 'http://timestamp.sectigo.com',
  relayPath: '/relay/sectigo',
  rootName: 'sectigo-time-stamping-root-r46.pem',
});
await sleep(THROTTLE_MS);
results.freetsa = await rfc3161Provider('freetsa', {
  directUrl: 'https://freetsa.org/tsr',
  relayPath: '/relay/freetsa',
  rootName: 'freetsa-cacert.pem',
});
await sleep(THROTTLE_MS);
results.github = await rfc3161Provider('github', {
  directUrl: 'https://timestamp.githubapp.com/api/v1/timestamp',
  relayPath: null, // browser-direct provider; never relayed
  rootName: 'github-tsa-root.pem',
  chainName: 'github-tsa-certchain.pem',
});
await sleep(THROTTLE_MS);
results.opentimestamps = await otsProvider();

// ---------------- report ----------------

let blocking = [];
console.log('');
for (const [key, r] of Object.entries(results)) {
  const flag = r.blocking ? 'BLOCKING' : r.status.toUpperCase();
  console.log(`${flag.padEnd(9)} ${key.padEnd(15)} via=${(r.via || '-').padEnd(6)} ${r.blocking || r.detail || ''}`);
  if (r.blocking) blocking.push(`${key}: ${r.blocking}`);
}

if (WRITE_HEALTH) {
  // No timestamp on purpose: the scheduled workflow commits this file only
  // when provider status actually changes, so the diff must be meaningful.
  const health = {};
  for (const [key, r] of Object.entries(results)) {
    health[key] = { status: r.blocking ? 'degraded' : r.status };
    if (r.calendars_ok !== undefined) health[key].calendars_ok = r.calendars_ok;
  }
  mkdirSync(dirname(HEALTH_PATH), { recursive: true });
  writeFileSync(HEALTH_PATH, JSON.stringify(health, null, 2) + '\n');
  console.log(`\nhealth written: ${HEALTH_PATH}`);
}

if (blocking.length) {
  console.error(`\nDEPLOY-BLOCKING failures:\n  ${blocking.join('\n  ')}`);
  process.exit(1);
}
const degraded = Object.entries(results).filter(([, r]) => r.status !== 'ok').map(([k]) => k);
console.log(degraded.length ? `\ndegraded (third-party, non-blocking): ${degraded.join(', ')}` : '\nall providers green');
