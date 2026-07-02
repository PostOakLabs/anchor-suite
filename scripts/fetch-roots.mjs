// fetch-roots.mjs — one-time (and re-runnable) fetch of the pinned TSA trust roots.
//
// Downloads each authority's root or chain from its authoritative source, converts
// to PEM, writes public/vendor/roots/*.pem plus a roots.mjs constants module, and
// prints the sha256 of every committed file for ROOTS.md. Re-run to refresh; the
// CI pin-freshness gate only reads the committed files and never fetches.
//
// Usage: node scripts/fetch-roots.mjs

import { writeFileSync, mkdirSync } from 'fs';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { pkijs, asn1js } from '../public/vendor/pkijs.bundle.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOTS_DIR = join(HERE, '..', 'public', 'vendor', 'roots');
mkdirSync(ROOTS_DIR, { recursive: true });

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function derToPem(der, label = 'CERTIFICATE') {
  const b64 = Buffer.from(der).toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function pemBlocks(text) {
  return (text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [])
    .map((b) => b.replace(/\r/g, '') + '\n');
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s/g, '');
  return Buffer.from(b64, 'base64');
}

function certSubject(pem) {
  const asn = asn1js.fromBER(new Uint8Array(pemToDer(pem)).buffer);
  const cert = new pkijs.Certificate({ schema: asn.result });
  const get = (tv) => tv.typesAndValues?.map((t) => t.value.valueBlock.value).join(', ');
  return { subject: get(cert.subject), issuer: get(cert.issuer), notAfter: cert.notAfter.value.toISOString() };
}

// A chain endpoint returns leaf -> intermediates -> root. The root is the
// self-signed tail (subject === issuer).
function pickRoot(blocks) {
  for (const b of blocks) {
    const { subject, issuer } = certSubject(b);
    if (subject === issuer) return b;
  }
  return blocks[blocks.length - 1];
}

async function fetchBuf(url, init) {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

const written = [];
function save(name, content, sourceUrl) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const path = join(ROOTS_DIR, name);
  writeFileSync(path, buf);
  written.push({ name, sha256: sha256(buf), sourceUrl });
  const info = name.endsWith('.pem') ? certSubject(pemBlocks(buf.toString())[pemBlocks(buf.toString()).length - 1] ?? pemBlocks(buf.toString())[0]) : {};
  console.log(`written ${name}  sha256:${sha256(buf)}`);
  if (info.subject) console.log(`  root subject: ${info.subject}\n  notAfter: ${info.notAfter}`);
}

// 1. DigiCert Trusted Root G4 (anchors the DigiCert Trusted G4 TimeStamping chain).
{
  const url = 'https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem';
  const pem = (await fetchBuf(url)).toString().replace(/\r/g, '');
  save('digicert-trusted-root-g4.pem', pem, url);
}

// Shared helpers for the Sectigo AIA walk and the GitHub TST fallback.
function parseCert(der) {
  const asn = asn1js.fromBER(new Uint8Array(der).buffer);
  return new pkijs.Certificate({ schema: asn.result });
}
const certDer = (cert) => Buffer.from(cert.toSchema().toBER(false));
const dnString = (rdn) => rdn.typesAndValues.map((t) => t.value.valueBlock.value).join(', ');
const isSelfSigned = (cert) => dnString(cert.subject) === dnString(cert.issuer);

function caIssuerUrls(cert) {
  const ext = (cert.extensions || []).find((e) => e.extnID === '1.3.6.1.5.5.7.1.1');
  if (!ext?.parsedValue?.accessDescriptions) return [];
  return ext.parsedValue.accessDescriptions
    .filter((d) => d.accessMethod === '1.3.6.1.5.5.7.48.2' && d.accessLocation.type === 6)
    .map((d) => d.accessLocation.value);
}

async function fetchCerts(url) {
  const buf = await fetchBuf(url);
  try { return [parseCert(buf)]; } catch { /* not a bare cert; try PKCS7 */ }
  const asn = asn1js.fromBER(new Uint8Array(buf).buffer);
  const ci = new pkijs.ContentInfo({ schema: asn.result });
  const sd = new pkijs.SignedData({ schema: ci.content });
  return sd.certificates || [];
}

function buildTsqDer(message) {
  const hash = createHash('sha256').update(message).digest();
  const nonce = crypto.getRandomValues(new Uint8Array(8));
  nonce[0] &= 0x7f;
  const tsq = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: '2.16.840.1.101.3.4.2.1', algorithmParams: new asn1js.Null() }),
      hashedMessage: new asn1js.OctetString({ valueHex: new Uint8Array(hash).buffer }),
    }),
    nonce: new asn1js.Integer({ valueHex: nonce.buffer }),
    certReq: true,
  });
  return tsq.toSchema().toBER(false);
}

async function stampCerts(url) {
  const respBuf = await fetchBuf(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: buildTsqDer('anchor-suite root pin probe'),
  });
  const asn = asn1js.fromBER(new Uint8Array(respBuf).buffer);
  const tsr = new pkijs.TimeStampResp({ schema: asn.result });
  if (![0, 1].includes(tsr.status.status)) throw new Error(`TSA status ${tsr.status.status}`);
  const signed = new pkijs.SignedData({ schema: tsr.timeStampToken.content });
  return signed.certificates || [];
}

// 2. Sectigo Public Time Stamping Root R46. crt.sectigo.com is an AIA
//    distribution host (plain HTTP, like the AIA URLs inside the certs);
//    its TLS endpoint rejects modern handshakes. Fallback: stamp at the TSA
//    and walk caIssuers AIA links up to the self-signed root.
{
  const candidates = [
    'http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.crt',
    'http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c',
  ];
  let rootPem = null;
  let source = null;
  for (const url of candidates) {
    try {
      const certs = await fetchCerts(url);
      const self = certs.find(isSelfSigned) || certs[0];
      if (self) { rootPem = derToPem(certDer(self)); source = url; break; }
    } catch (e) { console.log(`  sectigo candidate failed: ${url} (${e.message})`); }
  }
  if (!rootPem) {
    console.log('  falling back to TST chain + AIA walk');
    const certs = await stampCerts('http://timestamp.sectigo.com');
    let top = certs.find((c) => !certs.some((o) => dnString(o.subject) === dnString(c.issuer) && o !== c)) || certs[certs.length - 1];
    for (let hops = 0; !isSelfSigned(top) && hops < 5; hops++) {
      const urls = caIssuerUrls(top);
      if (!urls.length) throw new Error('AIA walk dead-ends before a self-signed root: ' + dnString(top.subject));
      const parents = await fetchCerts(urls[0]);
      top = parents.find(isSelfSigned) || parents[0];
    }
    if (!isSelfSigned(top)) throw new Error('Sectigo AIA walk never reached a self-signed root');
    rootPem = derToPem(certDer(top));
    source = 'http://timestamp.sectigo.com TST chain + AIA caIssuers walk';
  }
  save('sectigo-time-stamping-root-r46.pem', rootPem, source);
}

// 3. FreeTSA root CA (ECC, valid to 2040).
{
  const url = 'https://freetsa.org/files/cacert.pem';
  const pem = (await fetchBuf(url)).toString().replace(/\r/g, '');
  save('freetsa-cacert.pem', pemBlocks(pem).join(''), url);
}

// 4. Sigstore TSA chain (leaf..root) from the TSA's own certchain endpoint.
{
  const url = 'https://timestamp.sigstore.dev/api/v1/timestamp/certchain';
  const pem = (await fetchBuf(url)).toString().replace(/\r/g, '');
  const blocks = pemBlocks(pem);
  save('sigstore-tsa-certchain.pem', blocks.join(''), url);
  save('sigstore-tsa-root.pem', pickRoot(blocks), url + ' (self-signed tail of the chain)');
}

// 5. GitHub TSA chain. GitHub runs the sigstore timestamp-authority server, so
//    the same certchain endpoint shape is expected; fall back to extracting the
//    certificates from a real TimeStampResp (certReq=true) if it is absent.
{
  const chainUrl = 'https://timestamp.githubapp.com/api/v1/timestamp/certchain';
  let blocks = null;
  let source = chainUrl;
  try {
    const pem = (await fetchBuf(chainUrl)).toString().replace(/\r/g, '');
    blocks = pemBlocks(pem);
    if (!blocks.length) throw new Error('no PEM blocks');
  } catch (e) {
    console.log(`certchain endpoint failed (${e.message}); extracting from a TST response instead`);
    const certs = await stampCerts('https://timestamp.githubapp.com/api/v1/timestamp');
    blocks = certs.map((c) => derToPem(certDer(c)));
    source = 'https://timestamp.githubapp.com/api/v1/timestamp (certificates in a certReq=true TST response)';
  }
  save('github-tsa-certchain.pem', blocks.join(''), source);
  save('github-tsa-root.pem', pickRoot(blocks), source + ' (self-signed tail of the chain)');
}

// Constants module for the pages and the smoke harness.
{
  const read = (n) => written.find((w) => w.name === n);
  const { readFileSync } = await import('fs');
  const pem = (n) => readFileSync(join(ROOTS_DIR, n), 'utf8');
  const mod = [
    '// Pinned TSA trust roots — generated by scripts/fetch-roots.mjs, committed.',
    '// Sources and hashes: ROOTS.md. Do not hand-edit; re-run the script to refresh.',
    'export const PINNED_ROOTS = {',
    `  digicert: ${JSON.stringify(pem('digicert-trusted-root-g4.pem'))},`,
    `  sectigo: ${JSON.stringify(pem('sectigo-time-stamping-root-r46.pem'))},`,
    `  freetsa: ${JSON.stringify(pem('freetsa-cacert.pem'))},`,
    `  sigstore: ${JSON.stringify(pem('sigstore-tsa-root.pem'))},`,
    `  github: ${JSON.stringify(pem('github-tsa-root.pem'))},`,
    '};',
    '',
    'export const PINNED_CHAINS = {',
    `  sigstore: ${JSON.stringify(pem('sigstore-tsa-certchain.pem'))},`,
    `  github: ${JSON.stringify(pem('github-tsa-certchain.pem'))},`,
    '};',
    '',
  ].join('\n');
  writeFileSync(join(ROOTS_DIR, 'roots.mjs'), mod);
  console.log('written roots.mjs');
  void read;
}

console.log('\nROOTS.md table data:');
for (const w of written) console.log(`| ${w.name} | ${w.sourceUrl} | ${w.sha256} |`);
