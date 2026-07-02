// check-root-freshness.mjs — warn when any PINNED ROOT is within 90 days of
// expiry (spec §6). Roots only: chain files contain short-lived leaves that
// rotate on the authority's schedule and are refreshed by re-running
// scripts/fetch-roots.mjs. Emits GitHub Actions ::warning annotations; only a
// root that is ALREADY expired fails the gate.

import { readFileSync } from 'fs';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { pkijs, asn1js } from '../public/vendor/pkijs.bundle.mjs';

const ROOTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'vendor', 'roots');
const ROOT_FILES = [
  'digicert-trusted-root-g4.pem',
  'sectigo-time-stamping-root-r46.pem',
  'freetsa-cacert.pem',
  'sigstore-tsa-root.pem',
  'github-tsa-root.pem',
];

const WARN_DAYS = 90;
let expired = 0;
let warned = 0;

for (const name of ROOT_FILES) {
  const pemText = readFileSync(join(ROOTS_DIR, name), 'utf8');
  const block = pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0];
  const der = Buffer.from(block.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s/g, ''), 'base64');
  const cert = new pkijs.Certificate({ schema: asn1js.fromBER(new Uint8Array(der).buffer).result });
  const notAfter = cert.notAfter.value;
  const daysLeft = Math.floor((notAfter.getTime() - Date.now()) / 86_400_000);
  if (daysLeft < 0) {
    console.error(`::error::pinned root EXPIRED: ${name} (notAfter ${notAfter.toISOString()})`);
    expired++;
  } else if (daysLeft <= WARN_DAYS) {
    console.log(`::warning::pinned root ${name} expires in ${daysLeft} days (${notAfter.toISOString()}) — refresh via scripts/fetch-roots.mjs`);
    warned++;
  } else {
    console.log(`ok  ${name}  ${daysLeft} days left (notAfter ${notAfter.toISOString()})`);
  }
}

if (expired) process.exit(1);
console.log(warned ? `root freshness: ${warned} warning(s)` : 'root freshness: all pins comfortably valid');
