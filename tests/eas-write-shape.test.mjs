// eas-write-shape.test.mjs — gate for the EAS timestamp(bytes32) write shape.
// Offline: asserts the selector and calldata layout of real third-party
// transactions and the simulated-write eth_call results stored in
// tests/fixtures/eas-write-shape.fixture.json. No network, no key, no signing.
// Run: node tests/eas-write-shape.test.mjs

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(readFileSync(join(HERE, 'fixtures', 'eas-write-shape.fixture.json'), 'utf8'));

const EAS = '0x4200000000000000000000000000000000000021';
const SELECTOR = '0x4d003070';
const HEX32 = /^0x[0-9a-f]{64}$/;
const failures = [];
const check = (ok, msg) => { if (!ok) failures.push(msg); };

check(fx.selector === SELECTOR, `fixture selector ${fx.selector} != ${SELECTOR}`);
check(fx.signature === 'timestamp(bytes32)', 'fixture signature is not timestamp(bytes32)');
// The selector is cross-checked against the third-party calldata below.
check(Array.isArray(fx.cases) && fx.cases.length >= 2, 'fixture needs a Base Sepolia and a Base mainnet case');
check(new Set(fx.cases.map((c) => c.chain_id)).size === fx.cases.length, 'duplicate chain_id among cases');

for (const c of fx.cases) {
  const tag = c.name;
  const tx = c.eth_getTransactionByHash?.response?.result;
  check(!!tx, `${tag}: stored eth_getTransactionByHash result missing`);
  if (!tx) continue;
  check(parseInt(c.eth_chainId.response.result, 16) === c.chain_id, `${tag}: eth_chainId does not match chain_id`);
  check(tx.hash === c.tx, `${tag}: stored tx hash differs from case tx`);
  check(typeof tx.to === 'string' && tx.to.toLowerCase() === EAS, `${tag}: tx.to is not the EAS predeploy`);
  // Third-party sender: must not be the arbitrary address used for the simulation.
  check(tx.from.toLowerCase() !== fx.simulated_from.toLowerCase(), `${tag}: tx.from equals simulated_from`);
  // Calldata layout: 4-byte selector + exactly one 32-byte word, nothing else.
  const input = tx.input;
  check(typeof input === 'string' && input.length === 2 + 8 + 64, `${tag}: calldata length ${input?.length} != 74`);
  check(input.slice(0, 10) === SELECTOR, `${tag}: calldata selector ${input.slice(0, 10)} != ${SELECTOR}`);
  check(HEX32.test('0x' + input.slice(10)), `${tag}: calldata argument is not one lowercase 32-byte word`);
  check('0x' + input.slice(10) === c.data, `${tag}: calldata argument != case data`);
  check(HEX32.test(c.data), `${tag}: case data is not 32 bytes of lowercase hex`);

  // Simulated write: request layout.
  for (const key of ['simulated_write_negative_control', 'simulated_write_positive_control']) {
    const s = c[key];
    const call = s.request.params[0];
    check(s.request.method === 'eth_call', `${tag}/${key}: method is ${s.request.method}, want eth_call`);
    check(call.to.toLowerCase() === EAS, `${tag}/${key}: eth_call target is not EAS`);
    check(call.from.toLowerCase() === fx.simulated_from.toLowerCase(), `${tag}/${key}: unexpected from`);
    check(call.data.slice(0, 10) === SELECTOR && call.data.length === 74, `${tag}/${key}: simulated calldata shape wrong`);
    check(s.request.params.length === 2, `${tag}/${key}: eth_call carries a state override or extra param`);
    check(!('signature' in call) && !('r' in call) && !('s' in call), `${tag}/${key}: eth_call carries signature fields`);
  }
  const neg = c.simulated_write_negative_control;
  check('0x' + neg.request.params[0].data.slice(10) === c.data, `${tag}: negative control does not use the stamped hash`);
  check(neg.response.error?.data === fx.already_timestamped_error_selector,
    `${tag}: negative control revert data ${neg.response.error?.data} != ${fx.already_timestamped_error_selector}`);
  const pos = c.simulated_write_positive_control;
  check('0x' + pos.request.params[0].data.slice(10) === pos.data, `${tag}: positive control data mismatch`);
  check(pos.data !== c.data, `${tag}: positive control reuses the stamped hash`);
  const r = pos.response.result;
  check(typeof r === 'string' && /^0x[0-9a-f]{64}$/.test(r) && BigInt(r) > 0n && BigInt(r) < 2n ** 64n,
    `${tag}: positive control result is not a non-zero uint64 word`);
}

// Fixture must not carry key material or a send path.
const text = readFileSync(join(HERE, 'fixtures', 'eas-write-shape.fixture.json'), 'utf8');
check(!/eth_send|privateKey|private_key|mnemonic/i.test(text), 'fixture mentions a send method or key material');

if (failures.length) {
  console.error(`eas-write-shape: FAIL (${failures.length})`);
  for (const f of failures) console.error('  - ' + f);
  process.exit(1);
}
console.log(`eas-write-shape: OK (${fx.cases.length} cases, selector ${SELECTOR})`);
