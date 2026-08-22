// gate-sigsum-session-token.mjs — offline gate for conditional Sigsum-Token
// attachment and the removal of the public token-state header (board row
// ANCHOR-SIGSUM-DRAIN-FIX-1; audit findings A1 HIGH + A3 LOW-MED,
// 0xAlpha/2026-08-21-worker-attack-surface-audit.md §2).
//
// It invokes the Worker's fetch handler directly with a stubbed global fetch
// standing in for seasalp, so every assertion is about what WE send upstream
// and what we return downstream — never about the log's behavior.
//
// Proves, mechanically:
//   1. a request carrying a valid first-party session artifact submits WITH
//      the domain-bound Sigsum-Token (our 288/24h bucket);
//   2. a request without one submits WITHOUT the token and is STILL relayed
//      (anonymous anchoring keeps working, in the log's shared pool);
//   3. a tampered artifact, an artifact minted for a different caller, and an
//      expired artifact all degrade to the tokenless path — never a rejection;
//   4. no public Response on any add-leaf path carries X-Sigsum-Token-State
//      (the drain-confirmation oracle A3 names), on 200 or on 429;
//   5. the 429 copy names the pool that actually ran out, per branch;
//   6. with no token secret configured the mint route answers honestly
//      (session: null) and add-leaf still relays.
//
// The signing key is generated fresh in-process: no key material is committed,
// and the gate can never pass by reading a value the Worker also read (SO #34 —
// the token bytes it asserts on are recomputed here from the generated key).

import { dirname, join } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = join(HERE, '..', 'src', 'worker.mjs');
const CLIENT_PATH = join(HERE, '..', 'public', 'lib', 'sigsum.mjs');

const SESSION_HEADER = 'X-Anchor-Session';
const CLIENT_IP = '203.0.113.7';
const OTHER_IP = '198.51.100.9';

let failed = 0;
function check(label, cond, detail = '') {
  if (cond) {
    console.log('gate-sigsum-session-token: ' + label + '... ok');
  } else {
    failed++;
    console.error('gate-sigsum-session-token: ' + label + '... FAIL' + (detail ? ' — ' + detail : ''));
  }
}

// Each check gets its own module instance so the per-isolate token/session key
// caches start empty and cannot leak between checks.
async function freshWorker() {
  const url = pathToFileURL(WORKER_PATH).href + '?bust=' + Math.random().toString(36).slice(2);
  return (await import(url)).default;
}

async function envWithKey() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { SIGSUM_TOKEN_PRIVATE_KEY_JWK: JSON.stringify(jwk) };
}

function addLeafRequest({ session, ip = CLIENT_IP } = {}) {
  const headers = { 'CF-Connecting-IP': ip };
  if (session) headers[SESSION_HEADER] = session;
  return new Request('https://anchor.ainumbers.co/relay/sigsum/add-leaf', {
    method: 'POST',
    headers,
    body: 'message=aaaa\nsignature=bbbb\npublic_key=cccc\n',
  });
}

function sessionRequest(ip = CLIENT_IP) {
  return new Request('https://anchor.ainumbers.co/relay/sigsum/session', {
    method: 'GET',
    headers: { 'CF-Connecting-IP': ip },
  });
}

const realFetch = globalThis.fetch;
// Records what the Worker sent upstream and answers with the supplied response.
function stubUpstream(makeResponse) {
  const seen = [];
  globalThis.fetch = async (url, init = {}) => {
    const headers = new Headers(init.headers || {});
    seen.push({ url: String(url), token: headers.get('Sigsum-Token') });
    return makeResponse(seen.length);
  };
  return seen;
}
function restoreFetch() { globalThis.fetch = realFetch; }

// Tolerant on purpose: a worker WITHOUT the fix answers this route with a
// 404 text body, and this gate must report that as a named failed check rather
// than crash on JSON.parse (SO #34c — a checker that dies is not a verdict).
async function mintSession(worker, env, ip = CLIENT_IP) {
  const res = await worker.fetch(sessionRequest(ip), env);
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch (_) { body = { session: null, ttl_ms: 0, raw: text.trim() }; }
  return { res, body };
}

// ---- check 1+2: both branches, one worker instance ---------------------------
{
  const worker = await freshWorker();
  const env = await envWithKey();
  const { res: mintRes, body: mint } = await mintSession(worker, env);
  check('mint route returns an artifact when the token secret is configured',
    mintRes.status === 200 && typeof mint.session === 'string' && mint.session.startsWith('ains.v1.') && mint.ttl_ms > 0,
    `status=${mintRes.status} body=${JSON.stringify(mint)}`);
  check('mint route is no-store + nosniff',
    mintRes.headers.get('Cache-Control') === 'no-store' && mintRes.headers.get('X-Content-Type-Options') === 'nosniff',
    `cc=${mintRes.headers.get('Cache-Control')} nosniff=${mintRes.headers.get('X-Content-Type-Options')}`);

  const seen = stubUpstream(async () => new Response('202\n', { status: 202 }));
  let withSession, withoutSession;
  try {
    withSession = await worker.fetch(addLeafRequest({ session: mint.session }), env);
    withoutSession = await worker.fetch(addLeafRequest(), env);
  } finally {
    restoreFetch();
  }

  check('valid artifact → upstream add-leaf carries Sigsum-Token',
    seen.length === 2 && seen[0].url.endsWith('/add-leaf') && typeof seen[0].token === 'string'
      && seen[0].token.startsWith('ainumbers.co '),
    `seen=${JSON.stringify(seen)}`);
  check('valid artifact → caller still gets the log answer (202)',
    withSession.status === 202, `status=${withSession.status}`);
  check('NO artifact → upstream add-leaf carries NO Sigsum-Token (shared bucket)',
    seen[1] && seen[1].token === null, `seen=${JSON.stringify(seen[1])}`);
  check('NO artifact → submission is STILL relayed, caller still gets 202',
    seen.length === 2 && withoutSession.status === 202, `status=${withoutSession.status} calls=${seen.length}`);
  check('no X-Sigsum-Token-State on either response (A3)',
    !withSession.headers.get('X-Sigsum-Token-State') && !withoutSession.headers.get('X-Sigsum-Token-State'),
    `with=${withSession.headers.get('X-Sigsum-Token-State')} without=${withoutSession.headers.get('X-Sigsum-Token-State')}`);
}

// ---- check 3: tampered / foreign-caller / expired artifacts ------------------
{
  const worker = await freshWorker();
  const env = await envWithKey();
  const { body: mine } = await mintSession(worker, env);
  const { body: theirs } = await mintSession(worker, env, OTHER_IP);

  // Flip one payload character: the MAC must fail.
  const idx = 'ains.v1.'.length + 3;
  const tampered = mine.session.slice(0, idx)
    + (mine.session[idx] === 'A' ? 'B' : 'A')
    + mine.session.slice(idx + 1);

  // Expired: mint against a clock 20 minutes in the past (TTL is 10 minutes).
  const realNow = Date.now;
  Date.now = () => realNow() - 20 * 60 * 1000;
  let expired;
  try { expired = (await mintSession(worker, env)).body.session; } finally { Date.now = realNow; }

  const seen = stubUpstream(async () => new Response('202\n', { status: 202 }));
  let responses;
  try {
    responses = [
      await worker.fetch(addLeafRequest({ session: tampered }), env),
      await worker.fetch(addLeafRequest({ session: theirs.session }), env), // minted for OTHER_IP
      await worker.fetch(addLeafRequest({ session: expired }), env),
      await worker.fetch(addLeafRequest({ session: 'garbage' }), env),
    ];
  } finally {
    restoreFetch();
  }

  check('tampered artifact → tokenless', seen[0] && seen[0].token === null, JSON.stringify(seen[0]));
  check('artifact minted for a different caller → tokenless', seen[1] && seen[1].token === null, JSON.stringify(seen[1]));
  check('expired artifact → tokenless', seen[2] && seen[2].token === null, JSON.stringify(seen[2]));
  check('unparseable artifact → tokenless, no throw', seen[3] && seen[3].token === null, JSON.stringify(seen[3]));
  check('every invalid-artifact submission is still relayed with the log answer',
    seen.length === 4 && responses.every((r) => r.status === 202),
    `calls=${seen.length} statuses=${responses.map((r) => r.status).join(',')}`);
  check('no X-Sigsum-Token-State on any invalid-artifact response',
    responses.every((r) => !r.headers.get('X-Sigsum-Token-State')));
}

// ---- check 4+5: 429 copy per branch, still no state header -------------------
{
  const worker = await freshWorker();
  const env = await envWithKey();
  const { body: mint } = await mintSession(worker, env);

  stubUpstream(async () => new Response('rate limit: unknown domain\n', { status: 429 }));
  let tokened, tokenless;
  try {
    tokened = await worker.fetch(addLeafRequest({ session: mint.session }), env);
    tokenless = await worker.fetch(addLeafRequest(), env);
  } finally {
    restoreFetch();
  }
  const tokenedBody = await tokened.text();
  const tokenlessBody = await tokenless.text();

  check('429 with token → names ainumbers.co\'s own budget',
    tokened.status === 429 && tokenedBody.includes("ainumbers.co's daily Sigsum budget (288 entries) is spent"),
    `body=${tokenedBody}`);
  check('429 without token → does NOT claim our budget ran out',
    tokenless.status === 429 && !tokenlessBody.includes("ainumbers.co's daily Sigsum budget (288 entries) is spent")
      && tokenlessBody.includes('share an upstream pool'),
    `body=${tokenlessBody}`);
  check('429 both branches → raw upstream detail preserved',
    tokenedBody.includes('rate limit: unknown domain') && tokenlessBody.includes('rate limit: unknown domain'));
  check('429 both branches → no X-Sigsum-Token-State (A3)',
    !tokened.headers.get('X-Sigsum-Token-State') && !tokenless.headers.get('X-Sigsum-Token-State'));
}

// ---- check 6: no secret configured → honest mint, relay unaffected -----------
{
  const worker = await freshWorker();
  const { res, body } = await mintSession(worker, {});
  // body.raw is only set when the route did not answer JSON at all (no mint
  // route present), so this cannot pass by absence.
  check('no token secret → mint answers session:null rather than a fake artifact',
    res.status === 200 && body.raw === undefined && body.session === null && body.ttl_ms === 0,
    `status=${res.status} body=${JSON.stringify(body)}`);

  const seen = stubUpstream(async () => new Response('202\n', { status: 202 }));
  let relayed;
  try { relayed = await worker.fetch(addLeafRequest(), {}); } finally { restoreFetch(); }
  check('no token secret → add-leaf still relays, tokenless',
    relayed.status === 202 && seen.length === 1 && seen[0].token === null,
    `status=${relayed.status} seen=${JSON.stringify(seen)}`);
}

// ---- check 7: the browser client actually attaches the artifact ---------------
// Drives public/lib/sigsum.mjs's stampSigsum() against a stubbed same-origin
// relay, proving the header the Worker checks is the header the page sends.
{
  const clientUrl = pathToFileURL(CLIENT_PATH).href + '?bust=' + Math.random().toString(36).slice(2);
  const { stampSigsum } = await import(clientUrl);

  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const headers = new Headers(init.headers || {});
    const path = String(url);
    calls.push({ path, session: headers.get(SESSION_HEADER) });
    if (path.endsWith('/relay/sigsum/session')) {
      return Response.json({ session: 'ains.v1.stub.stub', ttl_ms: 600_000, header: SESSION_HEADER });
    }
    if (path.endsWith('/add-leaf')) return new Response('202\n', { status: 202 });
    return new Response('not found\n', { status: 404 }); // inclusion lookup: still pending
  };
  let pending;
  try {
    pending = await stampSigsum('a'.repeat(64));
  } finally {
    restoreFetch();
  }

  const mintCall = calls.find((c) => c.path.endsWith('/relay/sigsum/session'));
  const addLeafCall = calls.find((c) => c.path.endsWith('/add-leaf'));
  check('client mints a session artifact before submitting', !!mintCall, `calls=${JSON.stringify(calls)}`);
  check('client sends the artifact on add-leaf',
    !!addLeafCall && addLeafCall.session === 'ains.v1.stub.stub', JSON.stringify(addLeafCall));
  check('client returns a pending binding for the submitted leaf',
    pending && pending.type === 'c2sp-tlog-pending-v1' && typeof pending.leaf_hash === 'string',
    JSON.stringify(pending && pending.type));
}

if (failed > 0) {
  console.error(`\ngate-sigsum-session-token: ${failed} check(s) failed`);
  process.exit(1);
}
console.log('\ngate-sigsum-session-token: all checks passed');
