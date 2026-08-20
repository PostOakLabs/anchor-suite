// gate-sigsum-budget-counter.mjs — offline gate for the add-leaf daily-budget
// counter in handleSigsumRelay (board row SIGSUM-BUDGET-COUNTER-1).
//
// Proves two things by invoking the Worker's fetch handler directly, with a
// stubbed global fetch standing in for seasalp:
//   1. an upstream 429 gets translated into the friendly budget message,
//      with the raw upstream text preserved in a detail line and
//      X-Sigsum-Token-State still present;
//   2. the predictive counter NEVER pre-blocks — even once the in-memory
//      count is already past the 288/24h budget, a submission that seasalp
//      itself accepts still gets relayed and returns seasalp's real 200,
//      never a synthetic local 429 (SO #34c).
//
// Each check gets its own fresh module instance (cache-busted import) so the
// in-memory per-isolate counter starts at zero and prior checks cannot leak
// state into later ones.

import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { pathToFileURL } from 'url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = join(HERE, '..', 'src', 'worker.mjs');

let failed = 0;
function check(label, cond, detail = '') {
  if (cond) {
    console.log('gate-sigsum-budget-counter: ' + label + '... ok');
  } else {
    failed++;
    console.error('gate-sigsum-budget-counter: ' + label + '... FAIL' + (detail ? ' — ' + detail : ''));
  }
}

async function freshWorker() {
  const url = pathToFileURL(WORKER_PATH).href + '?bust=' + Math.random().toString(36).slice(2);
  const mod = await import(url);
  return mod.default;
}

function addLeafRequest() {
  return new Request('https://anchor.ainumbers.co/relay/sigsum/add-leaf', {
    method: 'POST',
    body: 'message=aaaa\nsignature=bbbb\npublic_key=cccc\n',
  });
}

const realFetch = globalThis.fetch;
function stubFetch(fn) {
  globalThis.fetch = fn;
}
function restoreFetch() {
  globalThis.fetch = realFetch;
}

// ---- check 1: upstream 429 is translated, detail preserved -------------------

{
  const worker = await freshWorker();
  stubFetch(async () => new Response('rate limit: unknown domain\n', { status: 429 }));
  let res;
  try {
    res = await worker.fetch(addLeafRequest(), {});
  } finally {
    restoreFetch();
  }
  const body = await res.text();
  check('upstream 429 → friendly budget message',
    res.status === 429 && body.includes("daily Sigsum budget (288 entries) is spent"),
    `status=${res.status} body=${body}`);
  check('upstream 429 → raw upstream detail preserved',
    body.includes('rate limit: unknown domain'), `body=${body}`);
  check('upstream 429 → X-Sigsum-Budget-Note present',
    !!res.headers.get('X-Sigsum-Budget-Note'), `header=${res.headers.get('X-Sigsum-Budget-Note')}`);
  check('upstream 429 → X-Sigsum-Token-State still present',
    !!res.headers.get('X-Sigsum-Token-State'), `header=${res.headers.get('X-Sigsum-Token-State')}`);
}

// ---- check 2: non-429 upstream status passes through untouched ---------------

{
  const worker = await freshWorker();
  stubFetch(async () => new Response('trunk-size=5\n', { status: 200 }));
  let res;
  try {
    res = await worker.fetch(addLeafRequest(), {});
  } finally {
    restoreFetch();
  }
  const body = await res.text();
  check('upstream 200 → passed through unchanged',
    res.status === 200 && body === 'trunk-size=5\n' && !res.headers.get('X-Sigsum-Budget-Note'),
    `status=${res.status} body=${body}`);
}

// ---- check 3: predictive counter NEVER pre-blocks -----------------------------
// Drive the in-memory counter well past the 288/24h budget with upstream
// accepting every call, then send one more. If the counter pre-blocked, this
// last call would short-circuit to a local 429 without ever reaching fetch.
// It must not: it has to hit the stub and return the stub's real 200.

{
  const worker = await freshWorker();
  let upstreamCalls = 0;
  stubFetch(async () => {
    upstreamCalls++;
    return new Response('trunk-size=999\n', { status: 200 });
  });
  try {
    for (let i = 0; i < 300; i++) {
      await worker.fetch(addLeafRequest(), {});
    }
    const res = await worker.fetch(addLeafRequest(), {});
    const body = await res.text();
    check('301st submission (over the 288 budget) still reaches upstream',
      upstreamCalls === 301, `upstreamCalls=${upstreamCalls}`);
    check('301st submission (over the 288 budget) is NOT pre-blocked — returns upstream 200',
      res.status === 200 && body === 'trunk-size=999\n', `status=${res.status} body=${body}`);
  } finally {
    restoreFetch();
  }
}

if (failed > 0) {
  console.error(`\ngate-sigsum-budget-counter: ${failed} check(s) failed`);
  process.exit(1);
}
console.log('\ngate-sigsum-budget-counter: all checks passed');
