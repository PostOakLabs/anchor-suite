// tsa-relay — the only server-side code in the Anchor Suite.
//
// Classic CA timestamp authorities (DigiCert, Sectigo, FreeTSA) send no CORS
// headers, so browsers cannot POST a TimeStampReq to them directly. This Worker
// is a stateless, body-verbatim pipe: DER in, DER out. It parses nothing,
// stores nothing, and never logs a request or response body.
//
// Contract (ANCHOR-SUITE-BUILD-SPEC §4):
//   - POST /relay/{digicert|sectigo|freetsa} only; anything else 404/405.
//   - Request Content-Type must be application/timestamp-query, body <= 2 KB.
//   - Response is the upstream body verbatim as application/timestamp-reply.
//   - CORS allows https://anchor.ainumbers.co only.
//   - 4 requests/min/IP (also satisfies Sectigo's >=15s pacing politeness).
//   - 25s upstream timeout; upstream failure passes the status through with a
//     plain error body (never the upstream body, which is unverified on error).

const UPSTREAMS = {
  digicert: 'http://timestamp.digicert.com',
  sectigo: 'http://timestamp.sectigo.com',
  freetsa: 'https://freetsa.org/tsr',
};

const ALLOWED_ORIGIN = 'https://anchor.ainumbers.co';
const MAX_BODY_BYTES = 2048;
const UPSTREAM_TIMEOUT_MS = 25_000;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
  'Vary': 'Origin',
};

function textResponse(status, message) {
  return new Response(message + '\n', {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      ...CORS_HEADERS,
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // run_worker_first routes only /relay/* here; everything else is served
    // straight from static assets. Fall through defensively anyway.
    if (!url.pathname.startsWith('/relay/')) {
      return env.ASSETS.fetch(request);
    }

    const key = url.pathname.slice('/relay/'.length);
    const upstream = UPSTREAMS[key];
    if (!upstream) {
      return textResponse(404, 'Unknown relay path. Valid: /relay/digicert, /relay/sectigo, /relay/freetsa.');
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    if (request.method !== 'POST') {
      return textResponse(405, 'POST only.');
    }

    const contentType = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
    if (contentType !== 'application/timestamp-query') {
      return textResponse(415, 'Content-Type must be application/timestamp-query.');
    }

    const body = await request.arrayBuffer();
    if (body.byteLength === 0) {
      return textResponse(400, 'Empty body. Send a DER-encoded RFC 3161 TimeStampReq.');
    }
    if (body.byteLength > MAX_BODY_BYTES) {
      return textResponse(413, 'Body too large. TimeStampReq must be 2 KB or less.');
    }

    // 4/min/IP. The binding is a sliding-window counter keyed on the caller IP;
    // nothing about the request is stored.
    if (env.RELAY_LIMITER) {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env.RELAY_LIMITER.limit({ key: ip });
      if (!success) {
        const res = textResponse(429, 'Rate limit: 4 timestamps per minute per IP. Wait and retry.');
        res.headers.set('Retry-After', '15');
        return res;
      }
    }

    let upstreamRes;
    try {
      upstreamRes = await fetch(upstream, {
        method: 'POST',
        headers: { 'Content-Type': 'application/timestamp-query' },
        body,
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      });
    } catch {
      return textResponse(504, 'Timestamp authority did not answer within 25 seconds.');
    }

    if (!upstreamRes.ok) {
      return textResponse(upstreamRes.status, 'Timestamp authority returned HTTP ' + upstreamRes.status + '.');
    }

    const reply = await upstreamRes.arrayBuffer();
    return new Response(reply, {
      status: 200,
      headers: {
        'Content-Type': 'application/timestamp-reply',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        ...CORS_HEADERS,
      },
    });
  },
};
