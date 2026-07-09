# AUD-F3L — Live-CSP browser check (anchor-suite, main)

**Date:** 2026-07-09
**Claim under test:** the static inline-script gate (`scripts/check-no-inline-scripts.mjs`) is green, but that only proves no *literal* inline-script tags exist — it can't see whether the browser actually executes the page's JS under the estate's real CSP response header. This is the exact failure class that once took the whole `/sign/*` surface dead silently (drop-zone, banner, passkey flow never fired; no error surfaced to a static check).

**Method:** live browser (Chrome, via claude-in-chrome MCP) against the production origin `https://anchor.ainumbers.co`, so the CSP enforced is the real header the CDN/edge sends — not a local dev-server approximation.

## Live CSP header (confirmed identical on all 5 pages via `curl -I`)

```
content-security-policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self';
  connect-src 'self' https://timestamp.sigstore.dev https://timestamp.githubapp.com
    https://alice.btc.calendar.opentimestamps.org https://bob.btc.calendar.opentimestamps.org
    https://finney.calendar.eternitywall.com https://btc.calendar.catallaxy.com;
  manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none';
  frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types default
```

No `'unsafe-inline'`, no `'unsafe-eval'`, no script nonce/hash — `require-trusted-types-for 'script'` is the strictest posture available. Any inline script, inline event handler, or `javascript:` URL is a silent no-op under this policy, which is why the dynamic check (not just the static grep) matters.

## Results

| Page | Console CSP violations | JS initialized | Verdict |
|---|---|---|---|
| `/anchor.html` | none | drop-zone button, sha256 input + Copy button all present/wired | **PASS** |
| `/verify.html` | none | drop-zone button + "verify without this page (openssl)" fallback link present | **PASS** |
| `/sign/sign.html` | none | drop-zone button present | **PASS** |
| `/sign/request.html` | none | drop-zone button + Copy button present | **PASS** |
| `/sign/verify.html` | none | both drop-zones + Verify button present; clicked Verify (no files loaded) — no console error, no CSP violation | **PASS** |

Console output on every page was limited to a MetaMask browser-extension content-script warning stream (`EventEmitter memory leak`, `ObjectMultiplex ...`) — unrelated to the site, sourced from `chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/...`, not the page origin. Filtered for `Content Security Policy|Refused|CSP` explicitly: **zero matches on all 5 pages.**

Nav/header links (`Anchor`, `Verify`, `Sign`, `Library`, `Integrate`, `Docs`) rendered and resolved on every page, confirming shared layout JS also runs cleanly.

**Verdict: 5/5 PASS.** No CSP violation on any page; every page's interactive JS (drop-zone bindings, buttons, links) is live under the real production CSP.

## Headless gate: not landed — here's why

Checked `package.json` / `node_modules`: this repo has no browser-automation dependency (`puppeteer`, `playwright`, etc.) — `devDependencies` is `wrangler` only. A repeatable headless CSP-execution check requires launching a real browser engine that enforces CSP (a plain Node `fetch` cannot — CSP is enforced by the browser's script/eval loader, not visible to a static HTTP client). Adding a headless-browser dependency to this repo purely for one audit gate is a meaningful dependency-surface change (bundle size, CI runtime, new supply-chain surface) that sits outside this audit's scope fence (§ "SCOPE FENCE: audit + gates only. NO product refactors").

**Recommendation (not actioned — out of scope for this audit):** if a repeatable version of this check becomes worth the dependency cost, `playwright` (not full puppeteer/Chromium-per-OS bloat — supports a single `chromium` install) is the lighter path; the check itself is ~20 lines (load each page, assert `page.on('console')` never emits a `securitypolicyviolation`-sourced message, assert a known post-init DOM marker like the drop-zone button exists). Until then, this manual live-verify result is the deliverable per spec §AUD-F3L: *"Only land a gate if a repeatable headless check is practical; otherwise document the manual live-verify result."*

## Repro commands

```bash
# CSP header check
for p in /anchor.html /verify.html /sign/sign.html /sign/request.html /sign/verify.html; do
  curl -sI "https://anchor.ainumbers.co$p" | grep -i content-security-policy
done
```

Browser checks were run interactively via the claude-in-chrome MCP tab (navigate → read_console_messages filtered on `Content Security Policy|Refused|CSP` → read_page interactive-element dump) against each of the 5 URLs above.

## DONE checklist

- [x] Results table {area, case, expected, actual, verdict} above
- [ ] New gate shown passing/failing on fixtures — N/A, no gate landed (see rationale above)
- [ ] Gate wired into CI — N/A, no gate landed
- [x] N/A — no judgment-call item requiring DEFER-TO-OPUS in this area
- [x] Verify commands pasted with output above; worktree `../.worktrees/aud-f3l` off `origin/main`, branch `aud-f3l-live-csp`
- [x] Out-of-scope observation noted: headless-gate dependency addition, not actioned
