# Vendored libraries

All third-party code committed in this directory is vendored locally.
No CDNs. No runtime fetches from external origins for JS/CSS assets.

---

## mammoth.browser.min.js

**Package:** mammoth 1.9.1
**License:** BSD-2-Clause
**Source URL:** https://cdn.jsdelivr.net/npm/mammoth@1.9.1/mammoth.browser.min.js (npm registry build, same content as the npm tarball's `mammoth.browser.min.js`)
**sha256:** 78afc1f7bd08792370110cb54946ea48adb64b35ad21f6126d21f2d8e00d3a00
**Purpose:** DOCX to HTML conversion for the Conversion Lab's DOCX to Markdown/HTML tool (`/convert/docx-to-markdown.html`). Sets `window.mammoth`.
**License text:** `mammoth-LICENSE` in this directory.
**CSP note:** loads and runs clean under this site's `script-src 'self'` (no `unsafe-eval`) and Trusted Types (`require-trusted-types-for 'script'`) headers — verified locally with a real DOCX fixture before landing. Its bundled bluebird/lodash use `new Function` internally on some code paths but those paths were not observed to fire during a normal `convertToHtml` call in this test; if a future browser/CSP combination trips a violation there, the fix is a version bump, not a CSP relaxation.
**Load order:** Must be a plain `<script>` before `docx-to-markdown.js`, which uses `window.mammoth`.

---

## pdfjs.min.mjs + pdfjs.worker.min.mjs

**Package:** pdfjs-dist 6.1.200
**License:** Apache-2.0
**Source URL:** https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-6.1.200.tgz (`package/build/pdf.min.mjs`, `package/build/pdf.worker.min.mjs`, npm tarball build)
**sha256 (pdfjs.min.mjs):** 4ba2f15599b03fde8755ad91349920c21dadd3e8fd6b6460a7663d46d4cf21b5
**sha256 (pdfjs.worker.min.mjs):** 2ab9e09667296dab1a618868b3ce6e6c23d5b8f48120ae7c5b34e7e335ed01fa
**Purpose:** PDF text-layer extraction for the Conversion Lab's PDF to Markdown tool (`/convert/pdf-to-markdown.html`). ESM module — `import * as pdfjsLib from '/vendor/pdfjs.min.mjs'`; the module then points `pdfjsLib.GlobalWorkerOptions.workerSrc` at the vendored worker (same-origin, no CDN).
**License text:** `pdfjs-LICENSE` in this directory.
**Load order:** ESM `import` in `pdf-to-markdown.js`; the worker file is fetched same-origin by pdf.js at runtime, not loaded via `<script>`.

---

## pdf-lib.min.js

**Package:** pdf-lib 1.17.1
**License:** MIT
**Source URL:** https://cdn.jsdelivr.net/npm/pdf-lib@1.17.1/dist/pdf-lib.min.js (npm registry build, UMD)
**sha256:** 0f9a5cad07941f0826586c94e089d89b918c46e5c17cf2d5a3c6f666e3bc694f
**Purpose:** PDF merge/split/extract-pages/strip-metadata for the Conversion Lab's PDF toolkit (`/convert/pdf-toolkit.html`). Sets `window.PDFLib`.
**License text:** `pdf-lib-LICENSE` in this directory.
**CSP note:** UMD build, no `eval`/`new Function` in the byte manipulation paths exercised by this tool; loads under `script-src 'self'` and Trusted Types like the other vendored engines.
**Load order:** Must be a plain `<script>` before `pdf-toolkit.js`, which uses `window.PDFLib`.

---

## pkijs.bundle.mjs

**Package:** pkijs 3.4.0 + asn1js 3.0.10  
**License:** MIT  
**Source URL:** https://cdn.jsdelivr.net/npm/pkijs@3.4.0/build/pkijs.js (bundled with asn1js)  
**Purpose:** RFC 3161 TST parsing + CMS signature verification for anchor and verify pages.  
**Export:** `import { pkijs, asn1js } from '/vendor/pkijs.bundle.mjs'`  
**Build note:** Custom bundle — pkijs exports wrapped as named `{ pkijs, asn1js }`.

---

## opentimestamps.min.js

**Package:** opentimestamps-client (official browser build)  
**License:** LGPL-3.0  
**Source URL:** https://opentimestamps.org/js/opentimestamps.min.js (commit 6c0ca1a)  
**Purpose:** OpenTimestamps stamping and verification. Sets `window.OpenTimestamps`.  
**Load order:** Must be a plain `<script>` before any ES module that uses it.

---

## idb-keyval.umd.js

**Package:** idb-keyval 6.2.6  
**License:** Apache-2.0  
**Source URL:** https://cdn.jsdelivr.net/npm/idb-keyval@6.2.6/dist/umd.js  
**sha256:** 11b58231fcbfec600bdfb0659ce72d6b4a97336529539cbc8faeeac6a7fead8c  
**Purpose:** IndexedDB key/value wrapper for the Artifact Library. Sets `globalThis.idbKeyval`.  
**Load order:** Must be a plain `<script>` before any ES module that imports `/lib/library-bridge.mjs`.

---

## json-viewer.js

**Package:** @andypf/json-viewer 2.8.0  
**License:** MIT  
**Source URL:** https://cdn.jsdelivr.net/npm/@andypf/json-viewer@2.8.0/dist/iife/index.js  
**sha256:** a1d010d1fa9526fe251ca1dc1a57b3e53fa93f5844c1019c3e161e3f7c6cb6dc  
**Purpose:** `<json-viewer data='...'>` web component for the Artifact Library detail view.  
**Usage:** Set the `data` attribute (JSON string) and optionally `expanded` (depth integer).  
**Load order:** Must be a plain `<script>` before any module that creates `<json-viewer>` elements.

---

## ocg/

Byte-identical copies of the OCG verifier library from the ainumbers-mcp-apps worker embed/.
These files must not drift from the worker embed — the CI gate `check-vendor-fresh` enforces this.

---

## roots/

Pinned TSA root and intermediate certificates generated by `scripts/fetch-roots.mjs`.
CI warns 90 days before any cert expires.
