# Vendored libraries

Everything the pages load is committed in this repo. No CDNs, no runtime npm. Hashes are SHA-256 of the committed files, recorded 2026-07-02.

| File | What | Version / pin | License | SHA-256 |
|---|---|---|---|---|
| `public/vendor/pkijs.bundle.mjs` | PKI.js + asn1js, bundled once with esbuild 0.28.1 into a single ES module (`export * as pkijs`, `export * as asn1js`) | pkijs 3.4.0, asn1js 3.0.10 (npm) | BSD-3-Clause | `f1c2f9e8991bb28c76812ae5eda25b0693373609ef21748e4775bf902e0f1e40` |
| `public/vendor/opentimestamps.min.js` | javascript-opentimestamps official browser bundle, the exact file the opentimestamps.org web stamper serves (UMD, exposes `window.OpenTimestamps`) | opentimestamps/opentimestamps.org commit `6c0ca1ac6191605dee15475f33de9ff1b226a301` (byte-identical to the live site copy at vendor time) | LGPL-3.0 | `f6181ae00cce58773f8710894c99d0656058f6a1e08c57360b263cd46c54fbf2` |
| `public/vendor/ocg/verify.mjs` | OpenChainGraph offline verifier entry points (section 4 execution hash, section 16 signature, section 18 compute proof) | byte-identical copy of `embed/verify.mjs` from PostOakLabs/ainumbers-mcp-apps (OCGR Phase D bundle) | MIT | `ee89fea22ebea98e668257feed16d370f80aa5f5c8d5cf4ae88d3f3433beb4b9` |
| `public/vendor/ocg/lib/_hash.mjs` | Canonical OCG hashing primitives | byte-identical copy from the same bundle | MIT | `22eb174cb80d8794fa55dfc26d8fbc854daf0fdbb4c7720d2614da62017638bc` |
| `public/vendor/ocg/lib/_proof.mjs` | eddsa-jcs-2022 Data Integrity sign/verify | byte-identical copy from the same bundle | MIT | `96c2abbf56bddc81d44e107bbc721f67348a8072064f06a36032d02020ee6d94` |
| `public/vendor/ocg/lib/_computeproof.mjs` | risc0 Groth16-BN254 seal verifier | byte-identical copy from the same bundle | MIT | `bcc92a9b4ebb36cef87327bc067f33e858b1af8f774f0431a173a5651a08bbf9` |
| `public/vendor/ocg/lib/_noble-bn254.bundle.mjs` | Vendored @noble BN254 curve bundle used by the seal verifier | byte-identical copy from the same bundle | MIT | `82bf63d7e57d03d15fd3cde95018fd8c7643a08526b793c17a8537cf5006ca51` |

Pinned TSA roots live in `public/vendor/roots/` and are documented separately in [ROOTS.md](ROOTS.md).

Update procedure: bump the version in a branch, rebuild or refetch the file, update the hash here, and let the CI gates (including the TSA smoke harness, which exercises PKI.js end to end) prove the update before merge. The OCG verifier copies must stay byte-identical to the upstream bundle; never patch them locally.
