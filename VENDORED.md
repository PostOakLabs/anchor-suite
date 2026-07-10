# Vendored libraries

Everything the pages load is committed in this repo. No CDNs, no runtime npm. Hashes are SHA-256 of the committed files (recorded 2026-07-02; OCG verifier rows re-stamped 2026-07-09 to the deployed bytes and now gated by `scripts/check-vendor-freshness.mjs`).

| File | What | Version / pin | License | SHA-256 |
|---|---|---|---|---|
| `public/vendor/pkijs.bundle.mjs` | PKI.js + asn1js, bundled once with esbuild 0.28.1 into a single ES module (`export * as pkijs`, `export * as asn1js`) | pkijs 3.4.0, asn1js 3.0.10 (npm) | BSD-3-Clause | `f1c2f9e8991bb28c76812ae5eda25b0693373609ef21748e4775bf902e0f1e40` |
| `public/vendor/opentimestamps.min.js` | javascript-opentimestamps official browser bundle, the exact file the opentimestamps.org web stamper serves (UMD, exposes `window.OpenTimestamps`) | opentimestamps/opentimestamps.org commit `6c0ca1ac6191605dee15475f33de9ff1b226a301` (byte-identical to the live site copy at vendor time) | LGPL-3.0 | `f6181ae00cce58773f8710894c99d0656058f6a1e08c57360b263cd46c54fbf2` |
| `public/vendor/ocg/verify.mjs` | OpenChainGraph offline verifier entry points (section 4 execution hash, section 16 signature, section 18 compute proof) | byte-identical copy of `embed/verify.mjs` from PostOakLabs/ainumbers-mcp-apps (OCGR Phase D bundle) | MIT | `b6c387e301cd07e7db09146fa00b373e52514e4c4e2768675707efe3d9cc25b1` |
| `public/vendor/ocg/lib/_hash.mjs` | Canonical OCG hashing primitives | byte-identical copy from the same bundle | MIT | `9d60ba8b9a14900b9cc1f4878de4e92f5d8e622a128413840be9ea94bbae1cfb` |
| `public/vendor/ocg/lib/_proof.mjs` | eddsa-jcs-2022 Data Integrity sign/verify | byte-identical copy from the same bundle | MIT | `50031c81f64e64282709813004d154f5f799fec9e992d557aa6d6b13b7b1510d` |
| `public/vendor/ocg/lib/_computeproof.mjs` | risc0 Groth16-BN254 seal verifier | byte-identical copy from the same bundle | MIT | `544e2f8910e1aaae3692c58758003b267998d9f2f1533267745b96a2291e393f` |
| `public/vendor/ocg/lib/_noble-bn254.bundle.mjs` | Vendored @noble BN254 curve bundle used by the seal verifier | byte-identical copy from the same bundle | MIT | `d389cfa8eb9081831b29c2c187ab4ebde9609be7afd8fd910359b65d13a65f8c` |

Pinned TSA roots live in `public/vendor/roots/` and are documented separately in [ROOTS.md](ROOTS.md).

Update procedure: bump the version in a branch, rebuild or refetch the file, update the hash here, and let the CI gates (including the TSA smoke harness, which exercises PKI.js end to end) prove the update before merge. The OCG verifier copies must stay byte-identical to the upstream bundle; never patch them locally.
