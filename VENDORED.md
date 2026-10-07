# Vendored libraries

Everything the pages load is committed in this repo. No CDNs, no runtime npm. Hashes are SHA-256 of the committed files (recorded 2026-07-02; OCG verifier rows re-stamped 2026-07-09 to the deployed bytes and now gated by `scripts/check-vendor-freshness.mjs`; `_proof.mjs` re-vendored 2026-07-09 from the current `origin/master` embed bundle to pick up §16.5 proof sets; `_hash.mjs`, `_proof.mjs` and `_computeproof.mjs` re-vendored 2026-10-07 from `origin/master` `053bb99b7fa8d1517b6d43e681a64ad7fb701a3f` of PostOakLabs/ainumbers-mcp-apps to move verify paths onto the RFC 8785 serializer, `verify.mjs` already byte-identical at that SHA and not re-copied).

| File | What | Version / pin | License | SHA-256 |
|---|---|---|---|---|
| `public/vendor/pkijs.bundle.mjs` | PKI.js + asn1js, bundled once with esbuild 0.28.1 into a single ES module (`export * as pkijs`, `export * as asn1js`) | pkijs 3.4.0, asn1js 3.0.10 (npm) | BSD-3-Clause | `f1c2f9e8991bb28c76812ae5eda25b0693373609ef21748e4775bf902e0f1e40` |
| `public/vendor/opentimestamps.min.js` | javascript-opentimestamps official browser bundle, the exact file the opentimestamps.org web stamper serves (UMD, exposes `window.OpenTimestamps`) | opentimestamps/opentimestamps.org commit `6c0ca1ac6191605dee15475f33de9ff1b226a301` (byte-identical to the live site copy at vendor time) | LGPL-3.0 | `f6181ae00cce58773f8710894c99d0656058f6a1e08c57360b263cd46c54fbf2` |
| `public/vendor/ocg/verify.mjs` | OpenChainGraph offline verifier entry points (section 4 execution hash, section 16 signature, section 18 compute proof) | byte-identical copy of `embed/verify.mjs` from PostOakLabs/ainumbers-mcp-apps (OCGR Phase D bundle) | MIT | `b6c387e301cd07e7db09146fa00b373e52514e4c4e2768675707efe3d9cc25b1` |
| `public/vendor/ocg/lib/_hash.mjs` | Canonical OCG hashing primitives (RFC 8785 `jcsStringify` + legacy `cgCanon`) | byte-identical copy from `embed/lib/_hash.mjs` at `origin/master` `053bb99b` | MIT | `131f400870cd5c9a27b342c90ef1dc1cc8d0432745f4215ae13899ebe2edd4ae` |
| `public/vendor/ocg/lib/_proof.mjs` | eddsa-jcs-2022 Data Integrity sign/verify, plus §16.5 proof sets / endorsement chains (`verifyProofs`, `addProof`) | byte-identical copy from `embed/lib/_proof.mjs` at `origin/master` `053bb99b` | MIT | `b43facc8377960a65b3fc211571d641d53e715737c03052986a7350acd716d8b` |
| `public/vendor/ocg/lib/_computeproof.mjs` | risc0 Groth16-BN254 seal verifier | byte-identical copy from `embed/lib/_computeproof.mjs` at `origin/master` `053bb99b` | MIT | `c4e8401878fc469e558a918bcca4be6734c57a8d39441ac595837c9bcafb4e91` |
| `public/vendor/ocg/lib/_noble-bn254.bundle.mjs` | Vendored @noble BN254 curve bundle used by the seal verifier | byte-identical copy from the same bundle | MIT | `d389cfa8eb9081831b29c2c187ab4ebde9609be7afd8fd910359b65d13a65f8c` |

Pinned TSA roots live in `public/vendor/roots/` and are documented separately in [ROOTS.md](ROOTS.md).

Update procedure: bump the version in a branch, rebuild or refetch the file, update the hash here, and let the CI gates (including the TSA smoke harness, which exercises PKI.js end to end) prove the update before merge. The OCG verifier copies must stay byte-identical to the upstream bundle; never patch them locally.
