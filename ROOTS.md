# Pinned TSA trust roots

Fetched 2026-07-02 by `scripts/fetch-roots.mjs`. Committed under `public/vendor/roots/`. The verifier trusts ONLY these anchors; none of the Sigstore or GitHub roots are in OS trust stores, so pinning is mandatory, and pinning the classic CA roots keeps verification working offline and byte-reproducible.

Re-run `node scripts/fetch-roots.mjs` to refresh, then update this table. The CI pin-freshness gate warns when any pinned certificate is within 90 days of expiry.

| File | Authority | Source | SHA-256 (of committed file) | Root expires |
|---|---|---|---|---|
| `digicert-trusted-root-g4.pem` | DigiCert (anchors the Trusted G4 TimeStamping chain) | https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem | `ce7d6b44f5d510391be98c8d76b18709400a30cd87659bfebe1c6f97ff5181ee` | 2038-01-15 |
| `sectigo-time-stamping-root-r46.pem` | Sectigo Public Time Stamping Root R46 | http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.crt | `a5ad15883feead6740b67585c8e2e45011daed986bb43efe73e3fbc7f0ac1baa` | 2046-03-21 |
| `freetsa-cacert.pem` | FreeTSA root CA | https://freetsa.org/files/cacert.pem | `2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438` | 2041-03-07 |
| `sigstore-tsa-root.pem` | Sigstore TSA (self-signed root, tail of the chain) | https://timestamp.sigstore.dev/api/v1/timestamp/certchain | `bf6960b216d500905b7f71129be406a60a38a3dd34eea82fad5b36cc22dbb03f` | 2035-04-06 |
| `sigstore-tsa-certchain.pem` | Sigstore TSA (full chain, leaf to root) | https://timestamp.sigstore.dev/api/v1/timestamp/certchain | `16a57780dbc92f75ba62ff6cd740f7a6d11c458f985e75cf879d07681928d421` | leaf rotates |
| `github-tsa-root.pem` | GitHub TSA ("GitHub, Inc. Internal Services Root") | https://timestamp.githubapp.com/api/v1/timestamp/certchain | `6d6734c76d4280033315c30f63d20b7a8d5d4dd6d77c7446b08c93443beec26e` | 2033-08-04 |
| `github-tsa-certchain.pem` | GitHub TSA (full chain, leaf to root) | https://timestamp.githubapp.com/api/v1/timestamp/certchain | `7acc40bef5e7ca371780ceaedcd50d0675d15559649cbcc0fb5c91ae6bcf1244` | leaf rotates |

Notes:

- The Sectigo source is plain HTTP because `crt.sectigo.com` is an AIA distribution host, the same URL family embedded in the certificates themselves; its TLS endpoint rejects modern handshakes. Transport integrity does not matter here: the pinned file is content-addressed by the SHA-256 above, and the TSA smoke harness proves that live Sectigo timestamp tokens chain to exactly this root before any deploy.
- GitHub runs the Sigstore timestamp-authority server, so the same `certchain` endpoint shape applies. GitHub's TSA is undocumented for third-party use; the menu labels it accordingly.
- `roots.mjs` in the same directory is generated from these PEM files by `scripts/fetch-roots.mjs` and is what the pages and the smoke harness import. Do not hand-edit it.
