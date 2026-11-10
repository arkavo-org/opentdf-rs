# Changelog

## [Unreleased]

## [0.18.0] — 2026-11-10

A security release. The WASM decrypt function sent the caller's OAuth token to whatever KAS the TDF named, archive members were read with no size limit, and the optional RustCrypto RSA path was on a version with a timing side channel. All three are fixed; the first two change behaviour for existing callers.

### Security

- **WASM: `tdf_decrypt_with_kas` sent the caller's OAuth token to a KAS chosen by the TDF.** The KAS URL was read from the manifest of the TDF being decrypted and used without any check, so a crafted TDF could direct the bearer token to an attacker's host. The token is now sent only to a KAS whose origin the caller has allowlisted. The native client (`KasClient`) takes its KAS URL from caller configuration and was not affected.
  - The rewrap request refuses redirects, so a KAS response cannot forward the token-carrying request to another host.
  - A TDF with an empty `keyAccess` array is an error instead of an out-of-bounds panic.
- **Bounded reads of TDF archive members.** `TdfArchive` read the manifest and payload of an untrusted archive into memory with no size limit, and accepts deflated ZIP members, so a small crafted TDF (about 260 KB) could inflate to hundreds of megabytes or more. Every member is now read under a limit enforced on the bytes produced, whatever the member declares: 16 MiB for a manifest (`DEFAULT_MAX_MANIFEST_SIZE`) and 1 GiB for a payload (`DEFAULT_MAX_PAYLOAD_SIZE`). An oversized member fails with `TdfError::MemberTooLarge`.
  - `TdfMemberIndex::open` rejects a member whose central-directory size extends past the end of the archive, so a `TdfMemberLocation` can no longer make a caller allocate more than the archive holds.
  - `TdfEncryption::decrypt_with_segments` no longer panics on hostile segment sizes: its up-front reservation is capped at the payload length and its offset arithmetic is checked.
- **RUSTSEC-2023-0071 (the Marvin attack) in the optional RustCrypto RSA path.** `rsa` 0.9 leaks private-key information through timing. The path moves to `rsa` 0.10, the first release the advisory lists as patched. The default aws-lc-rs path was not affected and is unchanged.

### Changed

- **Breaking:** WASM `tdf_decrypt_with_kas(tdf_data, kas_token)` is now `tdf_decrypt_with_kas(tdf_data, kas_token, allowed_kas_urls)`. `allowed_kas_urls` is a required array of the KAS URLs you trust with the token. The TDF's KAS URL is accepted only if its parsed origin (scheme, host, port) equals that of an entry; an empty array rejects every TDF. The old two-argument call throws a `TypeError`.
  - The TDF's KAS URL must be `https`; `http` is accepted only for loopback hosts (`localhost`, `127.0.0.0/8`, `[::1]`), even if allowlisted.
  - A KAS URL containing userinfo, a query or a fragment is refused.
  - Decryption fails if the KAS answers the rewrap request with a redirect.
  - The WASM bundle grows from about 742 KB to 911 KB (314 KB to 387 KB gzipped) because the `url` crate is linked for allowlist matching.
- **Breaking:** reading a payload larger than 1 GiB through `TdfArchive::by_index`, `get_entry`, `validate`, `open_and_decrypt` or the `Tdf::decrypt*` builders fails with `TdfError::MemberTooLarge` unless the limit is raised. `open_and_decrypt` always uses the default; use `TdfArchive::open` with `with_max_payload_size` for a different one.
- **Breaking (opt-in features only):** `rsa` 0.9 → 0.10 in `opentdf-crypto` (`rustcrypto-provider`) and `opentdf-kas` (`rsa`). The re-exported `opentdf_crypto::rsa`, `opentdf_kas::rsa` and `opentdf::rsa` (`rustcrypto-rsa`), `KasRsaKeypair::private_key` and the key parameter of `rsa_unwrap` now carry the 0.10 types.
  - 0.10 renames `RsaPrivateKey` and `RsaPublicKey` to `PrivateKey` and `PublicKey`, keeping the old names as deprecated aliases, and replaces `BigUint` with `BoxedUint`.
  - 0.10 takes digest 0.11 hashes and rand_core 0.10 RNGs: use `rsa::sha2`, and `rand` 0.8's `OsRng` no longer works with it.
  - 0.10 rejects RSA keys under 1024 bits and accepts up to 8192 (0.9: up to 4096, no minimum), and rejects unbalanced or malformed prime factors.
  - Encodings are unchanged: RSA-OAEP with SHA-1 or SHA-256 wraps and unwraps against aws-lc-rs in both directions, with PKCS#8 and SPKI keys from either side.
  - The rsa paths use `sha1` 0.11 and, in `opentdf-kas`, `getrandom` 0.4 for key generation. The workspace `sha1`, `sha2`, `hmac`, `hkdf`, `aes-gcm` and `rand`, and the re-exported `opentdf_crypto::sha1` and `sha2`, are unchanged.
  - On `wasm32-unknown-unknown`, `rustcrypto-provider` needs getrandom 0.4's `wasm_js` backend, as the 0.14 curves do. `opentdf-wasm` does not use `rsa`.
- `TdfError`, `EncryptionError` and `IntegrityError` gained variants; exhaustive matches need a new arm. `IntegrityInformationExt` gained a required method.
- A manifest member that is not valid UTF-8 is reported as `TdfError::JsonError` instead of `TdfError::IoError`.

### Added

- `TdfArchive::with_max_payload_size` / `with_max_manifest_size` (and matching getters), plus `max_payload_size` on `TdfDecryptBuilder` and `TdfDecryptFileBuilder`, to raise or lower the read limits. `DEFAULT_MAX_MANIFEST_SIZE`, `DEFAULT_MAX_PAYLOAD_SIZE` and `TdfError::MemberTooLarge` (error code `OPENTDF_E_ARCHIVE_MEMBER_TOO_LARGE`).
- Verify-side APIs for the multi-entry (gguf-tdf) profile (#100):
  - `TdfEncryption::decrypt_segment_into_verified` decrypts a segment in place and compares its GCM tag with the manifest's segment hash in constant time, zeroizing the destination on failure. New `EncryptionError::SegmentHashMismatch`.
  - `IntegrityInformationExt::verify_root_signature_from_rows` verifies the root signature from the manifest's own segment rows, rejecting any row that is not a 16-byte tag. New `IntegrityError::SegmentHashLength`.
  - `TdfMemberIndex::read_member`, `read_into` and `read_manifest` read a member by name under a size limit (`with_max_member_size`, `with_max_manifest_size`); `read_manifest` looks for `manifest.json` and falls back to `0.manifest.json`.
- `PolicyBinding::validate()` and `PolicyBindingError`: structural validation of `keyAccess.policyBinding` without key material. Accepts `alg` `HS256` with a hash that is Base64 of a 32-byte HMAC-SHA256 (spec form) or of its 64-digit hex encoding (legacy Go SDK form). Opt-in; parsing a manifest does not run it. (#76)
- `Policy::has_attribute()` and `Policy::find_attribute()`: look up an `AttributeFqn` in a policy's attribute tree, including conditions nested in `AND`/`OR`/`NOT`. A value FQN matches an `Equals` condition with that string value; a namespace-only FQN matches any attribute in the namespace. (#77)
- Cross-backend RSA-OAEP tests between the `rsa` path and aws-lc-rs in `opentdf-crypto` and `opentdf-kas`. `aws-lc-rs` is a dev-dependency of both for this.

### Documentation

- The `KasClient` EC rewrap HKDF salt, `SHA256("TDF")`, is documented against the `opentdf/platform` KAS and Go SDK source; the path was mislabelled as NanoTDF. (#69)

## [0.17.0] — 2026-10-30

Moves the elliptic-curve crates to the RustCrypto 0.14 generation for RUSTSEC-2026-0387: crypto-bigint 0.5, which the 0.13 curves use for scalar arithmetic, has operations meant to be constant-time that can branch on secret values. The fix is only in crypto-bigint 0.7.6 and later, which only the 0.14 curves use. Encodings are unchanged: SEC1 points, PKCS#8 and SPKI documents, ECDH outputs and ES256 signatures are byte-for-byte the same for the same keys.

### Changed

- **Breaking:** `p256`, `p384`, `p521` and `k256` 0.13 → 0.14, and `pkcs8` 0.10 → 0.11. The re-exported `opentdf::p256` and `opentdf::pkcs8` (and the same names in `opentdf-crypto`), `CallerKey::P256` and `KasEcKeypair` now carry the 0.14 types.
  - 0.14 renames `EncodedPoint`, `ToEncodedPoint` and `FromEncodedPoint` to `Sec1Point`, `ToSec1Point` and `FromSec1Point`.
  - Keys are generated with the `Generate` trait (`SecretKey::generate()`), which draws from the operating system through getrandom 0.4, in place of `random(&mut OsRng)`.
- The RustCrypto RSA path (`rustcrypto-provider`, `opentdf-kas` `rsa`) keeps `rsa` 0.9 and uses its own `rsa::pkcs8` re-export. `opentdf-kas` no longer depends on `pkcs8` directly, and `opentdf-crypto` no longer depends on `spki`.
- `opentdf-wasm` enables getrandom 0.4's `wasm_js` backend, which the 0.14 curves need on `wasm32-unknown-unknown`.

## [0.16.1] — 2026-10-17

Moves to zip 9 for RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369, which zip 2.x has and zip 9.0 fixes: extraction kept SUID and SGID bits, created symlinks pointing outside the destination, and applied permissions through symlinks. opentdf never calls the affected `extract` functions, but every crate that depends on it inherits the vulnerable zip and fails `cargo audit` until it moves.

### Changed

- `zip` 2.2 → 9.0.4. zip 9 reports a member name that is not UTF-8 as an error rather than a lossy string:
  - `TdfMemberIndex::open` fails on such a name.
  - `TdfArchive::len` skips it, since it cannot be a manifest entry.

## [0.16.0] — 2026-09-27

Adds a caller-key mode to `KasClient`, so an agent whose access token is bound to its own key (`cnf`) can rewrap from the Arkavo platform KAS with proof of possession. It also releases four changes already on main since 0.15.0: the spec-compliant manifest entry name, per-segment integrity verification on decrypt, round-tripping of `keyAccess.sid` / manifest assertions, and the spec policy binding OpenTDFKit 5.0.0 writes.

### Added

- `kas::CallerKey` (`Ed25519(ed25519_dalek::SigningKey)` or `P256(p256::ecdsa::SigningKey)`) and `KasClient::with_caller_key`.
  - Each rewrap sends `Authorization: DPoP <token>` and an RFC 9449 proof: `typ` `dpop+jwt`, `alg` `EdDSA`/`ES256`, and the public `jwk`, with claims `htm`, `htu`, `iat`, `jti` (128-bit random) and `ath`.
  - It signs the signed request token with the same key and sends `Connect-Protocol-Version: 1`.
  - `htu` is the Connect procedure `/kas.AccessService/Rewrap`.
  - A configuration that resolved only to the legacy REST rewrap fails with `KasError::ConfigError` before anything is sent.
  - Without a caller key, requests are unchanged.
- `KasClient::set_access_token`: replaces the access token between requests. `ath` is computed at send time.
- `CallerKey::dpop_proof`: a proof for another Connect procedure of the same platform.
- `opentdf::ed25519_dalek`: re-exported under `kas-client`, matching `CallerKey::Ed25519`.
- `tests/data/dpop_interop_vectors.json`: recorded Ed25519 and P-256 vectors, verified by the opentdf-platform fork's `validateDPoP` through `tests/interop/opentdf_platform_dpop_vectors_test.go`.
- `KeyAccess.sid: Option<String>` and `TdfManifest.assertions: Vec<Assertion>`, so split ids and assertions survive a read/re-serialize round trip instead of being silently dropped; `statement.value` is now a JSON `Value` rather than a `String`, so a structured statement round-trips byte-for-byte and keeps its canonicalization hash stable across SDKs ([#107](https://github.com/arkavo-org/opentdf-rs/pull/107)). **Breaking:** code that builds `KeyAccess` or `TdfManifest` with a struct literal (rather than `..Default::default()` / a builder) needs updating for the new fields.
- `EncryptionError::InvalidIvLength(usize)`, returned by the TDF-JSON, JSON-RPC and TDF-CBOR decrypt paths when a legacy `method.iv` decodes to fewer than 12 bytes ([#107](https://github.com/arkavo-org/opentdf-rs/pull/107)). **Breaking:** an exhaustive `match` over `EncryptionError` needs a new arm.

### Changed

- TDF archives now write the manifest zip entry as `manifest.json` (spec-compliant) instead of `0.manifest.json`. Readers accept both names, and the payload entry is resolved from `manifest.payload.url` rather than assumed. `schemaVersion` is unchanged (still `4.3.0`); `tdf_spec_version` is now read at either its legacy or spec-conformant placement but never written. **Interop impact:** archives written by this version cannot be opened by released otdfctl, or the upstream opentdf/platform Go, Java, or JS SDKs until they add a `manifest.json` read fallback (an upstream reader-fallback PR is planned). Files written by older versions of this crate remain readable.
- `method.iv` and `method.isStreamable` now default when absent on read, which every Java-written TDF requires; the TDF-JSON path takes its schema version from the crate constant instead of a hardcoded `"1.0.0"` ([#107](https://github.com/arkavo-org/opentdf-rs/pull/107)).
- **Breaking (wire): spec policy binding.** `keyAccess.policyBinding.hash` is now `Base64(HMAC-SHA256(DEK, Base64(policy)))`, 44 characters, replacing the Go SDK's legacy `Base64(hex(HMAC))` (88 characters). This matches OpenTDFKit 5.0.0. **Interop impact:** rewrap needs a KAS with opentdf/platform#4081; platform.arkavo.net has it through arkavo-org/opentdf-platform#54, and no released upstream KAS accepts this form yet. TDFs written by older versions still rewrap, since a patched KAS accepts both forms. The `hex` dependency is dropped from `opentdf-crypto` ([#110](https://github.com/arkavo-org/opentdf-rs/pull/110)).

### Fixed

- Decrypt now compares every `integrityInformation.segments[i].hash` against the GMAC tag of that segment's ciphertext; previously only the root signature was checked, so a TDF with a tampered segment hash still decrypted successfully because the root signature is derived from the real ciphertext tags, not from the manifest hashes. A mismatch is now rejected ([#106](https://github.com/arkavo-org/opentdf-rs/pull/106)).
- The legacy single-block decrypt branch returns an error for a wrong-length `method.iv` instead of panicking inside `Nonce::from_slice` (which previously aborted the process, including on wasm) ([#106](https://github.com/arkavo-org/opentdf-rs/pull/106)).
- Omitted per-segment sizes (`segmentSize` / `encryptedSegmentSize`) now fall back to the manifest's `integrityInformation` defaults instead of `0` ([#106](https://github.com/arkavo-org/opentdf-rs/pull/106)).
- The WebAssembly decrypt path now runs the same segment-hash and root-signature verification as the library path; previously it verified nothing ([#106](https://github.com/arkavo-org/opentdf-rs/pull/106)).
- TDF-JSON (`TdfJson`, `TdfJsonRpc`) and TDF-CBOR (`TdfCbor`) builders, and the `xtest_cli` JSON/CBOR paths, computed the policy binding over the policy base64-encoded twice. A KAS that verifies the binding (`HMAC(DEK, manifest policy)`) refused to rewrap them. They now bind over the manifest's `policy` string, as ZIP TDFs already did ([#110](https://github.com/arkavo-org/opentdf-rs/pull/110)).

### CI

- X-Test pins the KAS to opentdf/platform#4081 (`ca178b05`) and the upstream Go peer to opentdf/platform#4063 (`29498d20`), as OpenTDFKit does, until upstream releases include both. The previous floating pins rejected the spec binding and could not read `manifest.json` ([#110](https://github.com/arkavo-org/opentdf-rs/pull/110)).

## [0.15.0] — 2026-08-30

Additive API for the `gguf-tdf/1` profile (multi-member archives with one OpenTDF segment per zip member) plus a bounded-plaintext fix in segment decryption. No wire-format change; existing archives read and write as before.

### Added

- `TdfMultiEntryBuilder` and `TdfMemberIndex`: build a TDF archive with one encrypted member per segment and locate members through the central directory (ZIP64-aware) without reading the whole file.
- `TdfEncryption::encrypt_segment` / `decrypt_segment_into`: single-segment encrypt and decrypt into a caller-owned buffer, returning the GMAC tag so it can be checked against the manifest row.
- `TdfManifest`: optional `tdf_spec_version` and a `gguf` index object; `GgufIndex`, `GgufSegment`, `GgufSegmentKind` re-exported from the root crate.
- crates.io Trusted Publishing from `arkavo-org/opentdf-rs` GitHub Actions (`.github/workflows/crates-io.yml`, environment `crates-io`), invoked after a new version tag in Release.

### Changed

- README install snippets and badges now point at crates.io `opentdf` 0.14.

### Fixed

- `decrypt_segment_into` decrypted into a second heap-allocated plaintext, copied it into `dest`, and dropped it unzeroized — one unwiped full-segment plaintext per segment plus an extra alloc and memcpy on the load hot path. It now decrypts in place into `dest` and zeroizes `dest` on tag failure; a counting-allocator test proves zero heap allocations per segment ([#99](https://github.com/arkavo-org/opentdf-rs/issues/99), [#101](https://github.com/arkavo-org/opentdf-rs/pull/101)).

## [0.14.2] — 2026-08-26

### Security

- Raise the `aws-lc-rs` requirement from 1.15 to 1.18 (`aws-lc-sys` 0.37 → 0.44) so AWS-LC AES-CCM, X.509, CRL, and PKCS7 advisory fixes are required. `Cargo.lock` is not committed; current crates.io resolution also picks up patched `rustls-webpki` 0.103.15, `h2` 0.4.19, `quinn-proto` 0.11.17, `jsonwebtoken` 10.4.0, and `crossbeam-epoch` 0.9.20 ([#94](https://github.com/arkavo-org/opentdf-rs/pull/94)).

### Fixed

- X-Test: build the go peer from source when tagged `otdfctl` setup leaves `sdk/go/dist` empty, and fail clearly instead of `find: sdk/go/dist: No such file or directory` ([#94](https://github.com/arkavo-org/opentdf-rs/pull/94)).

## [0.14.1] — 2026-07-13

### Fixed

- Stop emitting `payload.tdf_spec_version` on encrypt (default + `xtest_cli`). Go and Swift only set root `schemaVersion`; otdf-python’s strict `ManifestPayload` rejects the unknown field and broke rust→python Stage-2 ([#89](https://github.com/arkavo-org/opentdf-rs/pull/89)). Field is still accepted on read.

### Added

- **X-Test** GitHub Actions workflow (`.github/workflows/xtest.yml`): rust ↔ go Stage-1 via `arkavo-org/opentdf-tests`, wiring the PR checkout into `xtest/sdk/rust` (same pattern as OpenTDFKit) ([#89](https://github.com/arkavo-org/opentdf-rs/pull/89)).

## [0.14.0] — 2026-07-12

### Added

- **Stage-1 community xtest KAS path** for `examples/xtest_cli` ([#87](https://github.com/arkavo-org/opentdf-rs/pull/87)):
  - Encrypt ZIP/Base TDF via Connect PublicKey + RSA-OAEP wrap (`kid`)
  - Decrypt via client-credentials OAuth + `KasClient::rewrap_standard_tdf`
  - Env contract: `CLIENTID` / `CLIENTSECRET` / `PLATFORMURL` / `KASURL` / `TOKENENDPOINT`
  - Honest `supports` map: `hexless`, `connectrpc`, `kas-rewrap`; exit `2` for unknown features
  - Manifest `schemaVersion` / `tdf_spec_version` **4.3.0** (go@latest hexless Stage-1)

### Fixed

- Standard TDF **RSA rewrap** no longer requires `sessionPublicKey` (EC-only field); RSA path returns the DEK encrypted to the client RSA key ([#87](https://github.com/arkavo-org/opentdf-rs/pull/87))

### Notes

- This is the first release that passes community Stage-1 (`rust` ↔ `go@latest`, Base TDF) in [arkavo-org/opentdf-tests](https://github.com/arkavo-org/opentdf-tests).
- GitHub “latest” before this release was **0.13.0**, which lacked Stage-1 `supports hexless` / KAS CLI wiring.

## [0.13.0] — 2026-05-28

### Breaking changes

- `KasClient::new` now takes `&OpentdfConfiguration` instead of a base URL string. Migrate via:
  ```rust
  // before
  let client = KasClient::new("https://kas.example.com", token)?;

  // after
  let cfg = opentdf::kas_discovery::OpentdfConfiguration::for_kas_connect(
      "https://kas.example.com",
  );
  let client = KasClient::new(&cfg, token)?;
  ```
  For discovery-driven setups, use `fetch_well_known(platform_url, &http).await?` to obtain the config.

### Added

- `opentdf::kas_discovery` module:
  - `OpentdfConfiguration` deserialization of `/.well-known/opentdf-configuration`
  - `KasEndpoints::from_config` with Connect-preferred / REST-fallback URL resolution
  - `OpentdfConfiguration::for_kas_connect` / `for_kas_legacy_rest` direct builders
  - `fetch_well_known` async discovery
  - `parse_connect_error` Connect error envelope parser
- `opentdf::kas_key::fetch_kas_public_key_connect` and `fetch_kas_ec_public_key_connect` for ConnectRPC public-key retrieval
- Live ConnectRPC integration tests against `platform.arkavo.net` in `tests/platform_integration.rs` (`#[ignore]`d by default)
- ConnectRPC route handlers in `examples/mock_kas_server.rs`

### Changed

- KAS rewrap now POSTs to `/kas.AccessService/Rewrap` (ConnectRPC) instead of `/kas/v2/rewrap` (legacy REST)
- Connect error envelope (`{code, message}`) parsed into `KasError` reason strings
- KAS URL validation moved into `KasEndpoints::from_config`, which now validates **both** the resolved rewrap and public-key URLs (exposed as `kas_discovery::validate_kas_url`). This closes an SSRF gap where a remotely-fetched well-known document could otherwise redirect the bearer-carrying rewrap request at an internal target.

### Security

- SSRF URL validation now rejects IPv6 unique-local (`fc00::/7`) and link-local (`fe80::/10`) addresses, unspecified addresses (`0.0.0.0`, `::`), and folds IPv4-mapped IPv6 literals (e.g. `::ffff:169.254.169.254`) back to IPv4 so they can't bypass the metadata/private-range checks.
- The KAS rewrap HTTP client now follows no redirects (`redirect::Policy::none()`), so a 3xx from a validated host cannot re-issue the bearer-carrying rewrap request to an unvalidated target (URL validation only runs on the initial URL, not per redirect hop).

### Deprecated

- `opentdf::kas_key::fetch_kas_public_key` — use `fetch_kas_public_key_connect`
- `opentdf::kas_key::fetch_kas_ec_public_key` — use `fetch_kas_ec_public_key_connect`

### Notes

- The `oauth_token` parameter of `KasClient::new` is an opaque passthrough. Pass a JWT or a base64url-encoded CWT; the server decides how to validate.
- Closes [#85](https://github.com/arkavo-org/opentdf-rs/issues/85).
