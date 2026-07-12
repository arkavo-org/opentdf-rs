# Changelog

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
