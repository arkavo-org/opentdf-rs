# Changelog

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

### Deprecated

- `opentdf::kas_key::fetch_kas_public_key` — use `fetch_kas_public_key_connect`
- `opentdf::kas_key::fetch_kas_ec_public_key` — use `fetch_kas_ec_public_key_connect`

### Notes

- The `oauth_token` parameter of `KasClient::new` is an opaque passthrough. Pass a JWT or a base64url-encoded CWT; the server decides how to validate.
- Closes [#85](https://github.com/arkavo-org/opentdf-rs/issues/85).
