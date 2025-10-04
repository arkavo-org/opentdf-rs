# OpenTDF Interoperability Testing Summary

## Test Environment
- **Platform**: OpenTDF Platform running on `localhost:8080`
- **Keycloak**: Running on `localhost:8888`
- **Rust Implementation**: opentdf-rs (current branch: `feature/kas-rewrap-protocol`)
- **Go Implementation**: otdfctl at `/Users/paul/Projects/opentdf/otdfctl`
- **Swift Implementation**: OpenTDFKit at `/Users/paul/Projects/arkavo/OpenTDFKit`

## Test Results

### ✓ KAS Client Infrastructure
- **Status**: PASSED
- **Test**: `cargo test --features kas test_kas_rewrap_with_real_server -- --ignored`
- **Result**: KAS client successfully connects to local platform
- **Details**:
  - KAS endpoint: `http://localhost:8080/kas`
  - Authentication: OAuth2 client credentials flow
  - Protocol: KAS v2 rewrap (Connect RPC compatible)

### ✓ KAS Public Key Retrieval
- **Status**: PASSED
- **Endpoint**: `http://localhost:8080/kas/v2/kas_public_key`
- **Result**:
  ```json
  {
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
    "kid": "r1"
  }
  ```
- **Key Type**: RSA 2048-bit

### ✓ RSA Key Wrapping
- **Status**: IMPLEMENTED
- **Implementation**: RSA-OAEP with SHA1 hash (matching OpenTDF specification)
- **Location**: `src/crypto.rs::wrap_key_with_rsa_oaep()`
- **Example**: `examples/create_tdf_with_kas.rs` demonstrates usage

### ⚠ Cross-Platform TDF Creation/Decryption
- **Status**: PARTIAL - Format incompatibilities discovered
- **Scenarios tested**:
  1. Create TDF with Rust → Decrypt with otdfctl: ❌ (KAS request format issues)
  2. Create TDF with otdfctl → Decrypt with Rust: ❌ (KAS request format issues)
  3. Create TDF with OpenTDFKit → Decrypt with Rust: ⏸ (Not yet tested)
  4. Create TDF with Rust → Decrypt with OpenTDFKit: ⏸ (Not yet tested)

**Issues Discovered:**
- TDF format differences between Rust and Go implementations
  - Go uses segment-based encryption with empty method.iv
  - Rust uses single-payload encryption with IV in method.iv
  - Policy binding hash encoding may differ (hex vs base64)
  - Integrity information structure varies (segments vs single payload)
- KAS rewrap requests from both implementations fail with "invalid request"
- Root cause requires deeper investigation of protocol expectations

## Components Verified

### KAS Rewrap Request Format ✓
```rust
UnsignedRewrapRequest {
    client_public_key: String,  // PEM format
    requests: Vec<PolicyRequest>
}
```

### KAS Rewrap Response Format ✓
```rust
RewrapResponse {
    responses: Vec<PolicyRewrapResult>,
    session_public_key: Option<String>
}
```

### ECDH Key Unwrapping ✓
- Protocol: ECDH → HKDF(salt=SHA256("TDF")) → AES-256-GCM
- Implementation: Verified in `src/kas.rs:456`

## Implementation Progress

### ✅ Phase 1: RSA Key Wrapping (COMPLETED)
- [x] Add `rsa` crate dependency (Cargo.toml)
- [x] Add `sha1` crate for OAEP padding
- [x] Create `src/kas_key.rs` module for KAS public key fetching
- [x] Implement `wrap_key_with_rsa_oaep()` function in `src/crypto.rs`
- [x] Create example `examples/create_tdf_with_kas.rs`
- [x] Successfully fetch KAS public key from platform
- [x] Successfully wrap payload key with RSA-OAEP-SHA1

## Next Steps for Full Interoperability

### 1. Investigate Protocol Compatibility Issues
- [ ] Debug KAS rewrap request/response format
- [ ] Compare actual HTTP requests between Go SDK and Rust implementations
- [ ] Identify specific field mismatches causing "invalid request" errors
- [ ] Review OpenTDF protocol specification for Standard TDF format

### 2. Create Cross-Platform Test Suite
Once RSA wrapping is implemented:
- [ ] Create test TDF with Rust, decrypt with otdfctl
- [ ] Create test TDF with otdfctl, decrypt with Rust
- [ ] Create test TDF with OpenTDFKit, decrypt with Rust
- [ ] Verify policy binding across implementations
- [ ] Test attribute-based access control interoperability

### 3. Protocol Validation
- [ ] Verify manifest format compatibility
- [ ] Test policy serialization/deserialization
- [ ] Validate encryption metadata
- [ ] Check KAS URL format handling

## Code References
- KAS client implementation: `src/kas.rs`
- KAS integration tests: `tests/kas_integration.rs`
- Example usage: `examples/kas_decrypt.rs`
- Recent commit: `a2af789` - Fix KAS rewrap request format for Connect RPC compatibility

## OAuth Token Generation
```bash
curl -s http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=opentdf&client_secret=secret" \
  | jq -r '.access_token'
```

## Platform Configuration
```bash
curl -s http://localhost:8080/.well-known/opentdf-configuration | jq
```
