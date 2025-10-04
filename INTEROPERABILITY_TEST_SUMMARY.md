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
- **Status**: IN PROGRESS - Policy binding encoding fixed, remaining issues under investigation
- **Scenarios tested**:
  1. Create TDF with Rust → Decrypt with otdfctl: ⚠ (tamper detected - under investigation)
  2. Create TDF with otdfctl → Decrypt with Rust: ⚠ (authentication issues - under investigation)
  3. Create TDF with OpenTDFKit → Decrypt with Rust: ⏸ (Not yet tested)
  4. Create TDF with Rust → Decrypt with OpenTDFKit: ⏸ (Not yet tested)

**Issues Discovered and Fixed:**
- ✅ **Policy Binding Encoding** (FIXED in this session):
  - **Root Cause**: Go SDK uses `base64(hex(hmac))` but Rust was using `base64(hmac)`
  - **Go SDK** (`/platform/sdk/tdf.go:537-538`): Hex encodes HMAC before base64
  - **Rust** (was): Directly base64 encoded the 32-byte HMAC
  - **Fix**: Updated `src/manifest.rs:generate_policy_binding_raw()` to match Go format
  - **Result**: Policy bindings now use same encoding (64 hex chars → base64)

**Remaining Issues:**
- TDF format differences between Rust and Go implementations:
  - **Encryption approach**:
    - Go: Segment-based encryption with empty `method.iv`, IV stored in segments
    - Rust: Single-payload encryption with IV in `method.iv`
  - **Integrity information**:
    - Go: Populated `segments` array with hashes and signatures
    - Rust: Empty `segments` array, empty `rootSignature.sig`
- otdfctl decrypt still reports "tamper detected" despite policy binding fix
- Rust KAS client authentication issues (may be OAuth token related)

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

### ✅ Phase 2: Policy Binding Compatibility (COMPLETED)
- [x] Add `hex` crate dependency (Cargo.toml)
- [x] Investigate Go SDK policy binding generation
- [x] Update `generate_policy_binding_raw()` to use hex encoding
- [x] Verified new format: base64(hex(hmac)) - 64 hex chars after b64 decode
- [x] Confirmed compatibility with Go SDK format

## Next Steps for Full Interoperability

### 1. Investigate Remaining Compatibility Issues
- [ ] **TDF Format Alignment**: Decide whether to adopt segment-based encryption
  - Review OpenTDF Standard TDF specification for required format
  - Determine if single-payload encryption is acceptable or if segments are required
  - If segments required, implement segment-based encryption matching Go SDK
- [ ] **Integrity Information**: Implement root signature and segment hashes
  - Understand GMAC segment hash algorithm
  - Implement HS256 root signature generation
- [ ] **Authentication Issues**: Debug KAS client OAuth token handling
  - Verify token is properly included in rewrap requests
  - Check Authorization header format
  - Test with fresh tokens
- [ ] **otdfctl "tamper detected"**: Debug why decryption still fails
  - Capture actual KAS rewrap HTTP requests (both Go and Rust)
  - Compare JSON structures byte-by-byte
  - Verify policy binding calculation with same test data

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
