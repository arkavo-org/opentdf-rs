# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Important Project Files
When starting a new conversation or initializing, please read these files:
- `README.md` - Project overview and basic usage
- `CLAUDE.md` - Coding guidelines (this file)
- `REQUIREMENTS.md` - Technical and functional requirements

## Build/Test Commands

### Core Library
- Build: `cargo build`
- Format code: `cargo fmt`
- Run all tests: `cargo test`
- Run a single test: `cargo test test_name`
- Run tests with output: `cargo test -- --nocapture`
- Run clippy lints: `cargo clippy`
- Fix all clippy warnings: `cargo clippy --fix`
- Build with warnings as errors: `RUSTFLAGS="-D warnings" cargo build`

### MCP Server
- Run MCP server: `cargo run -p opentdf-mcp-server`
- Test MCP server: `node tools/test-mcp.js`
- Test ABAC functionality: `node tools/test-abac-access.js`
- Audit logging test: `node tools/audit-logging-test.js`

## Architecture Overview

### Core Modules
- **`src/lib.rs`**: Main library entry point, exports public API
- **`src/archive.rs`**: TDF archive creation and reading using ZIP format
  - `TdfArchive`: Read TDF archives from files or streams
  - `TdfArchiveBuilder`: Create new TDF archives with manifest and payload
- **`src/crypto.rs`**: Cryptographic operations for TDF
  - `TdfEncryption`: AES-256-GCM encryption/decryption with key management
  - `EncryptedPayload`: Encrypted data structure with IV and wrapped keys
- **`src/manifest.rs`**: TDF manifest structure and serialization
  - `TdfManifest`: JSON manifest containing encryption metadata and policy
- **`src/policy.rs`**: Attribute-Based Access Control (ABAC) policy system
  - `AttributeIdentifier`: Namespace-qualified attribute names
  - `AttributeValue`: Type-safe attribute values (string, number, boolean, datetime, arrays)
  - `Operator`: Rich comparison operators (equals, contains, in, minimumOf, etc.)
  - `AttributePolicy`: Logical policy expressions with AND/OR/NOT
  - `Policy`: Complete policy with time constraints and dissemination

### MCP Server (`crates/mcp-server`)
- JSON-RPC 2.0 server over stdio implementing Model Context Protocol
- Exposes TDF operations as tools for AI agents (Claude, etc.)
- Tools include: `tdf_create`, `tdf_read`, `policy_create`, `policy_validate`, `attribute_define`, `access_evaluate`, `policy_binding_verify`
- Includes comprehensive audit logging for compliance

### Key Design Patterns
- **Encryption Flow**: Data → AES-256-GCM encryption → Policy binding via HMAC-SHA256 → ZIP archive
- **Policy Evaluation**: User attributes → Policy tree evaluation → Access decision with audit trail
- **Type Safety**: Strong typing with `thiserror` for error handling, `serde` for serialization

## Code Style Guidelines

- **Formatting**: Use `rustfmt` defaults (enforced via `cargo fmt`)
- **Error Handling**: Use `thiserror` for custom error types (see `PolicyError`, `EncryptionError`, `TdfError`)
- **Naming**: Follow Rust conventions - snake_case for variables/functions, CamelCase for types
- **Imports**: Group std imports first, then external crates, then local modules
- **Types**: Use strong typing and prefer specific error types over `Box<dyn Error>`
- **Documentation**: Document public API with doc comments
- **Testing**: Write unit tests for each module, integration tests for API
- **Error Types**: Create enum-based error types that implement `std::error::Error`
- **Serialization**: Use `serde` attributes consistently for JSON serialization
- **Security**: Never commit secrets, validate cryptographic operations
- **Commit Preparation**: Always run `cargo build`, `cargo clippy`, and `cargo fmt` before committing
- **Dead Code**: Remove unused code rather than using `#[allow(dead_code)]` attributes
- **Warnings**: Eliminate all compiler warnings before committing code

## Workflow Guidelines

- Always run the full test suite before submitting PRs: `cargo test`
- Address all clippy warnings before submitting code: `cargo clippy`
- Format code before committing: `cargo fmt`
- When adding new dependencies, document their purpose in comments
- For MCP server development, test with Node.js tools in `tools/` directory
- Verify backwards compatibility when modifying public APIs
- Fix all compiler warnings before committing

### MCP Server Development Notes
- The MCP server uses JSON-RPC 2.0 over stdio (not HTTP)
- Tool definitions require both `schema` and `inputSchema` fields for compatibility
- Protocol version is "2024-11-05"
- All responses must follow JSON-RPC 2.0 format with `jsonrpc`, `id`, `result`/`error` fields
- When adding new tools, update both `initialize` and `listTools` responses
- Test with `tools/test-mcp.js` to verify tool registration and execution

## PR Review Process

- Use GitHub CLI (`gh`) for PR reviews: `gh pr review [PR-NUMBER]`
- PRs should be reviewed across multiple perspectives:
  - **Product**: Business value, user experience, and strategic alignment
  - **Development**: Code quality, performance, and adherence to standards
  - **Quality**: Test coverage, edge cases, and regression risks
  - **Security**: Vulnerabilities, data handling, and compliance
  - **DevOps**: CI/CD integration, configuration, and monitoring
  - **Usability**: API design and interaction patterns
- All PR reviews should identify specific issues that need to be fixed before merging
- PRs should include tests and documentation for new features
- No PR should be merged with pending warnings or clippy issues

## Pre-Commit Checklist

1. Run `cargo fmt` to ensure consistent formatting
2. Run `cargo clippy` and fix all warnings
3. Run `cargo test` to verify all tests pass
4. Run `cargo build` with warnings treated as errors: `RUSTFLAGS="-D warnings" cargo build`
5. Ensure all new features are documented
6. Verify that security-sensitive code has been properly reviewed