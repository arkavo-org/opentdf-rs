# OpenTDF-RS Guidelines

## Important Project Files
When starting a new conversation or initializing, please read these files:
- `README.md` - Project overview and basic usage
- `CLAUDE.md` - Coding guidelines (this file)
- `REQUIREMENTS.md` - Technical and functional requirements

## Build/Test Commands

- Build: `cargo build`
- Format code: `cargo fmt`
- Run all tests: `cargo test`
- Run a single test: `cargo test test_name`
- Run tests with output: `cargo test -- --nocapture`
- Run clippy lints: `cargo clippy`

## Code Style Guidelines

- **Formatting**: Use `rustfmt` defaults (enforced via `cargo fmt`)
- **Error Handling**: Use `thiserror` for custom error types
- **Naming**: Follow Rust conventions - snake_case for variables/functions, CamelCase for types
- **Imports**: Group std imports first, then external crates, then local modules
- **Types**: Use strong typing and prefer specific error types over `Box<dyn Error>`
- **Documentation**: Document public API with doc comments
- **Testing**: Write unit tests for each module, integration tests for API
- **Error Types**: Create enum-based error types that implement `std::error::Error`
- **Serialization**: Use `serde` attributes consistently for JSON serialization
- **Security**: Never commit secrets, validate cryptographic operations
- **Commit Preparation**: Always run `cargo build`, `cargo clippy`, and `cargo fmt` before committing

## Workflow Guidelines

- Always run the full test suite before submitting PRs: `cargo test`
- Address all clippy warnings before submitting code: `cargo clippy`
- Format code before committing: `cargo fmt`
- When adding new dependencies, document their purpose in comments
- For MCP server development, manually test endpoints with HTTP client tools
- Verify backwards compatibility when modifying public APIs

PRs should include tests and documentation for new features.