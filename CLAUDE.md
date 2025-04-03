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
- Fix all clippy warnings: `cargo clippy --fix`

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
- **Dead Code**: Remove unused code rather than using `#[allow(dead_code)]` attributes
- **Warnings**: Eliminate all compiler warnings before committing code

## Workflow Guidelines

- Always run the full test suite before submitting PRs: `cargo test`
- Address all clippy warnings before submitting code: `cargo clippy`
- Format code before committing: `cargo fmt`
- When adding new dependencies, document their purpose in comments
- For MCP server development, manually test endpoints with HTTP client tools
- Verify backwards compatibility when modifying public APIs
- Fix all compiler warnings before committing

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