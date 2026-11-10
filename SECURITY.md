# Security Policy

## Supported versions

`opentdf-rs` is pre-1.0. Security fixes are released for the latest `0.x`
minor version only, as a new patch or minor release. Older minor versions do
not receive fixes; please upgrade to the latest release.

This covers every crate published from this repository (`opentdf`,
`opentdf-protocol`, `opentdf-crypto`, `opentdf-kas`, `opentdf-wasm`) and the
`@arkavo-org/opentdf-wasm` npm package.

## Reporting a vulnerability

Please do not open a public issue or pull request for a suspected
vulnerability.

Report it privately through GitHub private vulnerability reporting:
<https://github.com/arkavo-org/opentdf-rs/security/advisories/new>
(or the repository's **Security** tab, then **Report a vulnerability**).

Include what you can of:

- the affected crate, version and enabled features
- a description of the issue and its impact
- steps to reproduce or a proof of concept

## What to expect

- We aim to acknowledge a report within 5 business days.
- We will confirm whether we can reproduce the issue, and keep you informed
  while a fix is prepared.
- Fixes are published as a new release together with a GitHub security
  advisory. Reporters are credited unless they ask not to be.

## The pure-Rust RSA backend

[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (the
"Marvin attack", a timing side channel in the `rsa` crate before 0.10) affected
the opt-in pure-Rust RSA backend in releases up to 0.17:

- `opentdf`: features `kas-client-rustcrypto` and `rustcrypto-rsa`
- `opentdf-crypto`: features `rustcrypto-provider` and `rustcrypto-rsa`
- `opentdf-kas`: feature `rsa`

From 0.18.0 these features use `rsa` 0.10, the first release the advisory lists
as patched. None of them are enabled by default: default builds use `aws-lc-rs`
for RSA, which remains the recommended backend, and the browser WASM build uses
WebCrypto.
