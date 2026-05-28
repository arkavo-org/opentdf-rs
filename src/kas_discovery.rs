//! KAS endpoint discovery via /.well-known/opentdf-configuration
//!
//! Provides types for deserializing the platform's well-known configuration
//! document, plus URL-resolution logic that prefers ConnectRPC endpoints
//! and falls back to legacy REST paths when only REST is advertised.

#![cfg(feature = "kas-client")]
