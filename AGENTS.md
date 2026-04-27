# Agents Guide

This document provides guidance for AI agents working with this codebase.

## Project Overview

**Smart Account Auth: CosmWasm** is a Rust library for authentication mechanisms in CosmWasm smart contracts, specifically designed for smart account implementations. It handles credential storage, verification, session keys, and replay attack protection.

## Repository Structure

```yaml
saa-wasm/
├── Cargo.toml              # Workspace manifest
├── packages/
│   ├── bundle/             # Main library bundle
│   │   └── src/
│   │       ├── lib.rs      # Library exports
│   │       ├── session.rs  # Session key handling
│   │       └── utils.rs    # Utility functions
│   ├── protos/             # Protocol buffer definitions
│   ├── tests/              # Test utilities
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── storage.rs  # Storage test helpers
│   │       ├── types.rs    # Test type definitions
│   │       └── utils.rs    # Test utilities
│   └── types/              # Type definitions
│       └── src/
│           ├── lib.rs
│           ├── sessions.rs # Session types
│           └── stores.rs   # Storage types
└── scripts/
    ├── check.sh            # Linting and checking script
    └── publish.sh          # Publishing script
```

## Key Concepts

### Credentials

Authentication credentials that can be stored and verified. Includes both native chain addresses and custom authenticators (e.g., passkeys, secp256k1 signatures).

### Replay Attack Protection

All signed messages include a nonce and contract address to prevent replay attacks. The envelope structure:

```rust
pub struct MsgDataToSign<M = String> {
    pub chain_id: String,
    pub contract_address: String,
    pub messages: Vec<M>,
    pub nonce: Uint64,
}
```

### Session Keys

Temporary authorization mechanisms with limited permissions and expiration.

## Development Guidelines

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

### Linting

```bash
./scripts/check.sh
```

### Code Style

- Follow standard Rust conventions
- Use `rustfmt` for formatting
- Use `clippy` for linting
- Prefer explicit error handling over `.unwrap()`

## Common Tasks

### Adding a New Credential Type

1. Define the type in `packages/types/src/`
2. Implement verification logic in `packages/bundle/src/`
3. Add storage helpers if needed
4. Write tests in `packages/tests/`

### Modifying Storage Schema

1. Update types in `packages/types/src/stores.rs`
2. Ensure backward compatibility or provide migration path
3. Update related verification logic

## Important Notes

- The `replay` feature tag is no longer optional; replay attack protection is always enabled
- The `iterator` feature is always enabled
- When working with factory/registry patterns, be aware of address and nonce handling for instantiation
- Native addresses use `MessageInfo` for verification; custom authenticators use signed payloads
