# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Security
- Enable the `zeroize` features of `sha3` and `shake`, so the Keccak state of the combiner
  (which absorbs all three component shared secrets) and of the seed expansion is wiped on drop.
- Reject non-canonical HQC-192 public keys (unused high bits of the last byte set) in
  `EncapsulationKey::from_bytes`, so encapsulation-key bytes and keys correspond 1:1.

### Added
- Pinned regression vectors for all-zero and all-0xFF inputs, and for decapsulating a
  ciphertext with an all-zero (non-contributory) X25519 component.
- CI: MSRV + stable tests, `no_std` builds for `thumbv7em-none-eabi` and
  `wasm32-unknown-unknown`, clippy, rustfmt, rustdoc, and `cargo audit`.

### Documentation
- Document `EncapsulationKey::from_bytes` validation rules, side-channel and zeroization
  caveats in the README, and `# Panics` sections on the `getrandom`-based functions.

## 0.1.0

- Initial release: X25519 + ML-KEM-768 + HQC-192 hybrid KEM.
