# Changelog

## v0.1.0

Initial public verifier kit for `craton.receipt.protocol.v1`.

- Added `verify.html`, a standalone browser verifier with no network calls.
- Added `verify.py`, a command-line verifier using only the Python standard library.
- Added sample receipt and pinned sample public key fixtures.
- Added Ed25519 verification over exact decoded `receipt.payload_b64` bytes.
- Added checks for unsupported signature algorithms, non-canonical Ed25519 points, small-order Ed25519 points, and non-v1 payloads.
- Added repository hygiene files for public distribution.
