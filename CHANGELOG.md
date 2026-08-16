# Changelog

## Unreleased

- Aligned public positioning with retained CRATON signed boundary records.
- Reduced public documentation to the minimum verification contract.
- Replaced the sample with a disclosure-safe cryptographic fixture.
- Removed non-verification payload fields from verifier summary output.
- Added single-file CRATON verification bundle input for `verify.py`.
- Kept legacy `receipt.json --jwks pinned-public-key.jwks.json` mode for compatibility.
- Added support for CRATON public key bundle entries that wrap public JWK material.

## v0.1.0

Initial public verifier kit for `craton.receipt.protocol.v1`.

- Added `verify.html`, a standalone browser verifier with no network calls.
- Added `verify.py`, a command-line verifier using only the Python standard library.
- Added sample receipt and pinned sample public key fixtures.
- Added Ed25519 verification over exact decoded `receipt.payload_b64` bytes.
- Added checks for unsupported signature algorithms, non-canonical Ed25519 points, small-order points, and non-v1 payloads.
- Added repository hygiene files for public distribution.
