# Craton Offline Receipt Verifier

- **Status:** public verification kit for `craton.receipt.protocol.v1`
- **Runtime:** no network calls, no package install, no Craton account required
- **Use case:** retained verification bundle -> independent local verification

Craton receipts are designed to remain independently verifiable even if the Craton runtime is unavailable. The default input is a Craton verification bundle: the receipt plus the pinned public key bundle retained with it. The verifier does not call Craton, does not require a network connection, and does not send receipt data anywhere.

The verifier implements `craton.receipt.protocol.v1` only. It first checks any root-signed operational-key attestation carried in a verification bundle, then verifies the Ed25519 receipt signature over the exact decoded `receipt.payload_b64` bytes before it parses or displays the signed payload.

## Files

- `verify.html` - offline browser verifier with no external dependencies.
- `verify.py` - command-line verifier using only the Python standard library.
- `examples/sample_receipt.json` - a signed test receipt for this kit.
- `keys/public_key.jwks.json` - the public key bundle that verifies the sample receipt.
- A production verification bundle combines a receipt, its pinned key bundle, protocol metadata, and verifier instructions in one JSON file.

The included sample receipt and key are test fixtures. For production receipts, replace `keys/public_key.jwks.json` with the pinned public key bundle from:

```text
https://cratonlayer.com/protocol/v1/jwks.json
```

Retain the verification bundle for audit records. If you use the legacy two-file mode, retain the receipt and JWKS bundle together. Do not fetch a fresh JWKS later and treat it as proof of what was pinned when the receipt was created.

## Browser Usage

`verify.html` is a two-field browser verifier. It does not automatically parse a single verification bundle JSON file.

1. Open `verify.html` from this folder. It can be opened directly from disk.
2. Paste a receipt JSON object into the receipt field. You may paste either the receipt itself, `{ "receipt": ... }`, or a full boundary response that contains `receipt`.
3. Paste the public JWKS key bundle you retained with the receipt.
4. Select **Verify receipt**.

If you retained a Craton verification bundle, the recommended path is the command-line bundle mode below. To use this browser page manually, paste `bundle.receipt` into the receipt field and a JWKS document containing the matching public JWK into the JWKS field.

The page verifies the Ed25519 signature over the decoded `receipt.payload_b64` bytes. Only after the signature is valid does it parse and display the signed payload.

## Command-Line Usage

Verify a production verification bundle:

```bash
python verify.py path/to/craton_verification_bundle.json
```

Legacy two-file mode is still supported for retained receipt and key files:

```bash
python verify.py path/to/receipt.json --jwks path/to/pinned-public-key.jwks.json
```

Verify the bundled sample fixtures with the legacy two-file mode:

```bash
python verify.py examples/sample_receipt.json --jwks keys/public_key.jwks.json
```

On success, the script prints a JSON report with `signature_valid`, `issuer_identity_verified`, `trust_anchor`, the selected `kid`, a SHA-256 hash of the signed payload bytes, and the decoded signed payload. `verified: true` means both the receipt signature and the Craton root-signed operational-key attestation verified. Legacy inputs without attestation can return `signature_valid: true` with `issuer_identity_verified: false`.

## Security Notes

- The sample receipt and bundled key are fixtures for testing this kit. They are not production keys.
- Anchored production verification depends on a verification bundle that includes the receipt, the matching public key bundle, and a root-signed operational-key attestation.
- Legacy receipt/JWKS verification remains supported, but it proves only `signature_valid`, not `issuer_identity_verified`.
- The verifier rejects unsupported signature algorithms, non-canonical Ed25519 point encodings, small-order Ed25519 points, and payloads that are not `craton.receipt.protocol.v1`.
- Signature verification is performed before payload parsing. Do not reserialize the payload JSON and verify a transformed representation.
- This repository intentionally contains no production private keys, API keys, customer data, runtime configuration, or Craton server code.

## Repository Scope

This repository is intentionally narrow. It contains only the standalone offline verifier, a sample receipt fixture, and a sample public key fixture. It does not contain the Craton runtime, production signing keys, customer configuration, billing logic, or deployment configuration.

## Verification Logic

The verification logic follows `craton.receipt.protocol.v1`:

1. Extract `receipt.payload_b64`, `receipt.signature`, and `receipt.kid`.
2. Select the public key in the JWKS whose `kid` matches the receipt.
3. If an `attestation` object is present, verify it with the pinned Craton root key and confirm it binds the selected operational key.
4. Decode `receipt.payload_b64` to bytes.
5. Decode `receipt.signature` and the selected Ed25519 public key.
6. Verify the signature over the decoded payload bytes exactly.
7. Do not reserialize JSON before verifying.
8. Parse the signed payload only after the signature is valid.

This is the basis for no-callback verification: a retained verification bundle, or a retained receipt plus a pinned public key bundle, can be checked offline by auditors, counsel, engineers, or other authorized third parties.
