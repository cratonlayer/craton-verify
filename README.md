# Craton Offline Receipt Verifier

Craton receipts are designed to remain independently verifiable even if the Craton runtime is unavailable. This kit verifies a stored receipt locally with a pinned public key bundle. It does not call Craton, does not require a network connection, and does not send receipt data anywhere.

The verifier implements `craton.receipt.protocol.v1` only. It verifies the Ed25519 signature over the exact decoded `receipt.payload_b64` bytes before it parses or displays the signed payload.

## Files

- `verify.html` - offline browser verifier with no external dependencies.
- `verify.py` - command-line verifier using only the Python standard library.
- `examples/sample_receipt.json` - a signed test receipt for this kit.
- `keys/public_key.jwks.json` - the public key bundle that verifies the sample receipt.

The included sample receipt and key are test fixtures. For production receipts, replace `keys/public_key.jwks.json` with the pinned public key bundle from:

```text
https://cratonlayer.com/protocol/v1/jwks.json
```

Retain the receipt and the JWKS bundle together for audit records. Do not fetch a fresh JWKS later and treat it as proof of what was pinned when the receipt was created.

## Browser Usage

1. Open `verify.html` from this folder. It can be opened directly from disk.
2. Paste a receipt JSON object into the receipt field. You may paste either the receipt itself, `{ "receipt": ... }`, or a full boundary response that contains `receipt`.
3. Paste the public JWKS key bundle you retained with the receipt.
4. Select **Verify receipt**.

The page verifies the Ed25519 signature over the decoded `receipt.payload_b64` bytes. Only after the signature is valid does it parse and display the signed payload.

## Command-Line Usage

Verify the bundled sample:

```bash
python verify.py examples/sample_receipt.json --jwks keys/public_key.jwks.json
```

Verify a production receipt with a pinned production key bundle:

```bash
python verify.py path/to/receipt.json --jwks path/to/pinned-public-key.jwks.json
```

On success, the script prints a JSON report with `verified: true`, the selected `kid`, a SHA-256 hash of the signed payload bytes, and the decoded signed payload. On failure, it exits non-zero and prints `verified: false` with a reason.

## Security Notes

- The sample receipt and bundled key are fixtures for testing this kit. They are not production keys.
- Production verification depends on a receipt plus the exact public JWKS bundle retained for that audit record.
- The verifier rejects unsupported signature algorithms, non-canonical Ed25519 point encodings, small-order Ed25519 points, and payloads that are not `craton.receipt.protocol.v1`.
- Signature verification is performed before payload parsing. Do not reserialize the payload JSON and verify a transformed representation.
- This repository intentionally contains no production private keys, API keys, customer data, runtime configuration, or Craton server code.

## Verification Logic

The verification logic follows `craton.receipt.protocol.v1`:

1. Extract `receipt.payload_b64`, `receipt.signature`, and `receipt.kid`.
2. Select the public key in the JWKS whose `kid` matches the receipt.
3. Decode `receipt.payload_b64` to bytes.
4. Decode `receipt.signature` and the selected Ed25519 public key.
5. Verify the signature over the decoded payload bytes exactly.
6. Do not reserialize JSON before verifying.
7. Parse the signed payload only after the signature is valid.

This is the basis for no-callback verification: a retained receipt plus a pinned public key bundle can be checked offline by auditors, counsel, engineers, or other authorized third parties.
