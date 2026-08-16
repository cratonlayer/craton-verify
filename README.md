# CRATON Offline Verifier

Standalone offline verifier for retained CRATON signed boundary records.

Verification runs locally without a CRATON account, network callback, package installation, or production-service dependency. The verifier is intended to establish:

- cryptographic integrity;
- issuer/key binding when applicable retained trust material is present; and
- validity of the retained public verification material used for the check.

It does not independently establish underlying business truth, completeness of evidence, physical execution, legal or organisational authority, or independent trusted time.

## Verification inputs

The recommended input is the verification bundle retained with the signed boundary record. A legacy two-file mode remains available for a retained record and its pinned public key bundle.

Keep the record and its verification material together. A public key fetched later can show what is published at that later time; it is not evidence of what was retained with the original record.

The public protocol version, signature algorithm, and verification fields present in a retained record are interoperability metadata. They do not describe how CRATON constructs production requests, boundary decisions, acknowledgements, or execution confirmations.

## Files

- `verify.py` — command-line verifier using only the Python standard library.
- `verify.html` — standalone browser verifier with no external dependencies.
- `examples/sample_receipt.json` — disclosure-safe signed test fixture.
- `keys/public_key.jwks.json` — test-only public key material for the fixture.

The sample files are not production records or production keys.

## Command-line usage

Verify a retained verification bundle:

```bash
python verify.py path/to/craton_verification_bundle.json
```

Verify a legacy retained record with its pinned public key bundle:

```bash
python verify.py path/to/receipt.json --jwks path/to/pinned-public-key.jwks.json
```

Verify the included test fixture:

```bash
python verify.py examples/sample_receipt.json --jwks keys/public_key.jwks.json
```

For a current verification bundle, `verified: true` means that both signature integrity and issuer/key binding were established against the applicable retained trust material. A legacy input can return `signature_valid: true` while `issuer_identity_verified` and `verified` remain false. Failed verification exits non-zero.

## Browser usage

Open `verify.html` directly from disk, paste the retained signed record and its pinned public JWKS material, then select **Verify receipt**.

The browser page is deliberately limited to the legacy two-input check. It establishes signature consistency with the supplied public key but does not establish issuer identity. Use the command-line verifier with a current retained verification bundle when issuer/key binding is required.

## Public verification resources

- Online verifier: <https://cratonlayer.com/verify>
- Current public verification keys: <https://cratonlayer.com/protocol/v1/jwks.json>

These resources support verification. They are not a production integration specification.

## Security boundary

- Verification performs no network calls and sends no record data anywhere.
- Signed content is not displayed as trusted until its signature has been checked.
- Unsupported algorithms and malformed verification material are rejected.
- The repository contains no signing private keys, customer data, production credentials, runtime configuration, server code, or production integration recipe.

See [SECURITY.md](SECURITY.md) for reporting and trust-boundary details.
