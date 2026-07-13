# Security Policy

## Scope

This repository contains only the standalone offline verifier for `craton.receipt.protocol.v1`.

In scope:

- Verification behavior in `verify.py`
- Verification behavior in `verify.html`
- Sample receipt and sample public key fixtures
- Documentation that affects safe verifier use

Out of scope:

- Craton production runtime services
- Production signing keys
- Customer data or customer configuration
- Billing, activation, deployment, or API-key provisioning flows

## Reporting

Please report suspected verifier security issues privately to the Craton maintainers before public disclosure.

Include:

- The affected file and version or commit SHA
- A minimal receipt/JWKS example when possible
- Expected behavior and observed behavior
- Whether the issue affects false positives, false negatives, or local data handling

## Design Boundary

The verifier must remain independently auditable:

- No network calls during verification
- No third-party runtime dependencies
- No production secrets or customer data
- Signature verification before payload parsing or display
- Exact-byte verification over decoded `receipt.payload_b64`

## Root Trust Anchor

Current verification bundles may include an `attestation` object. This attestation is signed by Craton's offline root key and binds an operational receipt-signing key to a specific `kid`, public key fingerprint, allowed use, environment, and validity window.

The command-line verifier pins the Craton root public key fingerprint:

```text
craton-root-v1 / 43a88132f76a9201b0773f245381329922754eed1a668d386be653b5549cfe80
```

For an anchored verification bundle, the verifier first validates the root-signed operational-key attestation. Only after that does it verify the receipt signature with the attested operational key. A forged bundle that contains a fake receipt and an attacker-generated public key cannot produce `issuer_identity_verified: true` unless it also contains a valid Craton root-signed attestation for that key.

Legacy receipts or bundles without an attestation are still checked for signature consistency. They return `signature_valid: true` when the receipt signature matches the supplied key, but they return `issuer_identity_verified: false` and `trust_anchor: "missing_attestation_legacy_bundle"`. That legacy result means the receipt and supplied key are internally consistent; it does not prove the key was issued by Craton.

The root private key is not stored in this repository, not used by this verifier, and not required for ordinary receipt verification. It is held offline and used only to sign operational-key attestations.
