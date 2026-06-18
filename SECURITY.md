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
