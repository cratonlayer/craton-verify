# Security Policy

## Scope

This repository contains the standalone offline verifier for retained CRATON signed boundary records.

In scope:

- verification behaviour in `verify.py` and `verify.html`;
- test-only signed-record and public-key fixtures; and
- documentation that affects safe verifier use.

Out of scope:

- CRATON production runtime services;
- signing private keys;
- customer data or customer configuration;
- billing, activation, deployment, or credential-provisioning flows; and
- issuer-side record construction or production integration mechanics.

## Reporting

Please report suspected verifier security issues privately to the CRATON maintainers before public disclosure.

Include:

- the affected file and version or commit SHA;
- a minimal test-only record and public-key example when possible;
- expected and observed behaviour; and
- whether the issue affects false positives, false negatives, or local data handling.

## Independent-verification boundary

The verifier must remain independently auditable:

- no network calls during verification;
- no third-party runtime dependency;
- no production secrets or customer data;
- signature validation before signed content is treated as trusted; and
- no production write, callback, or service dependency.

Current retained verification bundles may include public trust material that binds the signing key to CRATON. The command-line verifier validates that material against its pinned public trust anchor and reports issuer/key binding separately from signature integrity.

Legacy records without applicable retained trust material remain signature-checkable against the supplied public key. That result confirms internal signature consistency only; it does not establish that the supplied key was issued by CRATON.

The public trust material needed for verification is included in the verifier or retained bundle. No private trust-anchor material is stored in this repository or required for verification.

## Proof limits

A successful result establishes the cryptographic properties stated in the report. It does not independently establish business truth, evidence completeness, physical execution, legal or organisational authority, or independent trusted time.
