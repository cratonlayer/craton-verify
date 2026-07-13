#!/usr/bin/env python3
"""Offline verifier for craton.receipt.protocol.v1 receipts.

This script uses only the Python standard library. It verifies Ed25519
signatures over the decoded receipt.payload_b64 bytes and never calls Craton.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
IDENTITY = (0, 1)

CRATON_ROOT_TRUST_ANCHORS = {
    "craton-root-v1": {
        "root_key_id": "craton-root-v1",
        "public_key_b64": "P6Z/Z9yfpiiKR+oq8AxTR3Oe5ax9lY4Hrm0kQYa5im8=",
        "public_key_fingerprint_sha256": "43a88132f76a9201b0773f245381329922754eed1a668d386be653b5549cfe80",
        "sig_alg": "ed25519",
    }
}
ATTESTATION_OBJECT = "craton.receipt.operational_key_attestation.v1"
ATTESTATION_PAYLOAD_OBJECT = "craton.receipt.operational_key_attestation_payload.v1"
RECEIPT_PROTOCOL = "craton.receipt.protocol.v1"


def _inv(value: int) -> int:
    return pow(value, P - 2, P)


D = (-121665 * _inv(121666)) % P
I = pow(2, (P - 1) // 4, P)
B_Y = (4 * _inv(5)) % P


def _xrecover(y: int) -> int:
    xx = ((y * y - 1) * _inv(D * y * y + 1)) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x & 1:
        x = P - x
    return x


B = (_xrecover(B_Y), B_Y)


def _is_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _edwards(point_a: tuple[int, int], point_b: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = point_a
    x2, y2 = point_b
    return (
        ((x1 * y2 + x2 * y1) * _inv(1 + D * x1 * x2 * y1 * y2)) % P,
        ((y1 * y2 + x1 * x2) * _inv(1 - D * x1 * x2 * y1 * y2)) % P,
    )


def _scalar_mult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = _edwards(result, point)
        point = _edwards(point, point)
        scalar >>= 1
    return result


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 public keys and R values must be 32 bytes")
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("point encoding is not canonical")
    x = _xrecover(y)
    if (x & 1) != (encoded[31] >> 7):
        x = P - x
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("point is not on Ed25519 curve")
    return point


def _is_small_order(point: tuple[int, int]) -> bool:
    return _scalar_mult(point, 8) == IDENTITY


def verify_ed25519(signature: bytes, message: bytes, public_key: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r_point = _decode_point(signature[:32])
        public_point = _decode_point(public_key)
    except ValueError:
        return False
    if _is_small_order(r_point) or _is_small_order(public_point):
        return False
    s_value = int.from_bytes(signature[32:], "little")
    if s_value >= L:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(),
        "little",
    ) % L
    return _scalar_mult(B, s_value) == _edwards(r_point, _scalar_mult(public_point, challenge))


def b64_decode(value: str) -> bytes:
    compact = "".join(str(value).split()).replace("-", "+").replace("_", "/")
    compact += "=" * ((4 - len(compact) % 4) % 4)
    return base64.b64decode(compact, validate=True)


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_timestamp(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("missing timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def extract_receipt(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        if isinstance(document.get("receipt"), dict):
            return document["receipt"]
        if {"payload_b64", "signature", "kid"}.issubset(document.keys()):
            return document
        for value in document.values():
            if isinstance(value, dict):
                try:
                    return extract_receipt(value)
                except ValueError:
                    pass
    raise ValueError("receipt object not found")


def public_key_bytes_from_key_entry(key: dict[str, Any], kid: str) -> bytes:
    jwk = key.get("public_key_jwk") if isinstance(key.get("public_key_jwk"), dict) else key
    public_key_b64 = key.get("public_key_b64")
    if public_key_b64:
        public_key = b64_decode(public_key_b64)
    else:
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError(f"key {kid!r} is not an Ed25519 OKP key")
        public_key = b64_decode(jwk["x"])
    if len(public_key) != 32:
        raise ValueError(f"key {kid!r} does not contain a 32-byte Ed25519 public key")
    return public_key


def select_public_key_entry(jwks: dict[str, Any], kid: str) -> tuple[dict[str, Any], bytes]:
    for key in jwks.get("keys", []):
        if isinstance(key, dict) and key.get("kid") == kid:
            return key, public_key_bytes_from_key_entry(key, kid)
    raise ValueError(f"no key bundle entry matches receipt.kid {kid!r}")


def select_public_key(jwks: dict[str, Any], kid: str) -> bytes:
    return select_public_key_entry(jwks, kid)[1]


def attestation_from_document(document: Any) -> dict[str, Any] | None:
    if not isinstance(document, dict):
        return None
    attestation = document.get("attestation") or document.get("operational_key_attestation")
    return attestation if isinstance(attestation, dict) else None


def missing_attestation_report() -> dict[str, Any]:
    return {
        "issuer_identity_verified": False,
        "trust_anchor": "missing_attestation_legacy_bundle",
        "attestation_status": "missing",
        "trust_boundary": "Receipt signature is valid for the supplied key, but this legacy input does not include a root-signed Craton operational-key attestation.",
    }


def invalid_attestation_report(reason: str) -> dict[str, Any]:
    return {
        "issuer_identity_verified": False,
        "trust_anchor": "invalid_operational_key_attestation",
        "attestation_status": "invalid",
        "attestation_failure_reason": reason,
        "trust_boundary": "Receipt signature is valid for the supplied key, but the supplied operational-key attestation did not verify against the pinned Craton root trust anchor.",
    }


def verify_operational_key_attestation(attestation: dict[str, Any] | None, kid: str, operational_public_key: bytes) -> dict[str, Any]:
    if not attestation:
        return missing_attestation_report()
    try:
        if attestation.get("object") != ATTESTATION_OBJECT:
            return invalid_attestation_report("unsupported_attestation_object")
        root_key_id = str(attestation.get("root_key_id") or "").strip()
        anchor = CRATON_ROOT_TRUST_ANCHORS.get(root_key_id)
        if not anchor:
            return invalid_attestation_report("unknown_root_key_id")
        root_public_key = b64_decode(anchor["public_key_b64"])
        if sha256_hex(root_public_key) != anchor["public_key_fingerprint_sha256"]:
            return invalid_attestation_report("pinned_root_fingerprint_mismatch")
        if str(attestation.get("root_public_key_fingerprint_sha256") or "").strip() != anchor["public_key_fingerprint_sha256"]:
            return invalid_attestation_report("attestation_root_fingerprint_mismatch")
        payload_bytes = b64_decode(str(attestation.get("payload_b64") or ""))
        signature = b64_decode(str(attestation.get("signature") or ""))
        if not verify_ed25519(signature, payload_bytes, root_public_key):
            return invalid_attestation_report("root_signature_verification_failed")
        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("object") != ATTESTATION_PAYLOAD_OBJECT:
            return invalid_attestation_report("unsupported_attestation_payload_object")
        if payload.get("protocol") != RECEIPT_PROTOCOL:
            return invalid_attestation_report("unsupported_attestation_protocol")
        if payload.get("root_key_id") != root_key_id:
            return invalid_attestation_report("root_key_id_payload_mismatch")
        if payload.get("root_public_key_fingerprint_sha256") != anchor["public_key_fingerprint_sha256"]:
            return invalid_attestation_report("root_fingerprint_payload_mismatch")
        subject = payload.get("subject")
        if not isinstance(subject, dict):
            return invalid_attestation_report("missing_subject")
        if str(subject.get("kid") or "").strip() != kid:
            return invalid_attestation_report("subject_kid_mismatch")
        if str(subject.get("allowed_use") or "").strip() != "receipt_signing":
            return invalid_attestation_report("subject_use_not_receipt_signing")
        if str(subject.get("sig_alg") or "").strip().lower() != "ed25519":
            return invalid_attestation_report("subject_sig_alg_not_ed25519")
        subject_public_b64 = str(subject.get("public_key_b64") or "").strip()
        if subject_public_b64 and b64_decode(subject_public_b64) != operational_public_key:
            return invalid_attestation_report("subject_public_key_mismatch")
        if subject.get("public_key_fingerprint_sha256") != sha256_hex(operational_public_key):
            return invalid_attestation_report("subject_public_key_fingerprint_mismatch")
        now = datetime.now(timezone.utc)
        not_before = parse_timestamp(payload.get("not_before") or payload.get("issued_at"))
        not_after = parse_timestamp(payload.get("not_after"))
        if now < not_before:
            return invalid_attestation_report("attestation_not_yet_valid")
        if now > not_after:
            return invalid_attestation_report("attestation_expired")
        return {
            "issuer_identity_verified": True,
            "trust_anchor": root_key_id,
            "attestation_status": "verified",
            "attestation_payload_sha256": sha256_hex(payload_bytes),
            "root_public_key_fingerprint_sha256": anchor["public_key_fingerprint_sha256"],
            "operational_key_fingerprint_sha256": sha256_hex(operational_public_key),
            "attestation_not_after": payload.get("not_after"),
            "trust_boundary": "Receipt signature is valid and the operational signing key is covered by a root-signed Craton attestation pinned by this verifier.",
        }
    except Exception as exc:
        return invalid_attestation_report(str(exc))


def resolve_verification_inputs(receipt_document: Any, jwks_document: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any] | None]:
    if isinstance(receipt_document, dict) and receipt_document.get("object") == "craton.receipt.verification_bundle":
        receipt = receipt_document.get("receipt")
        key_bundle = receipt_document.get("key_bundle")
        if not isinstance(receipt, dict) or not isinstance(key_bundle, dict):
            raise ValueError("verification bundle must include receipt and key_bundle objects")
        return receipt, key_bundle, "verification_bundle", attestation_from_document(receipt_document)
    if jwks_document is None:
        raise ValueError("non-bundle receipt input requires --jwks with the pinned public key bundle")
    return extract_receipt(receipt_document), jwks_document, "jwks_argument", attestation_from_document(receipt_document)


def verify_receipt(receipt_document: Any, jwks_document: dict[str, Any] | None = None) -> dict[str, Any]:
    receipt, key_document, key_source, attestation = resolve_verification_inputs(receipt_document, jwks_document)
    payload_b64 = receipt.get("payload_b64")
    signature_b64 = receipt.get("signature")
    kid = receipt.get("kid")
    if not payload_b64 or not signature_b64 or not kid:
        raise ValueError("receipt must include payload_b64, signature, and kid")
    sig_alg = str(receipt.get("sig_alg", "ed25519")).lower()
    if sig_alg != "ed25519":
        raise ValueError(f"unsupported receipt signature algorithm {receipt.get('sig_alg')!r}")

    payload_bytes = b64_decode(payload_b64)
    signature = b64_decode(signature_b64)
    _, public_key = select_public_key_entry(key_document, str(kid))
    signature_valid = verify_ed25519(signature, payload_bytes, public_key)
    if not signature_valid:
        raise ValueError("signature verification failed")

    try:
        signed_payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"verified payload is not valid UTF-8 JSON: {exc}") from exc
    if signed_payload.get("protocol") != RECEIPT_PROTOCOL:
        raise ValueError("verified payload is not craton.receipt.protocol.v1")

    attestation_report = verify_operational_key_attestation(attestation, str(kid), public_key)
    issuer_identity_verified = bool(attestation_report.get("issuer_identity_verified"))

    return {
        "verified": bool(signature_valid and issuer_identity_verified),
        "signature_valid": bool(signature_valid),
        "verification_scope": "signature_and_root_attestation" if issuer_identity_verified else "signature_matches_supplied_key",
        **attestation_report,
        "kid": kid,
        "sig_alg": "ed25519",
        "payload_sha256": sha256_hex(payload_bytes),
        "key_source": key_source,
        "protocol": signed_payload.get("protocol"),
        "commitment_id": signed_payload.get("commitment_id"),
        "request_id": signed_payload.get("request_id"),
        "verdict": signed_payload.get("verdict"),
        "signed_payload": signed_payload,
    }


def load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify a Craton receipt offline.")
    parser.add_argument("receipt", help="Path to verification bundle, receipt JSON, or full boundary response JSON")
    parser.add_argument("--jwks", help="Path to pinned JWKS public key bundle for legacy two-file verification")
    args = parser.parse_args(argv)

    try:
        jwks_document = load_json(args.jwks) if args.jwks else None
        report = verify_receipt(load_json(args.receipt), jwks_document)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({
            "verified": False,
            "signature_valid": False,
            "issuer_identity_verified": False,
            "trust_anchor": "verification_failed_before_trust_anchor",
            "reason": str(exc),
        }, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
