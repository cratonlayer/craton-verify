#!/usr/bin/env python3
"""Offline verifier for craton.receipt.protocol.v1 receipts.

This script uses only the Python standard library. It verifies Ed25519
signatures over the decoded receipt.payload_b64 bytes and never calls Craton.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


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
    x = _xrecover(y)
    if (x & 1) != (encoded[31] >> 7):
        x = P - x
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("point is not on Ed25519 curve")
    return point


def verify_ed25519(signature: bytes, message: bytes, public_key: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r_point = _decode_point(signature[:32])
        public_point = _decode_point(public_key)
    except ValueError:
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
    compact = "".join(str(value).split())
    compact += "=" * ((4 - len(compact) % 4) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(compact)


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


def select_public_key(jwks: dict[str, Any], kid: str) -> bytes:
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
                raise ValueError(f"key {kid!r} is not an Ed25519 OKP key")
            return b64_decode(key["x"])
    raise ValueError(f"no JWKS key matches receipt.kid {kid!r}")


def verify_receipt(receipt_document: Any, jwks_document: dict[str, Any]) -> dict[str, Any]:
    receipt = extract_receipt(receipt_document)
    payload_b64 = receipt.get("payload_b64")
    signature_b64 = receipt.get("signature")
    kid = receipt.get("kid")
    if not payload_b64 or not signature_b64 or not kid:
        raise ValueError("receipt must include payload_b64, signature, and kid")

    payload_bytes = b64_decode(payload_b64)
    signature = b64_decode(signature_b64)
    public_key = select_public_key(jwks_document, str(kid))

    if not verify_ed25519(signature, payload_bytes, public_key):
        raise ValueError("signature verification failed")

    try:
        signed_payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"verified payload is not valid UTF-8 JSON: {exc}") from exc

    return {
        "verified": True,
        "kid": kid,
        "sig_alg": receipt.get("sig_alg", "ed25519"),
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
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
    parser.add_argument("receipt", help="Path to receipt JSON or full boundary response JSON")
    parser.add_argument("--jwks", required=True, help="Path to pinned JWKS public key bundle")
    args = parser.parse_args(argv)

    try:
        report = verify_receipt(load_json(args.receipt), load_json(args.jwks))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"verified": False, "reason": str(exc)}, indent=2, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
