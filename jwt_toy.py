"""
jwt_toy.py -- a small, hand-rolled JWT encode/decode implementation.

This intentionally does NOT wrap a hardened third-party JWT library.
The whole point of this project is to demonstrate genuine, exploitable
classic JWT vulnerabilities, and a well-hardened library (like modern
PyJWT with its defaults) would silently prevent most of them. Writing
the encode/decode logic ourselves means the vulnerable code paths in
routes/*.py are real, not simulated.

Only the low-level cryptographic primitives (HMAC-SHA256 via hashlib/hmac,
and RSA sign/verify via the `cryptography` package) are reused -- the JWT
*protocol* logic (header/payload framing, algorithm selection, signature
verification, expiry checking) is all implemented here from scratch.

DO NOT use this module for anything other than local security education.
It is deliberately flexible/unsafe in ways a production JWT library is not.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


class JWTError(Exception):
    """Raised whenever a token is malformed or fails verification."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _json_dumps(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=False).encode("utf-8")


def encode(payload: dict, key: Any, alg: str = "HS256") -> str:
    """Encode `payload` into a JWT signed with `key` using `alg`.

    alg="HS256": key is a str/bytes HMAC secret.
    alg="RS256": key is a `cryptography` RSA private key object.
    alg="none":  key is ignored, token is left unsigned.
    """
    header = {"alg": alg, "typ": "JWT"}
    header_b64 = b64url_encode(_json_dumps(header))
    payload_b64 = b64url_encode(_json_dumps(payload))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if alg == "none":
        signature_b64 = ""
    elif alg == "HS256":
        key_bytes = key if isinstance(key, bytes) else str(key).encode("utf-8")
        sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
        signature_b64 = b64url_encode(sig)
    elif alg == "RS256":
        sig = key.sign(signing_input, asym_padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = b64url_encode(sig)
    else:
        raise ValueError(f"Unsupported alg: {alg}")

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode(
    token: str,
    key: Optional[Any] = None,
    allowed_algs: Optional[list] = None,
    verify_exp: bool = True,
    allow_none: bool = False,
    verify_signature: bool = True,
) -> dict:
    """Decode and (optionally) verify a JWT.

    This single function is deliberately parameterized so that the SAME
    hand-rolled implementation can express both the vulnerable and the
    fixed behaviour for every scenario in this project -- the difference
    between "vulnerable" and "fixed" routes is which arguments they pass,
    exactly like real-world misconfigurations of real JWT libraries.

    key:              HMAC secret (str/bytes) for HS256, or an RSA public
                       key (either a `cryptography` key object, or raw PEM
                       bytes -- see the algorithm-confusion vulnerability).
    allowed_algs:      whitelist of algorithms this caller accepts, e.g.
                       ["HS256"] or ["RS256"]. None means "no restriction"
                       (vulnerable).
    verify_exp:        if True, reject tokens with a missing/past `exp`.
    allow_none:        if True, a token with header {"alg": "none"} is
                       accepted with NO signature check whatsoever
                       (this is the classic alg=none vulnerability).
    verify_signature:  if False, skip ALL signature verification, no
                       matter the algorithm (the classic "missing
                       verification" vulnerability).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError("Malformed token: expected 3 dot-separated segments")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception as exc:  # noqa: BLE001 - deliberately broad, re-raised as JWTError
        raise JWTError(f"Malformed token: {exc}") from exc

    alg = header.get("alg")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    if verify_signature:
        if alg == "none":
            if not allow_none:
                raise JWTError("alg=none is not permitted by this verifier")
            # No signature to check for alg=none.
        else:
            if allowed_algs is not None and alg not in allowed_algs:
                raise JWTError(f"Algorithm '{alg}' is not in the allowed list {allowed_algs}")

            if alg == "HS256":
                if key is None:
                    raise JWTError("No key configured for HS256 verification")
                key_bytes = key if isinstance(key, bytes) else str(key).encode("utf-8")
                expected_sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
                try:
                    actual_sig = b64url_decode(signature_b64)
                except Exception as exc:  # noqa: BLE001
                    raise JWTError("Malformed signature") from exc
                if not hmac.compare_digest(expected_sig, actual_sig):
                    raise JWTError("HMAC signature verification failed")

            elif alg == "RS256":
                if key is None:
                    raise JWTError("No key configured for RS256 verification")
                pubkey = key
                if isinstance(key, bytes):
                    pubkey = serialization.load_pem_public_key(key)
                try:
                    actual_sig = b64url_decode(signature_b64)
                    pubkey.verify(
                        actual_sig,
                        signing_input,
                        asym_padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                except InvalidSignature as exc:
                    raise JWTError("RSA signature verification failed") from exc
                except Exception as exc:  # noqa: BLE001
                    raise JWTError(f"RSA signature verification failed: {exc}") from exc

            else:
                raise JWTError(f"Unsupported alg '{alg}'")
    # else: verify_signature is False -> deliberately skip every signature
    # check, regardless of alg. This models the "missing verification"
    # vulnerability where a token is decoded but never authenticated.

    if verify_exp:
        exp = payload.get("exp")
        if exp is None:
            raise JWTError("Missing 'exp' claim")
        if time.time() > exp:
            raise JWTError("Token has expired")

    return payload
