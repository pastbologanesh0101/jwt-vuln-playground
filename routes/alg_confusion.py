"""
Vulnerability #3: RS256 -> HS256 algorithm confusion.

VULNERABLE (/vuln/alg-confusion/*): tokens are normally issued with RS256,
verified with the server's RSA key pair. But the verifier hands the SAME
key material to the verifier no matter what algorithm the attacker's
header claims. Since RSA public keys are meant to be public, an attacker
can fetch it, then craft a token with header {"alg": "HS256"} and HMAC-sign
it using the public key's PEM bytes as the "secret". The verifier ends up
running HMAC verification with that exact key material and accepts it.

FIXED (/fixed/alg-confusion/*): the algorithm is pinned server-side
(allowed_algs=["RS256"]) independent of anything the attacker's header
says, and the key handed to the verifier is already a proper RSA public
key object -- there is no way for an attacker-chosen alg to repurpose it
as an HMAC secret.
"""
import time

from flask import Blueprint, jsonify, request

import jwt_toy
from keys import RSA_PRIVATE_KEY, RSA_PUBLIC_KEY, RSA_PUBLIC_PEM
from routes.util import bearer_token

bp = Blueprint("alg_confusion", __name__)


@bp.post("/vuln/alg-confusion/login")
def vuln_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, RSA_PRIVATE_KEY, alg="RS256"
    )
    return jsonify(token=token)


@bp.get("/vuln/alg-confusion/public-key")
def vuln_public_key():
    # RSA public keys (and JWKS endpoints in real systems) are meant to be
    # public -- that is exactly what makes this vulnerability dangerous:
    # the attacker doesn't need to steal anything.
    return jsonify(public_key_pem=RSA_PUBLIC_PEM.decode("ascii"))


@bp.get("/vuln/alg-confusion/whoami")
def vuln_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        # VULNERABLE: the same key bytes are handed to decode() regardless
        # of which algorithm the attacker's header claims, and both RS256
        # and HS256 are accepted.
        payload = jwt_toy.decode(token, key=RSA_PUBLIC_PEM, allowed_algs=["RS256", "HS256"])
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))


@bp.post("/fixed/alg-confusion/login")
def fixed_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, RSA_PRIVATE_KEY, alg="RS256"
    )
    return jsonify(token=token)


@bp.get("/fixed/alg-confusion/whoami")
def fixed_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        # FIXED: algorithm is pinned to what this key/issuer actually uses.
        # An attacker-supplied alg=HS256 header is rejected before the key
        # is ever touched.
        payload = jwt_toy.decode(token, key=RSA_PUBLIC_KEY, allowed_algs=["RS256"])
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))
