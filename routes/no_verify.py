"""
Vulnerability #4: missing signature verification / missing expiry check.

VULNERABLE (/vuln/no-verify/*): the endpoint decodes the token's header and
payload but never checks the signature and never checks `exp`. Any
hand-edited payload -- even with a garbage signature, even long expired --
is trusted.

FIXED (/fixed/no-verify/*): the endpoint verifies both the signature and
the expiry claim before trusting anything in the payload.
"""
import time

from flask import Blueprint, jsonify, request

import jwt_toy
from keys import DEMO_SECRET
from routes.util import bearer_token

bp = Blueprint("no_verify", __name__)


@bp.post("/vuln/no-verify/login")
def vuln_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, DEMO_SECRET, alg="HS256"
    )
    return jsonify(token=token)


@bp.get("/vuln/no-verify/whoami")
def vuln_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        # VULNERABLE: signature and expiry are both skipped entirely.
        payload = jwt_toy.decode(
            token, key=None, allowed_algs=None, verify_exp=False, verify_signature=False
        )
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))


@bp.post("/fixed/no-verify/login")
def fixed_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, DEMO_SECRET, alg="HS256"
    )
    return jsonify(token=token)


@bp.get("/fixed/no-verify/whoami")
def fixed_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        # FIXED: both signature and expiry are verified.
        payload = jwt_toy.decode(
            token, key=DEMO_SECRET, allowed_algs=["HS256"], verify_exp=True, verify_signature=True
        )
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))
