"""
Vulnerability #1: alg=none acceptance.

VULNERABLE (/vuln/none/*): the verifier accepts a token whose header says
{"alg": "none"} and has no signature at all, trusting the payload blindly.

FIXED (/fixed/none/*): the verifier explicitly whitelists the algorithms it
accepts (["HS256"]) and never allows "none", full stop.
"""
import time

from flask import Blueprint, jsonify, request

import jwt_toy
from keys import DEMO_SECRET
from routes.util import bearer_token

bp = Blueprint("none_alg", __name__)


@bp.post("/vuln/none/login")
def vuln_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, DEMO_SECRET, alg="HS256"
    )
    return jsonify(token=token)


@bp.get("/vuln/none/whoami")
def vuln_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        # VULNERABLE: allow_none=True means a header of {"alg": "none"} skips
        # signature verification entirely.
        payload = jwt_toy.decode(token, key=DEMO_SECRET, allowed_algs=["HS256"], allow_none=True)
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))


@bp.post("/fixed/none/login")
def fixed_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, DEMO_SECRET, alg="HS256"
    )
    return jsonify(token=token)


@bp.get("/fixed/none/whoami")
def fixed_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        # FIXED: allow_none defaults to False, so alg=none is always rejected,
        # and only HS256 is in the allowed-algorithm whitelist.
        payload = jwt_toy.decode(token, key=DEMO_SECRET, allowed_algs=["HS256"])
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))
