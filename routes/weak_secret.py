"""
Vulnerability #2: weak / guessable HMAC secret.

VULNERABLE (/vuln/weak-secret/*): tokens are signed with the string
"secret" -- trivially recoverable with a tiny wordlist brute force.

FIXED (/fixed/weak-secret/*): tokens are signed with a 256-bit random
secret generated at process start, which is not in any reasonable
wordlist.
"""
import time

from flask import Blueprint, jsonify, request

import jwt_toy
from keys import STRONG_SECRET, WEAK_SECRET
from routes.util import bearer_token

bp = Blueprint("weak_secret", __name__)


@bp.post("/vuln/weak-secret/login")
def vuln_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, WEAK_SECRET, alg="HS256"
    )
    return jsonify(token=token)


@bp.get("/vuln/weak-secret/whoami")
def vuln_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        payload = jwt_toy.decode(token, key=WEAK_SECRET, allowed_algs=["HS256"])
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))


@bp.post("/fixed/weak-secret/login")
def fixed_login():
    username = (request.get_json(silent=True) or {}).get("username", "alice")
    token = jwt_toy.encode(
        {"user": username, "admin": False, "exp": time.time() + 300}, STRONG_SECRET, alg="HS256"
    )
    return jsonify(token=token)


@bp.get("/fixed/weak-secret/whoami")
def fixed_whoami():
    token = bearer_token()
    if not token:
        return jsonify(error="missing token"), 401
    try:
        payload = jwt_toy.decode(token, key=STRONG_SECRET, allowed_algs=["HS256"])
    except jwt_toy.JWTError as exc:
        return jsonify(error=str(exc)), 401
    return jsonify(user=payload.get("user"), admin=payload.get("admin", False))
