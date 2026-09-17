from flask import request


def bearer_token():
    """Extract the raw token string from an `Authorization: Bearer <token>` header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):]
    return None
