import time

from exploits.exploit_no_verify import forge_unverified_token


def test_vuln_no_verify_accepts_expired_unsigned_token(client):
    token = forge_unverified_token({"user": "attacker", "admin": True, "exp": time.time() - 3600})
    resp = client.get("/vuln/no-verify/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["admin"] is True


def test_fixed_no_verify_rejects_expired_unsigned_token(client):
    token = forge_unverified_token({"user": "attacker", "admin": True, "exp": time.time() - 3600})
    resp = client.get("/fixed/no-verify/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
