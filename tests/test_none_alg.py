import time

from exploits.exploit_none import forge_none_token


def test_vuln_none_accepts_forged_admin_token(client):
    token = forge_none_token({"user": "attacker", "admin": True, "exp": time.time() + 300})
    resp = client.get("/vuln/none/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["admin"] is True


def test_fixed_none_rejects_forged_token(client):
    token = forge_none_token({"user": "attacker", "admin": True, "exp": time.time() + 300})
    resp = client.get("/fixed/none/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_fixed_none_accepts_properly_signed_token(client):
    login = client.post("/fixed/none/login", json={"username": "alice"})
    token = login.get_json()["token"]
    resp = client.get("/fixed/none/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["user"] == "alice"
