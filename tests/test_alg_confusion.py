import time

from exploits.exploit_alg_confusion import forge_hs256_token_using_public_key


def test_vuln_alg_confusion_accepts_forged_hs256_token(client):
    pubkey_resp = client.get("/vuln/alg-confusion/public-key")
    pem = pubkey_resp.get_json()["public_key_pem"].encode()

    forged = forge_hs256_token_using_public_key(
        {"user": "attacker", "admin": True, "exp": time.time() + 300}, pem
    )
    resp = client.get("/vuln/alg-confusion/whoami", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 200
    assert resp.get_json()["admin"] is True


def test_fixed_alg_confusion_rejects_forged_hs256_token(client):
    pubkey_resp = client.get("/vuln/alg-confusion/public-key")
    pem = pubkey_resp.get_json()["public_key_pem"].encode()

    forged = forge_hs256_token_using_public_key(
        {"user": "attacker", "admin": True, "exp": time.time() + 300}, pem
    )
    resp = client.get("/fixed/alg-confusion/whoami", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401
