from exploits.exploit_weak_secret import brute_force_secret, forge_admin_token, load_wordlist


def test_vuln_weak_secret_is_brute_forceable_and_exploitable(client):
    login = client.post("/vuln/weak-secret/login", json={"username": "alice"})
    token = login.get_json()["token"]

    wordlist = load_wordlist()
    secret = brute_force_secret(token, wordlist)
    assert secret == "secret"

    forged = forge_admin_token(secret)
    resp = client.get("/vuln/weak-secret/whoami", headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 200
    assert resp.get_json()["admin"] is True


def test_fixed_weak_secret_is_not_recoverable_from_wordlist(client):
    login = client.post("/fixed/weak-secret/login", json={"username": "alice"})
    token = login.get_json()["token"]

    wordlist = load_wordlist()
    secret = brute_force_secret(token, wordlist)
    assert secret is None
