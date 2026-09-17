# JWT Vulnerability Playground

**A DEFENSIVE / EDUCATIONAL security-training tool** in the spirit of
[OWASP WebGoat](https://owasp.org/www-project-webgoat/) and
[DVWA](https://github.com/digininja/DVWA). It deliberately implements a
handful of classic JWT authentication vulnerabilities in an isolated,
localhost-only Flask app, **alongside the correct/fixed version of each**,
so a learner can see the vulnerable behavior and the proper mitigation
side by side. Every vulnerability ships with a scripted exploit that
proves the attack succeeds against the vulnerable endpoint and fails
against the fixed one.

> **FOR LOCAL EDUCATIONAL USE ONLY.**
> This is **not production code** and must **never be deployed publicly
> reachable**. It contains intentionally broken authentication logic,
> hardcoded/weak secrets, and no rate limiting, logging, or hardening of
> any kind. Run it only on `127.0.0.1` on a machine you control, for the
> purpose of learning how these vulnerabilities work and how to fix them.

## Why a hand-rolled JWT implementation?

[`jwt_toy.py`](jwt_toy.py) implements JWT encode/decode from scratch
(header/payload framing, base64url, HMAC-SHA256 and RSA signature
verification, expiry checking) instead of wrapping a hardened third-party
library. A modern, well-configured JWT library would silently prevent
most of these bugs by default -- which is exactly why real-world
vulnerabilities like these come from *misusing* flexible low-level APIs,
missing configuration, or rolling your own logic. This project makes that
misuse explicit and inspectable in plain Python.

Only the underlying crypto primitives are reused: `hmac`/`hashlib` for
HMAC-SHA256, and the `cryptography` package for RSA sign/verify. All JWT
*protocol* logic -- which algorithm to trust, whether to check the
signature, whether to check expiry -- is implemented here and is exactly
what differs between each vulnerable/fixed pair.

## The four vulnerabilities

Each scenario exposes a **vulnerable** pair of routes and a **fixed** pair
of routes that share the same login flow, so you can compare behavior
directly.

### 1. `alg=none` acceptance

| | Route | Behavior |
|---|---|---|
| Vulnerable | `POST /vuln/none/login`, `GET /vuln/none/whoami` | Accepts a token whose header is `{"alg": "none"}` with **no signature at all**, trusting the payload blindly. |
| Fixed | `POST /fixed/none/login`, `GET /fixed/none/whoami` | Explicitly whitelists `allowed_algs=["HS256"]` and never allows `"none"`, no matter what. |

**Exploit:** [`exploits/exploit_none.py`](exploits/exploit_none.py) forges
`{"alg": "none"}` with `admin: true` and no signature segment, then shows
it is accepted by `/vuln/none/whoami` and rejected by `/fixed/none/whoami`.

```bash
python exploits/exploit_none.py
```

### 2. Weak / guessable HMAC secret

| | Route | Behavior |
|---|---|---|
| Vulnerable | `POST /vuln/weak-secret/login`, `GET /vuln/weak-secret/whoami` | Signs tokens with the string `"secret"`. |
| Fixed | `POST /fixed/weak-secret/login`, `GET /fixed/weak-secret/whoami` | Signs tokens with a 256-bit random secret generated at process start. |

**Exploit:** [`exploits/exploit_weak_secret.py`](exploits/exploit_weak_secret.py)
captures a real token, brute-forces the signing secret against the tiny
[`exploits/wordlist.txt`](exploits/wordlist.txt), forges a new `admin: true`
token with the recovered secret, and authenticates as admin against the
vulnerable endpoint. It then repeats the brute-force attempt against a
token from the fixed endpoint and shows the strong secret is not
recoverable from the same wordlist.

```bash
python exploits/exploit_weak_secret.py
```

### 3. Algorithm confusion (RS256 -> HS256)

| | Route | Behavior |
|---|---|---|
| Vulnerable | `POST /vuln/alg-confusion/login`, `GET /vuln/alg-confusion/public-key`, `GET /vuln/alg-confusion/whoami` | Normally issues/verifies RS256 tokens, but hands the **same key bytes** to the verifier regardless of what algorithm the attacker's header claims, and accepts both `RS256` and `HS256`. |
| Fixed | `POST /fixed/alg-confusion/login`, `GET /fixed/alg-confusion/whoami` | Pins `allowed_algs=["RS256"]` server-side, independent of the attacker's header, so an `HS256` header is rejected before the key is ever touched. |

**Exploit:** [`exploits/exploit_alg_confusion.py`](exploits/exploit_alg_confusion.py)
fetches the server's RSA public key (public keys are meant to be public --
that's the point), forges a token with header `{"alg": "HS256"}` and
HMAC-signs it **using the public key's PEM bytes as the HMAC secret**,
then shows it is accepted by the vulnerable endpoint and rejected by the
fixed one.

```bash
python exploits/exploit_alg_confusion.py
```

### 4. Missing signature verification / missing expiry check

| | Route | Behavior |
|---|---|---|
| Vulnerable | `POST /vuln/no-verify/login`, `GET /vuln/no-verify/whoami` | Decodes the token's header/payload but never checks the signature and never checks `exp`. |
| Fixed | `POST /fixed/no-verify/login`, `GET /fixed/no-verify/whoami` | Verifies both the signature and the expiry claim before trusting anything. |

**Exploit:** [`exploits/exploit_no_verify.py`](exploits/exploit_no_verify.py)
hand-crafts a token with a garbage signature (signed by nobody) and an
`exp` one hour in the past, claiming `admin: true`, then shows it is
accepted by the vulnerable endpoint and rejected by the fixed one.

```bash
python exploits/exploit_no_verify.py
```

## Running the app

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

The server binds to `127.0.0.1:5000` only. Visit `http://127.0.0.1:5000/`
for a JSON index of every scenario and its routes.

Every exploit script above also works completely standalone -- each one
spins up the Flask app in-process via `app.test_client()`, so you do not
need a server running in another terminal to use them.

## Running the tests

```bash
pip install -r requirements.txt
pytest -v
```

The test suite (`tests/`) uses Flask's test client to assert, for each
vulnerability, that the forged/malicious token is **accepted** by the
vulnerable endpoint and **rejected** by the fixed endpoint -- the same
properties the exploit scripts demonstrate interactively.

Continuous integration runs the same suite on every push/PR against
Python 3.11 and 3.12 (see [`.github/workflows/tests.yml`](.github/workflows/tests.yml)).

## Project layout

```
app.py                      Flask app factory + route registration
jwt_toy.py                  hand-rolled JWT encode/decode (the "engine")
keys.py                     demo key material (weak secret, strong secret, RSA keypair)
routes/
  none_alg.py                vuln #1: alg=none
  weak_secret.py             vuln #2: weak HMAC secret
  alg_confusion.py           vuln #3: RS256/HS256 algorithm confusion
  no_verify.py                vuln #4: missing signature/expiry verification
exploits/
  exploit_none.py            PoC for vuln #1
  exploit_weak_secret.py     PoC for vuln #2
  exploit_alg_confusion.py   PoC for vuln #3
  exploit_no_verify.py       PoC for vuln #4
  wordlist.txt               tiny brute-force wordlist
tests/                       pytest suite (Flask test client)
.github/workflows/tests.yml  CI: pytest on Python 3.11 & 3.12
```

## License

MIT -- see [LICENSE](LICENSE).
