"""
Key material used by the demo routes.

Everything here is generated at process start and lives only in memory --
there is no persistence, no key rotation, nothing production-grade. This
is intentional: this project's entire purpose is to demonstrate JWT
*protocol* vulnerabilities, not key management.
"""
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Weak vs. strong HMAC secret (used by the weak-secret vulnerability) ---
# "secret" is one of the most common weak JWT secrets found in the wild;
# it is deliberately near the top of exploits/wordlist.txt.
WEAK_SECRET = "secret"
STRONG_SECRET = secrets.token_hex(32)  # 256 bits, generated fresh each run

# --- Shared HMAC secret for the alg=none and missing-verification demos ---
DEMO_SECRET = secrets.token_hex(32)

# --- RSA keypair for the RS256/HS256 algorithm-confusion demo ---
_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_PRIVATE_KEY = _rsa_private_key
RSA_PUBLIC_KEY = _rsa_private_key.public_key()
RSA_PUBLIC_PEM = RSA_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
