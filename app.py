"""
JWT Vulnerability Playground -- a Flask app that pairs classic JWT
authentication vulnerabilities with their correctly-mitigated fix,
side by side, for local security education only.

See README.md before running this anywhere. Do NOT deploy this
publicly reachable.
"""
from flask import Flask, jsonify

from routes.alg_confusion import bp as alg_confusion_bp
from routes.no_verify import bp as no_verify_bp
from routes.none_alg import bp as none_alg_bp
from routes.weak_secret import bp as weak_secret_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(none_alg_bp)
    app.register_blueprint(weak_secret_bp)
    app.register_blueprint(alg_confusion_bp)
    app.register_blueprint(no_verify_bp)

    @app.get("/")
    def index():
        return jsonify(
            message=(
                "JWT Vulnerability Playground -- for local educational use only. "
                "Do not deploy this publicly reachable."
            ),
            scenarios=[
                {
                    "vulnerability": "alg=none acceptance",
                    "vuln": ["/vuln/none/login", "/vuln/none/whoami"],
                    "fixed": ["/fixed/none/login", "/fixed/none/whoami"],
                    "exploit_script": "exploits/exploit_none.py",
                },
                {
                    "vulnerability": "weak/guessable HMAC secret",
                    "vuln": ["/vuln/weak-secret/login", "/vuln/weak-secret/whoami"],
                    "fixed": ["/fixed/weak-secret/login", "/fixed/weak-secret/whoami"],
                    "exploit_script": "exploits/exploit_weak_secret.py",
                },
                {
                    "vulnerability": "RS256/HS256 algorithm confusion",
                    "vuln": [
                        "/vuln/alg-confusion/login",
                        "/vuln/alg-confusion/public-key",
                        "/vuln/alg-confusion/whoami",
                    ],
                    "fixed": ["/fixed/alg-confusion/login", "/fixed/alg-confusion/whoami"],
                    "exploit_script": "exploits/exploit_alg_confusion.py",
                },
                {
                    "vulnerability": "missing signature/expiry verification",
                    "vuln": ["/vuln/no-verify/login", "/vuln/no-verify/whoami"],
                    "fixed": ["/fixed/no-verify/login", "/fixed/no-verify/whoami"],
                    "exploit_script": "exploits/exploit_no_verify.py",
                },
            ],
        )

    return app


app = create_app()

if __name__ == "__main__":
    # localhost only, by design -- see README.md.
    app.run(host="127.0.0.1", port=5000, debug=False)
