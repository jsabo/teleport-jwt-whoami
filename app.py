"""jwt-whoami: show and verify the JWT Teleport adds to every request it forwards.

Teleport's application service signs a short-lived JSON Web Token (JWT) for each
request it proxies to an HTTP application and sends it in the
``Teleport-Jwt-Assertion`` header. This app reads that header, verifies the token
against the cluster's published signing keys (JWKS) and renders every claim, every
check and every other header the request arrived with.
"""

import base64
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import jwt
from flask import Flask, jsonify, make_response, render_template, request
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError, PyJWTError

HEADER = "Teleport-Jwt-Assertion"
ALGORITHMS = ["RS256", "ES256"]  # RSA or ECDSA signer, whichever the cluster's JWT CA uses
LEEWAY_SECONDS = 30
TOKEN_PREVIEW = 24


def host_only(value):
    """Return the host part of a proxy address, dropping any scheme and port."""
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc
    return value.rsplit(":", 1)[0] if ":" in value and not value.endswith("]") else value


def load_config():
    proxy = os.environ.get("TELEPORT_PROXY", "").strip()
    if not proxy:
        raise SystemExit(
            "TELEPORT_PROXY is required: the proxy address of the Teleport cluster "
            "whose tokens this app should trust, for example example.teleport.sh"
        )
    proxy_host = host_only(proxy)
    return {
        "proxy": proxy_host,
        "jwks_url": os.environ.get("JWKS_URL", "").strip() or f"https://{proxy_host}/.well-known/jwks.json",
        "expected_issuer": os.environ.get("EXPECTED_ISSUER", "").strip() or proxy_host,
        "expected_audience": os.environ.get("EXPECTED_AUDIENCE", "").strip() or None,
    }


CONFIG = load_config()
app = Flask(__name__)
jwks_client = PyJWKClient(CONFIG["jwks_url"], cache_keys=True, lifespan=300)


def find_token(req):
    """Return (token, where it came from). Teleport's own header wins; a Bearer token
    is accepted too so the app also works behind an ``Authorization: Bearer
    {{internal.jwt}}`` rewrite rule."""
    value = req.headers.get(HEADER)
    if value:
        return value.strip(), HEADER
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip(), "Authorization: Bearer"
    return None, None


def decode_segment(segment):
    """Decode one base64url segment of a compact JWT without verifying anything."""
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def signing_key_for(token, header):
    """Pick the JWKS key named by the token's ``kid``; without a ``kid`` try every key."""
    if header.get("kid"):
        return jwks_client.get_signing_key_from_jwt(token)
    keys = jwks_client.get_signing_keys()
    for key in keys:
        try:
            jwt.decode(token, key.key, algorithms=ALGORITHMS, options={"verify_signature": True, "verify_exp": False})
            return key
        except PyJWTError:
            continue
    raise PyJWKClientError("no key in the JWKS verifies this token")


def when(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def inspect(req):
    """Build the whole page as data. ``/whoami.json`` returns it verbatim."""
    now = int(time.time())
    checks = []
    report = {
        "generated_at": when(now),
        "verified": False,
        "verdict": "",
        "checks": checks,
        "token": None,
        "identity": None,
        "request_headers": request_headers(req),
        "config": {
            "jwks_url": CONFIG["jwks_url"],
            "expected_issuer": CONFIG["expected_issuer"],
            "expected_audience": CONFIG["expected_audience"],
            "algorithms": ALGORITHMS,
            "leeway_seconds": LEEWAY_SECONDS,
        },
    }

    def check(name, ok, detail):
        checks.append({"name": name, "ok": ok, "detail": detail})
        return ok

    token, source = find_token(req)
    if not token:
        check("header present", False, f"no {HEADER} header. This request did not come through Teleport.")
        report["verdict"] = "Refused: no token. Only requests forwarded by the Teleport application service carry one."
        return report
    check("header present", True, f"{source}, {len(token)} characters")

    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("expected three dot-separated segments")
        header, claims = decode_segment(parts[0]), decode_segment(parts[1])
    except (ValueError, json.JSONDecodeError) as err:
        check("token parses", False, f"not a compact JWT: {err}")
        report["verdict"] = "Refused: the header does not hold a JWT."
        return report

    report["token"] = {
        "raw": token,
        "preview": f"{token[:TOKEN_PREVIEW]}…{token[-TOKEN_PREVIEW:]}",
        "header": header,
        "claims": claims,
    }
    report["identity"] = {
        "username": claims.get("username") or claims.get("sub"),
        "roles": claims.get("roles") or [],
        "traits": claims.get("traits") or {},
    }

    signed = False
    try:
        key = signing_key_for(token, header)
        jwt.decode(
            token,
            key.key,
            algorithms=ALGORITHMS,
            options={"verify_signature": True, "verify_exp": False, "verify_nbf": False,
                     "verify_iss": False, "verify_aud": False},
        )
        signed = check(
            "signature",
            True,
            f"{header.get('alg')} with key id {header.get('kid', '(none)')} from {CONFIG['jwks_url']}",
        )
    except PyJWKClientError as err:
        check("signature", False, f"no matching key in {CONFIG['jwks_url']}: {err}")
    except PyJWTError as err:
        check("signature", False, f"{header.get('alg')} signature does not verify: {err}")

    issuer_ok = check(
        "issuer",
        claims.get("iss") == CONFIG["expected_issuer"],
        f"iss = {claims.get('iss')!r}, expected {CONFIG['expected_issuer']!r}",
    )

    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience] if audience else []
    if CONFIG["expected_audience"]:
        audience_ok = check(
            "audience",
            CONFIG["expected_audience"] in audiences,
            f"aud = {audiences}, expected to contain {CONFIG['expected_audience']!r}",
        )
    else:
        audience_ok = check("audience", True, f"aud = {audiences}, not checked (EXPECTED_AUDIENCE unset)")

    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        remaining = int(exp) - now
        exp_ok = check(
            "not expired",
            remaining + LEEWAY_SECONDS > 0,
            f"exp = {when(exp)}, {abs(remaining)} s {'left' if remaining >= 0 else 'ago'}",
        )
    else:
        exp_ok = check("not expired", False, "no exp claim")

    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)):
        nbf_ok = check("not before", now + LEEWAY_SECONDS >= nbf, f"nbf = {when(nbf)}")
    else:
        nbf_ok = check("not before", True, "no nbf claim")

    report["verified"] = signed and issuer_ok and audience_ok and exp_ok and nbf_ok
    if report["verified"]:
        report["verdict"] = (
            f"Verified: {CONFIG['expected_issuer']} signed this token for "
            f"{report['identity']['username']} and it is valid right now."
        )
    else:
        failed = ", ".join(c["name"] for c in checks if not c["ok"])
        report["verdict"] = f"Refused: {failed} failed. The claims below are shown as sent, unverified."
    return report


def request_headers(req):
    """Every header the request arrived with. The token itself is shortened so the
    table stays readable; the full value is in the token section."""
    rows = []
    for name, value in sorted(req.headers.items()):
        if name.lower() == HEADER.lower() or (name.lower() == "authorization" and value.lower().startswith("bearer ")):
            value = value[:TOKEN_PREVIEW] + "…"
        rows.append({"name": name, "value": value})
    return rows


@app.get("/")
def index():
    report = inspect(request)
    status = 200 if report["verified"] else 401
    body = render_template("index.html", r=report, header_name=HEADER, pretty=lambda v: json.dumps(v, indent=2, sort_keys=True))
    return make_response(body, status)


@app.get("/whoami.json")
def whoami_json():
    report = inspect(request)
    if report["token"]:
        report["token"] = {k: v for k, v in report["token"].items() if k != "raw"}
    return make_response(jsonify(report), 200 if report["verified"] else 401)


@app.get("/healthz")
def healthz():
    return "ok\n", 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
