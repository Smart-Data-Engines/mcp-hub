"""DEVELOPMENT ONLY: a local OIDC test provider with explicit demo identities.

This deliberately does not authenticate users. Never expose it outside localhost.
The production gateway delegates identity to the configured company OIDC provider.
"""

import base64
import hashlib
import hmac
import html
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import jwt
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

issuer = os.environ.get("DEMO_ISSUER", "http://localhost:8100")
client_id = os.environ.get("DEMO_CLIENT_ID", "mcp-hub-demo")
client_secret = os.environ["DEMO_CLIENT_SECRET"]
redirect_uri = os.environ.get("DEMO_REDIRECT_URI", "http://localhost:8000/oauth/oidc/callback")
key_path = Path(os.environ.get("DEMO_KEY_PATH", "/tmp/mcp-hub-demo-key.pem"))
if not key_path.exists():
    key_path.parent.mkdir(parents=True, exist_ok=True)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
private = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
public = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
public.update(kid="local-demo", use="sig", alg="RS256")
codes: dict[str, dict] = {}


async def discovery(request: Request):
    return JSONResponse({"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "response_types_supported": ["code"], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"], "code_challenge_methods_supported": ["S256"]})


async def jwks(request: Request):
    return JSONResponse({"keys": [public]})


async def authorize(request: Request):
    params = dict(request.query_params)
    if params.get("client_id") != client_id or params.get("redirect_uri") != redirect_uri or params.get("code_challenge_method") != "S256":
        return JSONResponse({"error": "invalid_request"}, 400)
    subject = params.pop("demo_subject", "")
    if subject not in {"admin", "developer", "analyst"}:
        hidden = "".join(f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">' for key, value in params.items())
        return HTMLResponse(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Local demonstration sign-in</title><body style="font-family:system-ui;max-width:650px;margin:70px auto;padding:20px"><p>LOCAL DEVELOPMENT · NO AUTHENTICATION</p><h1>Choose a demonstration identity</h1><p>This test provider is for your laptop only. A company deployment uses its configured identity provider.</p><form method="get" action="/authorize">{hidden}<button name="demo_subject" value="admin">Admin</button> <button name="demo_subject" value="developer">Developer</button> <button name="demo_subject" value="analyst">Analyst</button></form></body></html>''')
    code = secrets.token_urlsafe(32)
    codes[code] = {**params, "subject": subject, "expires": time.time() + 60}
    return RedirectResponse(redirect_uri + "?" + urlencode({"code": code, "state": params["state"]}), 302)


async def token(request: Request):
    params = dict(await request.form())
    if not hmac.compare_digest(str(params.get("client_secret", "")), client_secret) or params.get("client_id") != client_id:
        return JSONResponse({"error": "invalid_client"}, 401)
    code = codes.pop(str(params.get("code", "")), None)
    verifier = str(params.get("code_verifier", ""))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if not code or code["expires"] < time.time() or not hmac.compare_digest(challenge, code["code_challenge"]) or params.get("redirect_uri") != redirect_uri:
        return JSONResponse({"error": "invalid_grant"}, 400)
    now = int(time.time())
    identity = {"iss": issuer, "sub": code["subject"], "aud": client_id, "iat": now, "exp": now + 300, "nonce": code["nonce"], "preferred_username": code["subject"] + "@example.test", "email": code["subject"] + "@example.test", "email_verified": True}
    return JSONResponse({"access_token": secrets.token_urlsafe(32), "token_type": "Bearer", "expires_in": 300, "id_token": jwt.encode(identity, private, algorithm="RS256", headers={"kid": "local-demo"})})


app = Starlette(routes=[Route("/.well-known/openid-configuration", discovery), Route("/jwks", jwks), Route("/authorize", authorize), Route("/token", token, methods=["POST"])])
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8100, access_log=False)
