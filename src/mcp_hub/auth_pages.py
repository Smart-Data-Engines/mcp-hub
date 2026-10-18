"""Self-contained, accessible sign-in pages; no external assets or browser scripts."""

from __future__ import annotations

import html
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse

_STYLE = """
:root{font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
color:#243631;background:#f5f7f6;font-synthesis:none}*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:32px 20px}
main{width:100%;max-width:560px;background:white;border:1px solid #e1e8e4;
border-radius:18px;padding:36px;box-shadow:0 12px 40px #173d3608}
.brand{display:flex;align-items:center;gap:10px;color:#173d36;font-size:18px;
font-weight:650;letter-spacing:.3px;margin-bottom:32px}
.mark{display:grid;place-items:center;background:#173d36;color:white;width:34px;
height:34px;border-radius:9px;font-size:23px}
.eyebrow{color:#596d64;font-size:12px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase}
h1{color:#173d36;font-size:28px;font-weight:650;letter-spacing:-.8px;line-height:1.2;
margin:12px 0 16px;overflow-wrap:anywhere}h2{font-size:14px;color:#173d36;margin:0 0 8px}
p{color:#596d64;font-size:14px;line-height:1.7;margin:0 0 20px}
.account,.permissions{background:#f5f7f6;border:1px solid #e1e8e4;border-radius:10px;padding:16px;margin:20px 0}
.account small{display:block;font-size:12px;color:#596d64;margin-bottom:6px}
.account strong{display:block;font-size:14px;font-weight:600;overflow-wrap:anywhere}
.permissions p{margin:0}.destination{font-size:12px;overflow-wrap:anywhere}
.actions{display:flex;gap:12px;margin:28px 0 16px}
button,.button{display:inline-flex;align-items:center;justify-content:center;min-height:44px;
padding:11px 18px;border:1px solid #d6e0da;border-radius:8px;font:inherit;
font-size:14px;font-weight:600;line-height:1.4;color:#173d36;background:white;cursor:pointer;text-decoration:none}
button:hover,.button:hover{background:#edf4ef;border-color:#aec7b7}
.primary{color:white;background:#147d64;border-color:#147d64;flex:1}
.primary:hover{background:#10644f;border-color:#10644f}
button:focus-visible,a:focus-visible{outline:3px solid #147d64;outline-offset:4px}
.note{font-size:12px;margin:0}
@media(max-width:440px){body{padding:16px}main{padding:24px}.actions{flex-direction:column}
h1{font-size:25px}.brand{margin-bottom:28px}}
"""


def _page(title: str, content: str, *, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)} · MCP Hub</title><style>{_STYLE}</style></head>"
        '<body><main><div class="brand"><span class="mark" aria-hidden="true">◈</span>'
        f"MCP Hub</div>{content}</main></body></html>",
        status_code=status_code,
    )


def consent_page(client_name: str, username: str, redirect_uri: str, consent: str) -> HTMLResponse:
    destination = urlsplit(redirect_uri)
    origin = html.escape(f"{destination.scheme}://{destination.netloc}")
    return _page(
        "Connect an application",
        '<div class="eyebrow">Application connection</div>'
        f"<h1>Connect {html.escape(client_name)}?</h1>"
        "<p>This application is requesting access to your MCP Hub tools.</p>"
        '<div class="account"><small>Signed in as</small>'
        f"<strong>{html.escape(username)}</strong></div>"
        '<section class="permissions" aria-labelledby="permissions-heading">'
        '<h2 id="permissions-heading">Use your available tools</h2>'
        "<p>The application can use the tools available to your account, including actions "
        "that change data. Your existing workspace permissions apply to every request.</p></section>"
        f'<p class="destination">After connecting, you’ll return to <strong>{origin}</strong>.</p>'
        '<form method="post" action="/oauth/consent">'
        f'<input type="hidden" name="consent" value="{html.escape(consent, quote=True)}">'
        '<div class="actions"><button class="primary" name="decision" value="allow">Allow access</button>'
        '<button name="decision" value="deny">Cancel</button></div></form>'
        '<p class="note">Only continue if you started this connection.</p>',
    )


def expired_consent_page() -> HTMLResponse:
    return _page(
        "Connection expired",
        '<div class="eyebrow">Sign-in</div><h1>This connection has expired</h1>'
        "<p>Start the connection again in the application you’re using. "
        "If you want to open your workspace, continue to the Hub console.</p>"
        '<div class="actions"><a class="button primary" href="/admin/">Open MCP Hub</a></div>',
        status_code=400,
    )
