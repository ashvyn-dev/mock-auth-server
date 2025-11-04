#!/usr/bin/env python3

from fastapi import APIRouter, HTTPException, Request, Query, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
import hmac
import hashlib
import base64
import urllib.parse
import secrets
import time
from typing import Dict
from .config import settings

router = APIRouter(prefix="/oauth1", tags=["OAuth1"])

# OAuth1 In-memory stores
REQUEST_TOKENS = {}
ACCESS_TOKENS = {}

def get_oauth1_clients():
    """Return OAuth1 client registry from config"""
    return {
        settings.oauth1_consumer_key: {
            "consumer_secret": settings.oauth1_consumer_secret,
            "callback_uris": settings.oauth1_callback_uris,
        }
    }

def generate_signature(
    method: str,
    url: str,
    params: Dict[str, str],
    consumer_secret: str,
    token_secret: str = ""
) -> str:
    """Generate HMAC-SHA1 signature for OAuth1 requests"""
    sorted_params = sorted(params.items())
    param_string = "&".join([f"{k}={urllib.parse.quote(str(v), safe='')}"
                             for k, v in sorted_params])

    base_string = "&".join([
        method.upper(),
        urllib.parse.quote(url, safe=''),
        urllib.parse.quote(param_string, safe='')
    ])

    signing_key = f"{urllib.parse.quote(consumer_secret, safe='')}&{urllib.parse.quote(token_secret, safe='')}"

    signature = hmac.new(
        signing_key.encode('utf-8'),
        base_string.encode('utf-8'),
        hashlib.sha1
    )

    return base64.b64encode(signature.digest()).decode('utf-8')

def verify_signature(request: Request, consumer_secret: str, token_secret: str = "") -> bool:
    """Verify OAuth1 signature from request"""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("OAuth "):
        return False

    oauth_params = {}
    auth_content = auth_header[6:]

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    provided_signature = oauth_params.pop("oauth_signature", "")
    url = str(request.url).split("?")[0]

    expected_signature = generate_signature(
        request.method, url, oauth_params, consumer_secret, token_secret
    )

    return hmac.compare_digest(provided_signature, expected_signature)

@router.post("/request_token")
async def request_token(request: Request):
    """OAuth1 Step 1: Request temporary credentials"""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("OAuth "):
        raise HTTPException(status_code=401, detail="Missing OAuth authorization header")

    oauth_params = {}
    auth_content = auth_header[6:]

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    consumer_key = oauth_params.get("oauth_consumer_key")
    callback = oauth_params.get("oauth_callback")

    clients = get_oauth1_clients()
    if consumer_key not in clients:
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    client = clients[consumer_key]

    if not verify_signature(request, client["consumer_secret"]):
        raise HTTPException(status_code=401, detail="Invalid signature")

    request_token = secrets.token_urlsafe(32)
    request_token_secret = secrets.token_urlsafe(32)

    REQUEST_TOKENS[request_token] = {
        "token_secret": request_token_secret,
        "consumer_key": consumer_key,
        "callback": callback,
        "authorized": False,
        "verifier": None,
        "username": None,
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + settings.oauth1_request_token_ttl,
    }

    response_body = f"oauth_token={request_token}&oauth_token_secret={request_token_secret}&oauth_callback_confirmed=true"
    return Response(content=response_body, media_type="application/x-www-form-urlencoded")

@router.get("/authorize", response_class=HTMLResponse)
async def authorize(oauth_token: str = Query(...)):
    """OAuth1 Step 2: User authorization endpoint"""
    token_data = REQUEST_TOKENS.get(oauth_token)

    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid or expired request token")

    if int(time.time()) > token_data["expires_at"]:
        del REQUEST_TOKENS[oauth_token]
        raise HTTPException(status_code=400, detail="Request token expired")

    auth_form = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth1 Authorization</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto;
                    padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: #f9f9f9; }}
            h2 {{ color: #333; }}
            input, button {{ width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }}
            button {{ background: #0066cc; color: white; border: none; border-radius: 4px;
                      cursor: pointer; font-size: 16px; }}
            button:hover {{ background: #0052a3; }}
            .deny {{ background: #cc0000; }}
            .deny:hover {{ background: #a30000; }}
            .info {{ background: #e7f3ff; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <h2>🔐 OAuth1 Authorization</h2>
        <div class="info">
            <strong>Consumer:</strong> {token_data['consumer_key']}<br>
            <strong>Token:</strong> {oauth_token[:20]}...
        </div>
        <form method="post" action="/oauth1/authorize">
            <input type="hidden" name="oauth_token" value="{oauth_token}">
            <label>Email:</label>
            <input type="email" name="username" value="user@example.com" required>
            <label>Password:</label>
            <input type="password" name="password" value="password123" required>
            <button type="submit" name="action" value="authorize">Authorize Application</button>
            <button type="submit" name="action" value="deny" class="deny">Deny Access</button>
        </form>
        <p style="font-size: 12px; color: #666;">Test: user@example.com / password123</p>
    </body>
    </html>
    """
    return HTMLResponse(content=auth_form)

@router.post("/authorize")
async def authorize_post(
    oauth_token: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    action: str = Form(...),
):
    """Process OAuth1 authorization"""
    token_data = REQUEST_TOKENS.get(oauth_token)

    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid request token")

    if action == "deny":
        callback = token_data.get("callback", "oob")
        if callback == "oob":
            return HTMLResponse(content="<h2>Authorization Denied</h2>")
        return RedirectResponse(url=f"{callback}?error=access_denied", status_code=302)

    user = settings.mock_users.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    verifier = secrets.token_urlsafe(32)
    token_data["authorized"] = True
    token_data["verifier"] = verifier
    token_data["username"] = username

    callback = token_data.get("callback", "oob")

    if callback == "oob":
        return HTMLResponse(content=f"""
        <html><body style="font-family: Arial; max-width: 500px; margin: 100px auto; text-align: center;">
            <h2>✅ Authorization Successful</h2>
            <p>Enter this verifier code in your application:</p>
            <h1 style="background: #e7f3ff; padding: 20px; border-radius: 8px; letter-spacing: 2px;">
                {verifier}</h1>
        </body></html>
        """)

    redirect_url = f"{callback}?oauth_token={oauth_token}&oauth_verifier={verifier}"
    return RedirectResponse(url=redirect_url, status_code=302)

@router.post("/access_token")
async def access_token(request: Request):
    """OAuth1 Step 3: Exchange authorized request token for access token"""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("OAuth "):
        raise HTTPException(status_code=401, detail="Missing OAuth authorization header")

    oauth_params = {}
    auth_content = auth_header[6:]

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    consumer_key = oauth_params.get("oauth_consumer_key")
    request_token = oauth_params.get("oauth_token")
    verifier = oauth_params.get("oauth_verifier")

    clients = get_oauth1_clients()
    if consumer_key not in clients:
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    client = clients[consumer_key]
    token_data = REQUEST_TOKENS.get(request_token)

    if not token_data or not token_data["authorized"] or token_data["verifier"] != verifier:
        raise HTTPException(status_code=401, detail="Invalid request token or verifier")

    if not verify_signature(request, client["consumer_secret"], token_data["token_secret"]):
        raise HTTPException(status_code=401, detail="Invalid signature")

    access_token_str = secrets.token_urlsafe(32)
    access_token_secret = secrets.token_urlsafe(32)

    ACCESS_TOKENS[access_token_str] = {
        "token_secret": access_token_secret,
        "consumer_key": consumer_key,
        "username": token_data["username"],
        "issued_at": int(time.time()),
    }

    del REQUEST_TOKENS[request_token]

    response_body = f"oauth_token={access_token_str}&oauth_token_secret={access_token_secret}"
    return Response(content=response_body, media_type="application/x-www-form-urlencoded")

@router.get("/api/user")
async def protected_resource(request: Request):
    """Example protected resource using OAuth1"""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("OAuth "):
        raise HTTPException(status_code=401, detail="Missing OAuth authorization header")

    oauth_params = {}
    auth_content = auth_header[6:]

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    consumer_key = oauth_params.get("oauth_consumer_key")
    access_token = oauth_params.get("oauth_token")

    clients = get_oauth1_clients()
    if consumer_key not in clients:
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    client = clients[consumer_key]
    token_data = ACCESS_TOKENS.get(access_token)

    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid access token")

    if not verify_signature(request, client["consumer_secret"], token_data["token_secret"]):
        raise HTTPException(status_code=401, detail="Invalid signature")

    username = token_data["username"]
    user = settings.mock_users.get(username, {})

    return {
        "email": username,
        "name": user.get("name", "Unknown"),
        "oauth_version": "1.0a",
        "authenticated": True,
    }
