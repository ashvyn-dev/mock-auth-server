
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
    print("DEBUG: Retrieving OAuth1 client registry from config")
    clients = {
        settings.oauth1_consumer_key: {
            "consumer_secret": settings.oauth1_consumer_secret,
            "callback_uris": settings.oauth1_callback_uris,
        }
    }
    print(f"INFO: OAuth1 clients loaded: {list(clients.keys())}")
    return clients

def generate_signature(
    method: str,
    url: str,
    params: Dict[str, str],
    consumer_secret: str,
    token_secret: str = ""
) -> str:
    """Generate HMAC-SHA1 signature for OAuth1 requests"""
    print(f"DEBUG: Generating signature for {method} {url}")
    print(f"DEBUG: Signature parameters count: {len(params)}")

    sorted_params = sorted(params.items())
    print(f"DEBUG: Sorted parameters: {[(k, (str(v)[:20] + '...') if len(str(v)) > 20 else v) for k, v in sorted_params]}")

    param_string = "&".join([f"{k}={urllib.parse.quote(str(v), safe='')}"
                             for k, v in sorted_params])
    print(f"DEBUG: Parameter string created (length: {len(param_string)})")

    base_string = "&".join([
        method.upper(),
        urllib.parse.quote(url, safe=''),
        urllib.parse.quote(param_string, safe='')
    ])
    print(f"DEBUG: Base string for signing created (length: {len(base_string)})")

    signing_key = f"{urllib.parse.quote(consumer_secret, safe='')}&{urllib.parse.quote(token_secret, safe='')}"
    print(f"DEBUG: Signing key prepared (has_token_secret: {bool(token_secret)})")

    signature = hmac.new(
        signing_key.encode('utf-8'),
        base_string.encode('utf-8'),
        hashlib.sha1
    )

    generated_sig = base64.b64encode(signature.digest()).decode('utf-8')
    print(f"DEBUG: HMAC-SHA1 signature generated: {generated_sig[:20]}...")
    print(f"INFO: Signature generated successfully for {method} request")

    return generated_sig

def verify_signature(request: Request, consumer_secret: str, token_secret: str = "") -> bool:
    """Verify OAuth1 signature from request"""
    print(f"DEBUG: Verifying OAuth1 signature for {request.method} {request.url.path}")

    auth_header = request.headers.get("Authorization", "")
    print(f"DEBUG: Authorization header present: {bool(auth_header)}")

    if not auth_header.startswith("OAuth "):
        print("WARN: Authorization header does not start with 'OAuth ' - signature verification failed")
        return False

    oauth_params = {}
    auth_content = auth_header[6:]
    print("DEBUG: Parsing OAuth parameters from auth header")

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    print(f"DEBUG: OAuth parameters extracted: {list(oauth_params.keys())}")

    provided_signature = oauth_params.pop("oauth_signature", "")
    print(f"DEBUG: Provided signature extracted: {provided_signature[:20]}...")

    url = str(request.url).split("?")[0]
    print(f"DEBUG: Base URL for signature verification: {url}")

    expected_signature = generate_signature(
        request.method, url, oauth_params, consumer_secret, token_secret
    )
    print(f"DEBUG: Expected signature generated: {expected_signature[:20]}...")

    signature_valid = hmac.compare_digest(provided_signature, expected_signature)

    if signature_valid:
        print("INFO: ✓ OAuth1 signature verification PASSED")
    else:
        print("ERROR: ✗ OAuth1 signature verification FAILED - signature mismatch")

    return signature_valid

@router.post("/request_token")
async def request_token(request: Request):
    """OAuth1 Step 1: Request temporary credentials"""
    print("="*80)
    print("INFO: OAuth1 Step 1: REQUEST TOKEN endpoint called")
    print(f"INFO: Client IP: {request.client.host if request.client else 'Unknown'}")
    print("="*80)

    auth_header = request.headers.get("Authorization", "")
    print(f"DEBUG: Authorization header present: {bool(auth_header)}")

    if not auth_header.startswith("OAuth "):
        print("ERROR: Missing or malformed OAuth authorization header in request_token")
        raise HTTPException(status_code=401, detail="Missing OAuth authorization header")

    oauth_params = {}
    auth_content = auth_header[6:]

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    print(f"DEBUG: OAuth parameters parsed: {list(oauth_params.keys())}")

    consumer_key = oauth_params.get("oauth_consumer_key")
    callback = oauth_params.get("oauth_callback")

    print(f"INFO: Consumer Key: {consumer_key}")
    print(f"INFO: Callback URI: {callback}")

    clients = get_oauth1_clients()
    if consumer_key not in clients:
        print(f"ERROR: Invalid consumer key: {consumer_key}")
        print(f"ERROR: Valid consumer keys: {list(clients.keys())}")
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    print(f"DEBUG: Consumer key {consumer_key} found in registry")

    client = clients[consumer_key]

    if not verify_signature(request, client["consumer_secret"]):
        print(f"ERROR: Signature verification failed for consumer key: {consumer_key}")
        raise HTTPException(status_code=401, detail="Invalid signature")

    print(f"INFO: Signature verified for consumer key: {consumer_key}")

    request_token = secrets.token_urlsafe(32)
    request_token_secret = secrets.token_urlsafe(32)

    token_data = {
        "token_secret": request_token_secret,
        "consumer_key": consumer_key,
        "callback": callback,
        "authorized": False,
        "verifier": None,
        "username": None,
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + settings.oauth1_request_token_ttl,
    }

    REQUEST_TOKENS[request_token] = token_data

    print(f"INFO: Request token generated: {request_token[:20]}...")
    print(f"INFO: Request token TTL: {settings.oauth1_request_token_ttl} seconds")
    print(f"DEBUG: Token data stored: {token_data}")
    print(f"INFO: Total request tokens in store: {len(REQUEST_TOKENS)}")

    response_body = f"oauth_token={request_token}&oauth_token_secret={request_token_secret}&oauth_callback_confirmed=true"

    print("INFO: ✓ Request token successfully issued")
    print("="*80)

    return Response(content=response_body, media_type="application/x-www-form-urlencoded")

@router.get("/authorize", response_class=HTMLResponse)
async def authorize(oauth_token: str = Query(...)):
    """OAuth1 Step 2: User authorization endpoint"""
    print("="*80)
    print("INFO: OAuth1 Step 2: AUTHORIZE GET endpoint called")
    print(f"INFO: Request token: {oauth_token[:20]}...")
    print("="*80)

    token_data = REQUEST_TOKENS.get(oauth_token)

    if not token_data:
        print(f"ERROR: Request token not found: {oauth_token[:20]}...")
        print(f"DEBUG: Available tokens in store: {len(REQUEST_TOKENS)}")
        raise HTTPException(status_code=400, detail="Invalid or expired request token")

    print("DEBUG: Request token found in store")
    print(f"DEBUG: Token data: {token_data}")

    current_time = int(time.time())
    if current_time > token_data["expires_at"]:
        print(f"WARN: Request token expired - issued_at: {token_data['issued_at']}, expired_at: {token_data['expires_at']}, current: {current_time}")
        del REQUEST_TOKENS[oauth_token]
        print(f"INFO: Expired token removed from store. Remaining tokens: {len(REQUEST_TOKENS)}")
        raise HTTPException(status_code=400, detail="Request token expired")

    print(f"INFO: Request token valid - Consumer: {token_data['consumer_key']}")
    print(f"INFO: Time to expiration: {token_data['expires_at'] - current_time} seconds")

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

    print("INFO: ✓ Authorization form rendered successfully")
    print("="*80)

    return HTMLResponse(content=auth_form)

@router.post("/authorize")
async def authorize_post(
    oauth_token: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    action: str = Form(...),
):
    """Process OAuth1 authorization"""
    print("="*80)
    print("INFO: OAuth1 Step 2: AUTHORIZE POST endpoint called")
    print(f"INFO: Request token: {oauth_token[:20]}...")
    print(f"INFO: Action: {action}")
    print(f"INFO: Username: {username}")
    print("="*80)

    token_data = REQUEST_TOKENS.get(oauth_token)

    if not token_data:
        print(f"ERROR: Request token not found during authorization: {oauth_token[:20]}...")
        raise HTTPException(status_code=400, detail="Invalid request token")

    print(f"DEBUG: Token data retrieved: {token_data}")

    if action == "deny":
        print(f"WARN: User {username} DENIED authorization for consumer: {token_data['consumer_key']}")
        print(f"DEBUG: Request token {oauth_token[:20]}... marked as denied")

        callback = token_data.get("callback", "oob")
        print(f"DEBUG: Callback URI: {callback}")

        if callback == "oob":
            print("INFO: Out-of-band callback - returning denial message to user")
            return HTMLResponse(content="<h2>Authorization Denied</h2>")

        print(f"INFO: Redirecting to callback with error: {callback}")
        return RedirectResponse(url=f"{callback}?error=access_denied", status_code=302)

    print(f"INFO: User {username} authorized application")

    user = settings.mock_users.get(username)
    if not user:
        print(f"ERROR: User not found in mock users: {username}")
        print(f"DEBUG: Available users: {list(settings.mock_users.keys())}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    print(f"DEBUG: User found in registry: {username}")

    if user["password"] != password:
        print(f"ERROR: Password mismatch for user: {username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    print(f"INFO: ✓ Password verified for user: {username}")

    verifier = secrets.token_urlsafe(32)
    token_data["authorized"] = True
    token_data["verifier"] = verifier
    token_data["username"] = username

    print(f"INFO: Verifier generated: {verifier[:20]}...")
    print(f"DEBUG: Updated token data: {token_data}")

    callback = token_data.get("callback", "oob")
    print(f"DEBUG: Callback method: {callback}")

    if callback == "oob":
        print("INFO: Out-of-band flow - returning verifier code to user")
        return HTMLResponse(content=f"""
        <html><body style="font-family: Arial; max-width: 500px; margin: 100px auto; text-align: center;">
            <h2>✅ Authorization Successful</h2>
            <p>Enter this verifier code in your application:</p>
            <h1 style="background: #e7f3ff; padding: 20px; border-radius: 8px; letter-spacing: 2px;">
                {verifier}</h1>
        </body></html>
        """)

    redirect_url = f"{callback}?oauth_token={oauth_token}&oauth_verifier={verifier}"
    print(f"INFO: Redirecting to callback URL: {callback}")
    print(f"DEBUG: Redirect URL: {redirect_url}")
    print("="*80)

    return RedirectResponse(url=redirect_url, status_code=302)

@router.post("/access_token")
async def access_token(request: Request):
    """OAuth1 Step 3: Exchange authorized request token for access token"""
    print("="*80)
    print("INFO: OAuth1 Step 3: ACCESS TOKEN endpoint called")
    print(f"INFO: Client IP: {request.client.host if request.client else 'Unknown'}")
    print("="*80)

    auth_header = request.headers.get("Authorization", "")
    print(f"DEBUG: Authorization header present: {bool(auth_header)}")

    if not auth_header.startswith("OAuth "):
        print("ERROR: Missing or malformed OAuth authorization header in access_token")
        raise HTTPException(status_code=401, detail="Missing OAuth authorization header")

    oauth_params = {}
    auth_content = auth_header[6:]

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    print(f"DEBUG: OAuth parameters extracted: {list(oauth_params.keys())}")

    consumer_key = oauth_params.get("oauth_consumer_key")
    request_token = oauth_params.get("oauth_token")
    verifier = oauth_params.get("oauth_verifier")

    print(f"INFO: Consumer Key: {consumer_key}")
    print(f"INFO: Request Token: {request_token[:20] if request_token else 'None'}...")
    print(f"INFO: Verifier: {verifier[:20] if verifier else 'None'}...")

    clients = get_oauth1_clients()
    if consumer_key not in clients:
        print(f"ERROR: Invalid consumer key: {consumer_key}")
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    print(f"DEBUG: Consumer key {consumer_key} validated")

    client = clients[consumer_key]
    token_data = REQUEST_TOKENS.get(request_token)

    if not token_data:
        print(f"ERROR: Request token not found: {request_token[:20] if request_token else 'None'}...")
        print(f"DEBUG: Available request tokens: {len(REQUEST_TOKENS)}")
        raise HTTPException(status_code=401, detail="Invalid request token or verifier")

    print(f"DEBUG: Request token found - Consumer: {token_data['consumer_key']}, Authorized: {token_data['authorized']}")

    if not token_data["authorized"]:
        print(f"ERROR: Request token not authorized: {request_token[:20]}...")
        raise HTTPException(status_code=401, detail="Invalid request token or verifier")

    print("INFO: ✓ Request token is authorized")

    if token_data["verifier"] != verifier:
        print(f"ERROR: Verifier mismatch - Expected: {token_data['verifier'][:20]}..., Got: {verifier[:20] if verifier else 'None'}...")
        raise HTTPException(status_code=401, detail="Invalid request token or verifier")

    print("INFO: ✓ Verifier matches")

    if not verify_signature(request, client["consumer_secret"], token_data["token_secret"]):
        print("ERROR: Signature verification failed during access_token exchange")
        raise HTTPException(status_code=401, detail="Invalid signature")

    print("INFO: ✓ Signature verification passed")

    access_token_str = secrets.token_urlsafe(32)
    access_token_secret = secrets.token_urlsafe(32)

    access_token_data = {
        "token_secret": access_token_secret,
        "consumer_key": consumer_key,
        "username": token_data["username"],
        "issued_at": int(time.time()),
    }

    ACCESS_TOKENS[access_token_str] = access_token_data

    print(f"INFO: Access token generated: {access_token_str[:20]}...")
    print(f"INFO: Access token associated with user: {token_data['username']}")
    print(f"DEBUG: Access token data stored: {access_token_data}")
    print(f"INFO: Total access tokens in store: {len(ACCESS_TOKENS)}")

    del REQUEST_TOKENS[request_token]
    print(f"INFO: Request token {request_token[:20]}... removed from store")
    print(f"DEBUG: Remaining request tokens: {len(REQUEST_TOKENS)}")

    response_body = f"oauth_token={access_token_str}&oauth_token_secret={access_token_secret}"

    print("INFO: ✓ Access token successfully issued")
    print("="*80)

    return Response(content=response_body, media_type="application/x-www-form-urlencoded")

@router.get("/api/user")
async def protected_resource(request: Request):
    """Example protected resource using OAuth1"""
    print("="*80)
    print("INFO: PROTECTED RESOURCE: /api/user endpoint called")
    print(f"INFO: Client IP: {request.client.host if request.client else 'Unknown'}")
    print("="*80)

    auth_header = request.headers.get("Authorization", "")
    print(f"DEBUG: Authorization header present: {bool(auth_header)}")

    if not auth_header.startswith("OAuth "):
        print("ERROR: Missing or malformed OAuth authorization header in protected resource")
        raise HTTPException(status_code=401, detail="Missing OAuth authorization header")

    oauth_params = {}
    auth_content = auth_header[6:]

    for param in auth_content.split(", "):
        if "=" in param:
            key, value = param.split("=", 1)
            oauth_params[key] = urllib.parse.unquote(value.strip('"'))

    print(f"DEBUG: OAuth parameters extracted: {list(oauth_params.keys())}")

    consumer_key = oauth_params.get("oauth_consumer_key")
    access_token = oauth_params.get("oauth_token")

    print(f"INFO: Consumer Key: {consumer_key}")
    print(f"INFO: Access Token: {access_token[:20] if access_token else 'None'}...")

    clients = get_oauth1_clients()
    if consumer_key not in clients:
        print(f"ERROR: Invalid consumer key: {consumer_key}")
        raise HTTPException(status_code=401, detail="Invalid consumer key")

    print(f"DEBUG: Consumer key {consumer_key} validated")

    client = clients[consumer_key]
    token_data = ACCESS_TOKENS.get(access_token)

    if not token_data:
        print(f"ERROR: Access token not found: {access_token[:20] if access_token else 'None'}...")
        print(f"DEBUG: Available access tokens: {len(ACCESS_TOKENS)}")
        raise HTTPException(status_code=401, detail="Invalid access token")

    print(f"INFO: ✓ Access token valid - Consumer: {token_data['consumer_key']}, User: {token_data['username']}")

    if not verify_signature(request, client["consumer_secret"], token_data["token_secret"]):
        print("ERROR: Signature verification failed for protected resource access")
        raise HTTPException(status_code=401, detail="Invalid signature")

    print("INFO: ✓ Signature verification passed for protected resource")

    username = token_data["username"]
    user = settings.mock_users.get(username, {})

    print(f"DEBUG: User data retrieved: {username}")

    response_data = {
        "email": username,
        "name": user.get("name", "Unknown"),
        "oauth_version": "1.0a",
        "authenticated": True,
    }

    print(f"INFO: ✓ Protected resource accessed by: {username}")
    print(f"DEBUG: Response data: {response_data}")
    print("="*80)

    return response_data

