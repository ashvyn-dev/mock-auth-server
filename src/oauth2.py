
#!/usr/bin/env python3

from fastapi import APIRouter, HTTPException, Query, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from typing import Optional
import secrets
import time
import jwt
import urllib.parse
import json
from .config import settings

router = APIRouter(tags=["OAuth2"])

# OAuth2 In-memory stores
AUTHORIZATION_CODES = {}
REFRESH_TOKENS = {}

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    scope: str

def get_oauth2_clients():
    """Return OAuth2 client registry from config"""
    return {
        settings.oauth2_client_id: {
            "client_secret": settings.oauth2_client_secret,
            "redirect_uris": settings.oauth2_redirect_uris,
        }
    }

def create_access_token(user_email: str, scope: str) -> str:
    """Create JWT access token"""
    payload = {
        "sub": user_email,
        "scope": scope,
        "iat": int(time.time()),
        "exp": int(time.time()) + settings.access_token_ttl,
        "token_type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

def create_refresh_token() -> str:
    """Create opaque refresh token"""
    return secrets.token_urlsafe(48)

async def log_request(request: Request, form_data: dict = None):
    """Log complete request details"""
    print("=" * 80)
    print(f"[REQUEST LOG] {request.method} {request.url}")
    print("-" * 80)
    print(f"URL: {request.url}")
    print(f"Path: {request.url.path}")
    print(f"Query Params: {dict(request.query_params)}")
    print(f"Headers:")
    for key, value in request.headers.items():
        print(f"  {key}: {value}")
    print(f"Client: {request.client.host}:{request.client.port}" if request.client else "Client: Unknown")
    
    # Log body/form data
    if form_data:
        print(f"Form Data:")
        for key, value in form_data.items():
            # Mask sensitive fields
            if key in ['password', 'client_secret']:
                print(f"  {key}: ***MASKED***")
            else:
                print(f"  {key}: {value}")
    else:
        try:
            body = await request.body()
            if body:
                print(f"Body (raw): {body.decode('utf-8')}")
            else:
                print("Body: (empty)")
        except:
            print("Body: (unable to read)")
    
    print("=" * 80)

@router.get("/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read write"),
    state: Optional[str] = Query(None),
):
    """OAuth2 Authorization Endpoint - Step 1"""
    await log_request(request)
    
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code supported")

    clients = get_oauth2_clients()
    if client_id not in clients:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if redirect_uri not in clients[client_id]["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    login_form = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth2 Login</title>
        <style>
            body {{ font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto;
                    padding: 20px; border: 1px solid #ddd; border-radius: 8px; background: #f9f9f9; }}
            h2 {{ color: #333; }}
            input, button {{ width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }}
            button {{ background: #0066cc; color: white; border: none; border-radius: 4px;
                      cursor: pointer; font-size: 16px; }}
            button:hover {{ background: #0052a3; }}
            .info {{ background: #e7f3ff; padding: 10px; border-radius: 4px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <h2>🔐 OAuth2 Login</h2>
        <div class="info">
            <strong>Client:</strong> {client_id}<br>
            <strong>Scopes:</strong> {scope}<br>
            <strong>Redirect:</strong> {redirect_uri}
        </div>
        <form method="post" action="/authorize/login">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="scope" value="{scope}">
            <input type="hidden" name="state" value="{state or ''}">
            <label>Email:</label>
            <input type="email" name="username" value="user@example.com" required>
            <label>Password:</label>
            <input type="password" name="password" value="password123" required>
            <button type="submit">Authorize & Login</button>
        </form>
        <p style="font-size: 12px; color: #666;">Test: user@example.com / password123</p>
    </body>
    </html>
    """
    return HTMLResponse(content=login_form)

@router.post("/authorize/login")
async def authorize_login(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    state: Optional[str] = Form(None),
    username: str = Form(...),
    password: str = Form(...),
):
    """Process login and redirect with authorization code"""
    form_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "username": username,
        "password": password
    }
    await log_request(request, form_data)
    
    user = settings.mock_users.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    code = secrets.token_urlsafe(32)

    AUTHORIZATION_CODES[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "username": username,
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + settings.authorization_code_ttl,
    }

    params = {"code": code}
    if state:
        params["state"] = state

    redirect_url = f"{redirect_uri}?{urllib.parse.urlencode(params)}"
    print(f"[REDIRECT] Redirecting to: {redirect_url}")
    return RedirectResponse(url=redirect_url, status_code=302)

@router.post("/token", response_model=TokenResponse)
async def token(
    request: Request,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    refresh_token: Optional[str] = Form(None),
):
    """OAuth2 Token Endpoint - Exchange code for tokens"""
    form_data = {
        "grant_type": grant_type,
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token
    }
    await log_request(request, form_data)
    
    clients = get_oauth2_clients()
    client = clients.get(client_id)

    if not client or client["client_secret"] != client_secret:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    if grant_type == "authorization_code":
        if not code or not redirect_uri:
            raise HTTPException(status_code=400, detail="code and redirect_uri required")

        auth_data = AUTHORIZATION_CODES.get(code)
        if not auth_data:
            raise HTTPException(status_code=400, detail="Invalid authorization code")

        if auth_data["client_id"] != client_id or auth_data["redirect_uri"] != redirect_uri:
            raise HTTPException(status_code=400, detail="Mismatch in client_id or redirect_uri")

        if int(time.time()) > auth_data["expires_at"]:
            del AUTHORIZATION_CODES[code]
            raise HTTPException(status_code=400, detail="Authorization code expired")

        username = auth_data["username"]
        scope = auth_data["scope"]

        access_token = create_access_token(username, scope)
        refresh_token_str = create_refresh_token()

        REFRESH_TOKENS[refresh_token_str] = {
            "client_id": client_id,
            "username": username,
            "scope": scope,
            "issued_at": int(time.time()),
            "expires_at": int(time.time()) + settings.refresh_token_ttl,
        }

        del AUTHORIZATION_CODES[code]

        print(f"[TOKEN ISSUED] access_token created for user: {username}")
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_ttl,
            refresh_token=refresh_token_str,
            scope=scope,
        )

    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(status_code=400, detail="refresh_token required")

        refresh_data = REFRESH_TOKENS.get(refresh_token)
        if not refresh_data or refresh_data["client_id"] != client_id:
            raise HTTPException(status_code=400, detail="Invalid refresh token")

        if int(time.time()) > refresh_data["expires_at"]:
            del REFRESH_TOKENS[refresh_token]
            raise HTTPException(status_code=400, detail="Refresh token expired")

        access_token = create_access_token(refresh_data["username"], refresh_data["scope"])

        print(f"[TOKEN REFRESHED] access_token refreshed for user: {refresh_data['username']}")
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.access_token_ttl,
            refresh_token=refresh_token,
            scope=refresh_data["scope"],
        )

    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")

@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    """OAuth2 Authorization Server Metadata (RFC 8414)"""
    await log_request(request)
    
    return {
        "issuer": f"http://{settings.host}:{settings.port}",
        "authorization_endpoint": f"http://{settings.host}:{settings.port}/authorize",
        "token_endpoint": f"http://{settings.host}:{settings.port}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "scopes_supported": ["read", "write", "admin"],
    }

