#!/usr/bin/env python3

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn
import time
from src.config import settings

# Create FastAPI app
app = FastAPI(title=settings.app_name, version="2.0.0")

# ============================================================================
# GENERIC LOGGING MIDDLEWARE - Logs ALL requests and responses
# ============================================================================


class LoggingMiddleware(BaseHTTPMiddleware):
    """Generic logging middleware for all HTTP requests and responses"""

    async def dispatch(self, request: Request, call_next):
        # Start timing
        start_time = time.time()

        # Read the body
        body = await request.body()

        # Log incoming request
        print("\n" + "=" * 100)
        print(f"[REQUEST] {request.method} {request.url}")
        print("-" * 100)
        print(f"Path: {request.url.path}")
        if request.query_params:
            print(f"Query Params: {dict(request.query_params)}")
        print(f"Client: {request.client.host}:{request.client.port}" if request.client else "Unknown")
        print(f"\nHeaders:")
        # Log all headers as-is without masking
        for key, value in request.headers.items():
            print(f"  {key}: {value}")

        if body:
            print(f"\nBody: {body.decode('utf-8', errors='ignore')}")

        # Allow body to be read again by the route handler
        async def receive():
            return {"type": "http.request", "body": body}
        request._receive = receive

        # Process the request
        response = await call_next(request)

        # Calculate duration
        process_time = time.time() - start_time

        # Log response
        print(f"\n[RESPONSE] Status: {response.status_code} | Time: {process_time:.3f}s")
        print("=" * 100 + "\n")

        return response

# Add the logging middleware
app.add_middleware(LoggingMiddleware)

# ============================================================================
# INCLUDE OAUTH ROUTERS
# ============================================================================

if "oauth2" in settings.enabled_flows:
    from src.oauth2 import router as oauth2_router
    app.include_router(oauth2_router)
    print("✅ OAuth2 flow enabled")

if "oauth1" in settings.enabled_flows:
    from src.oauth1 import router as oauth1_router
    app.include_router(oauth1_router)
    print("✅ OAuth1 flow enabled")

# ============================================================================
# INCLUDE MOCK API ROUTER
# ============================================================================

if "mockapi" in settings.enabled_flows:
    from src.mockapi import router as mockapi_router, load_mock_apis
    app.include_router(mockapi_router, prefix="/mockapi")

    # Load and register mock APIs dynamically
    load_mock_apis(app)
    print("✅ Mock API flow enabled")

# ============================================================================
# ROOT ENDPOINTS
# ============================================================================

@app.get("/")
def root():
    """Root endpoint with server information"""
    response = {
        "service": settings.app_name,
        "version": "2.0.0",
        "enabled_flows": settings.enabled_flows,
        "config_file": str(settings.config_path),
    }

    if "oauth2" in settings.enabled_flows:
        response["oauth2"] = {
            "endpoints": {
                "authorize": "/authorize",
                "token": "/token",
                "metadata": "/.well-known/oauth-authorization-server",
            },
            "credentials": {
                "client_id": settings.oauth2_client_id,
                "client_secret": settings.oauth2_client_secret,
            },
            "test_flow": f"/authorize?response_type=code&client_id={settings.oauth2_client_id}&redirect_uri={settings.oauth2_redirect_uris[0]}&scope=read%20write&state=xyz123",
        }

    if "oauth1" in settings.enabled_flows:
        response["oauth1"] = {
            "endpoints": {
                "request_token": "/oauth1/request_token",
                "authorize": "/oauth1/authorize",
                "access_token": "/oauth1/access_token",
                "protected_resource": "/oauth1/api/user",
            },
            "credentials": {
                "consumer_key": settings.oauth1_consumer_key,
                "consumer_secret": settings.oauth1_consumer_secret,
            },
        }

    if "mockapi" in settings.enabled_flows:
        response["mockapi"] = {
            "endpoints": {
                "list": "/mockapi/list",
                "openapi_spec": "/mockapi/openapi.json",
            },
            "config_file": str(settings.mockapi_config_path),
        }

    response["test_users"] = list(settings.mock_users.keys())
    response["docs"] = "/docs"

    return response

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "enabled_flows": settings.enabled_flows,
        "config_file": str(settings.config_path),
    }

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print(f"🚀 Starting {settings.app_name}")
    print(f"📋 Configuration loaded from: {settings.config_path}")
    print(f"🔐 Enabled flows: {', '.join(settings.enabled_flows)}")
    print(f"📡 Server running at http://{settings.host}:{settings.port}")

    uvicorn.run(app, host=settings.host, port=settings.port)
