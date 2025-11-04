#!/usr/bin/env python3

from fastapi import FastAPI
import uvicorn
import sys
from src.config import settings

# Create FastAPI app
app = FastAPI(title=settings.app_name, version="2.0.0")

# Conditionally include OAuth routers based on config
if "oauth2" in settings.enabled_flows:
    from src.oauth2 import router as oauth2_router
    app.include_router(oauth2_router)
    print("✅ OAuth2 flow enabled")

if "oauth1" in settings.enabled_flows:
    from src.oauth1 import router as oauth1_router
    app.include_router(oauth1_router)
    print("✅ OAuth1 flow enabled")

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

if __name__ == "__main__":
    print(f"🚀 Starting {settings.app_name}")
    print(f"📋 Configuration loaded from: {settings.config_path}")
    print(f"🔐 Enabled flows: {', '.join(settings.enabled_flows)}")
    print(f"📡 Server running at http://{settings.host}:{settings.port}")

    uvicorn.run(app, host=settings.host, port=settings.port)
