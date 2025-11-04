#!/usr/bin/env python3

import yaml
import json
import os
from pathlib import Path
from typing import Dict, List, Any

class Config:
    """Configuration loader for YAML/JSON files"""

    def __init__(self, config_file: str = "config.yaml"):
        """Load configuration from file"""
        self.config_path = Path(config_file)
        self.config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self):
        """Load configuration from YAML or JSON file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

        try:
            if self.config_path.suffix == ".yaml" or self.config_path.suffix == ".yml":
                with open(self.config_path, "r") as f:
                    self.config = yaml.safe_load(f)
            elif self.config_path.suffix == ".json":
                with open(self.config_path, "r") as f:
                    self.config = json.load(f)
            else:
                raise ValueError(f"Unsupported config file format: {self.config_path.suffix}")
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration: {str(e)}")

    # Server Configuration
    @property
    def app_name(self) -> str:
        return self.config.get("server", {}).get("app_name", "OAuth Mock Server")

    @property
    def host(self) -> str:
        return self.config.get("server", {}).get("host", "localhost")

    @property
    def port(self) -> int:
        return self.config.get("server", {}).get("port", 8000)

    @property
    def enabled_flows(self) -> List[str]:
        return self.config.get("enabled_flows", ["oauth1", "oauth2"])

    # JWT Configuration
    @property
    def jwt_secret(self) -> str:
        return self.config.get("jwt", {}).get("secret", "mock-oauth-secret")

    @property
    def jwt_algorithm(self) -> str:
        return self.config.get("jwt", {}).get("algorithm", "HS256")

    @property
    def access_token_ttl(self) -> int:
        return self.config.get("jwt", {}).get("access_token_ttl", 3600)

    @property
    def refresh_token_ttl(self) -> int:
        return self.config.get("jwt", {}).get("refresh_token_ttl", 86400)

    @property
    def authorization_code_ttl(self) -> int:
        return self.config.get("jwt", {}).get("authorization_code_ttl", 600)

    # OAuth1 Configuration
    @property
    def oauth1_signature_method(self) -> str:
        return self.config.get("oauth1", {}).get("signature_method", "HMAC-SHA1")

    @property
    def oauth1_consumer_key(self) -> str:
        return self.config.get("oauth1", {}).get("consumer_key", "oauth1_consumer_key")

    @property
    def oauth1_consumer_secret(self) -> str:
        return self.config.get("oauth1", {}).get("consumer_secret", "oauth1_consumer_secret")

    @property
    def oauth1_callback_uris(self) -> List[str]:
        return self.config.get("oauth1", {}).get("callback_uris", ["http://localhost:3000/oauth1/callback", "oob"])

    @property
    def oauth1_request_token_ttl(self) -> int:
        return self.config.get("oauth1", {}).get("request_token_ttl", 600)

    @property
    def oauth1_access_token_ttl(self) -> int:
        return self.config.get("oauth1", {}).get("access_token_ttl", 2592000)

    # OAuth2 Configuration
    @property
    def oauth2_client_id(self) -> str:
        return self.config.get("oauth2", {}).get("client_id", "my_app_client_id")

    @property
    def oauth2_client_secret(self) -> str:
        return self.config.get("oauth2", {}).get("client_secret", "my_app_client_secret")

    @property
    def oauth2_redirect_uris(self) -> List[str]:
        return self.config.get("oauth2", {}).get("redirect_uris", [
            "http://localhost:3000/callback",
            "http://127.0.0.1:3000/callback",
        ])

    # Users Configuration
    @property
    def mock_users(self) -> Dict[str, Dict[str, str]]:
        return self.config.get("users", {
            "user@example.com": {"password": "password123", "name": "Test User"},
            "admin@example.com": {"password": "admin123", "name": "Admin User"},
        })

    def get_raw_config(self) -> Dict[str, Any]:
        """Return the entire raw configuration"""
        return self.config

    def __repr__(self) -> str:
        return f"<Config from {self.config_path}>"


# Initialize settings from config file
# Support passing config file via environment variable
config_file = os.getenv("OAUTH_CONFIG", "config.yaml")
settings = Config(config_file)
