# OAuth Mock Server

A complete mock OAuth1 and OAuth2 authorization server with dynamic Mock API support built with FastAPI for testing OAuth implementations and API integrations.

## Features

- OAuth1.0a support (3-legged flow with HMAC-SHA1 signatures)
- OAuth2 support (Authorization Code Grant flow with JWT tokens)
- **Mock API with OpenAPI 3.0 specification support**
- **Auto-generated fake data using Faker library**
- **Custom response data override support**
- YAML/JSON configuration
- Modular design (separate OAuth1, OAuth2, and Mock API modules)
- Protected resource endpoints
- Mock user database
- Built with uv for fast dependency management

## Installation

1. Clone the repository:
```
git clone git@github.com:ashvyn-dev/mock-auth-server.git
cd mock-auth-server
```

2. Install dependencies with uv:
```
uv sync
```

## Configuration

Edit `config.yaml` to customize settings:

```
server:
  app_name: "OAuth Mock Server"
  host: "localhost"
  port: 8000

enabled_flows:
  - "oauth1"
  - "oauth2"
  - "mockapi"  # Enable Mock API feature

jwt:
  secret: "mock-oauth-secret"
  algorithm: "HS256"
  access_token_ttl: 3600
  refresh_token_ttl: 86400
  authorization_code_ttl: 600

oauth1:
  consumer_key: "oauth1_consumer_key"
  consumer_secret: "oauth1_consumer_secret"
  callback_uris:
    - "http://localhost:3000/oauth1/callback"
    - "oob"
  request_token_ttl: 600
  access_token_ttl: 2592000

oauth2:
  client_id: "my_app_client_id"
  client_secret: "my_app_client_secret"
  redirect_uris:
    - "http://localhost:3000/callback"
    - "http://127.0.0.1:3000/callback"

mockapi:
  config_file: "mockapi-config.yaml"
  prefix: "/mockapi"
  auto_generate: true
  faker_locale: "en_IN"

users:
  user@example.com:
    password: "password123"
    name: "Test User"
  admin@example.com:
    password: "admin123"
    name: "Admin User"
```

### Configuration Changes

Add new OAuth1 consumer:
```
oauth1:
  consumer_key: "my_consumer_key"
  consumer_secret: "my_consumer_secret"
```

Add new OAuth2 client:
```
oauth2:
  client_id: "my_client_id"
  client_secret: "my_client_secret"
```

Add new test user:
```
users:
  newuser@example.com:
    password: "mypassword"
    name: "New User"
```

Change token expiration:
```
jwt:
  access_token_ttl: 7200  # 2 hours
  refresh_token_ttl: 604800  # 7 days
```

Use different config file:
```
export OAUTH_CONFIG=config.production.yaml
uv run app.py
```

## Running the Server

Start the server:
```
uv run app.py
```

Or with uvicorn directly:
```
uv run uvicorn app:app --reload --host localhost --port 8000
```

Access the server:
- API Documentation: http://localhost:8000/docs
- Root Endpoint: http://localhost:8000/
- Health Check: http://localhost:8000/health

## Mock API Feature

The Mock API feature allows you to quickly create mock REST APIs based on OpenAPI 3.0 specifications. It automatically generates realistic fake data or uses your custom response data.

### Setting Up Mock APIs

1. **Enable Mock API** in `config.yaml`:
```
enabled_flows:
  - "mockapi"

mockapi:
  config_file: "mockapi-config.yaml"  # Path to OpenAPI spec
  prefix: "/mockapi"                   # URL prefix for endpoints
  auto_generate: true                  # Auto-generate fake data
  faker_locale: "en_IN"                # Locale for generated data
```

2. **Create OpenAPI Specification** (`mockapi-config.yaml`):
```
openapi: 3.0.3
info:
  title: My Mock API
  version: 1.0.0

paths:
  /users:
    get:
      summary: Get all users
      responses:
        '200':
          description: Success
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/User'

components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        email:
          type: string
          format: email
```

3. **Add Custom Response Data** (optional):
```
x-custom-responses:
  /users/me:
    get:
      id: 12345
      email: "john.doe@example.com"
      name: "John Doe"
      role: "admin"
```

### Testing Mock APIs

List all available endpoints:
```
curl http://localhost:8000/mockapi/list
```

Get OpenAPI specification:
```
curl http://localhost:8000/mockapi/openapi.json
```

Call mock endpoints:
```
# Auto-generated data
curl http://localhost:8000/mockapi/users
curl http://localhost:8000/mockapi/products
curl http://localhost:8000/mockapi/orders

# Custom response data
curl http://localhost:8000/mockapi/users/me
```

### Mock API Features

**Auto-Generated Data Types:**
- Realistic emails, names, addresses
- UUIDs, dates, timestamps
- Numbers within specified ranges
- Booleans, enums
- Arrays and nested objects
- Localized data (Indian names, addresses with `en_IN`)

**Schema Support:**
- All OpenAPI 3.0 data types
- Schema references (`$ref`)
- Required fields
- Min/max constraints
- Format specifications (email, uri, date, uuid)
- Enum values
- Examples

**Custom Data Override:**
Use `x-custom-responses` in your OpenAPI spec to provide specific response data instead of auto-generated data.

### Example Mock API Endpoints

Based on the included `mockapi-config.yaml`:

**Users API:**
```
GET  /mockapi/users           # List all users
POST /mockapi/users           # Create user
GET  /mockapi/users/{userId}  # Get user by ID
PUT  /mockapi/users/{userId}  # Update user
DELETE /mockapi/users/{userId} # Delete user
GET  /mockapi/users/me        # Get current user (custom data)
```

**Products API:**
```
GET  /mockapi/products        # List products (custom data)
POST /mockapi/products        # Create product
```

**Orders API:**
```
GET  /mockapi/orders          # List orders
POST /mockapi/orders          # Create order
GET  /mockapi/orders/{orderId} # Get order by ID
```

**Analytics API:**
```
GET  /mockapi/analytics/stats # Get analytics data
```

All endpoints are automatically documented in Swagger UI at http://localhost:8000/docs

## Testing OAuth1

Automated test:
```
uv run oauth1_test.py
```

This runs the complete OAuth1 flow:
1. Requests temporary token
2. Authorizes request token
3. Exchanges for access token
4. Accesses protected resource

Manual test with cURL:
```
# Step 1: Generate signature and request token
AUTH_HEADER=$(uv run oauth1_signer.py POST "http://localhost:8000/oauth1/request_token" "" "" "" "oob")
curl -X POST "http://localhost:8000/oauth1/request_token" \
  -H "Authorization: $AUTH_HEADER"

# Step 2: Authorize
curl -X POST "http://localhost:8000/oauth1/authorize" \
  -d "oauth_token=REQUEST_TOKEN" \
  -d "username=user@example.com" \
  -d "password=password123" \
  -d "action=authorize"

# Step 3: Exchange for access token
AUTH_HEADER=$(uv run oauth1_signer.py POST "http://localhost:8000/oauth1/access_token" "REQUEST_TOKEN" "REQUEST_TOKEN_SECRET" "VERIFIER")
curl -X POST "http://localhost:8000/oauth1/access_token" \
  -H "Authorization: $AUTH_HEADER"

# Step 4: Access protected resource
AUTH_HEADER=$(uv run oauth1_signer.py GET "http://localhost:8000/oauth1/api/user" "ACCESS_TOKEN" "ACCESS_TOKEN_SECRET")
curl -X GET "http://localhost:8000/oauth1/api/user" \
  -H "Authorization: $AUTH_HEADER"
```

## Testing OAuth2

Step 1: Authorization
```
curl -X POST http://localhost:8000/authorize/login \
  -d "client_id=my_app_client_id" \
  -d "redirect_uri=http://127.0.0.1:3000/callback" \
  -d "scope=read write" \
  -d "username=user@example.com" \
  -d "password=password123"
```

Step 2: Exchange code for token
```
curl -X POST http://localhost:8000/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "redirect_uri=http://127.0.0.1:3000/callback" \
  -d "client_id=my_app_client_id" \
  -d "client_secret=my_app_client_secret"
```

Step 3: Use access token
```
curl -X GET http://localhost:8000/oauth2/api/user \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## API Endpoints

### OAuth1 Endpoints
- `POST /oauth1/request_token` - Get temporary credentials
- `GET /oauth1/authorize` - User authorization page
- `POST /oauth1/authorize` - Submit authorization
- `POST /oauth1/access_token` - Exchange for access token
- `GET /oauth1/api/user` - Access protected resource

### OAuth2 Endpoints
- `GET /authorize` - Authorization request
- `POST /authorize/login` - Login and authorization
- `POST /token` - Get tokens
- `GET /.well-known/oauth-authorization-server` - Server metadata
- `GET /oauth2/api/user` - Access protected resource

### Mock API Endpoints
- `GET /mockapi/list` - List all registered mock endpoints
- `GET /mockapi/openapi.json` - Get OpenAPI specification
- `GET|POST|PUT|PATCH|DELETE /mockapi/*` - Dynamic endpoints based on OpenAPI spec

## Test Credentials

Users:
```
user@example.com / password123
admin@example.com / admin123
```

OAuth1:
```
Consumer Key: oauth1_consumer_key
Consumer Secret: oauth1_consumer_secret
```

OAuth2:
```
Client ID: my_app_client_id
Client Secret: my_app_client_secret
```

## Project Structure

```
oauth-mock-server/
├── app.py
├── config.yaml
├── mockapi-config.yaml
├── pyproject.toml
├── uv.lock
├── .gitignore
├── README.md
├── oauth1_test.py
├── oauth1_signer.py
└── src/
    ├── __init__.py
    ├── config.py
    ├── oauth1.py
    ├── oauth2.py
    └── mockapi.py
```

## Troubleshooting

Port already in use:
```
# Change port in config.yaml
server:
  port: 8001
```

Config file not found:
```
# Make sure config.yaml exists in project root
ls -la config.yaml

# Or specify custom config
export OAUTH_CONFIG=config.json
uv run app.py
```

Module not found:
```
# Sync dependencies
uv sync

# Reinstall all dependencies
uv pip install --upgrade -r requirements.txt
```

Connection refused:
```
# Make sure server is running
uv run app.py

# In another terminal, test connection
curl http://localhost:8000/health
```

Mock API not loading:
```
# Check if mockapi is enabled in config.yaml
enabled_flows:
  - "mockapi"

# Verify OpenAPI spec file exists
ls -la mockapi-config.yaml

# Check server logs for errors
uv run app.py
```

## Development

Add new package:
```
uv add package_name
```

Remove package:
```
uv remove package_name
```

Update all packages:
```
uv sync --upgrade
```

Add new OAuth client:
1. Edit config.yaml
2. Add consumer key/secret or client ID/secret
3. Restart server

Add new test user:
1. Edit config.yaml
2. Add user in users section
3. Restart server

Add new mock API endpoints:
1. Edit mockapi-config.yaml
2. Add paths and schemas to OpenAPI spec
3. Optionally add custom responses in `x-custom-responses`
4. Restart server (endpoints are auto-registered)

## Dependencies

- **FastAPI** - Modern web framework
- **Uvicorn** - ASGI server
- **PyJWT** - JWT token handling
- **PyYAML** - YAML configuration
- **Faker** - Fake data generation for Mock API
- **Starlette** - ASGI toolkit
