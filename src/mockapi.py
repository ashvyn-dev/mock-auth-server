#!/usr/bin/env python3

#!/usr/bin/env python3

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from typing import Any, Dict, List, Optional
import yaml
import json
from pathlib import Path
from faker import Faker
import random
from datetime import datetime, timedelta

router = APIRouter()
fake = Faker()

# Global storage for mock APIs
MOCK_APIS: Dict[str, Any] = {}
OPENAPI_SPEC: Dict[str, Any] = {}


def load_openapi_spec(config_path: Path) -> Dict[str, Any]:
    """Load OpenAPI specification from YAML file"""
    if not config_path.exists():
        raise FileNotFoundError(f"Mock API config not found: {config_path}")

    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def generate_fake_data(schema: Dict[str, Any], custom_data: Optional[Dict] = None) -> Any:
    """
    Generate fake data based on OpenAPI schema definition
    Uses Faker for realistic data generation
    """
    if custom_data:
        return custom_data

    schema_type = schema.get("type", "string")
    schema_format = schema.get("format")
    example = schema.get("example")

    # If example is provided, use it
    if example is not None:
        return example

    # Generate based on type
    if schema_type == "string":
        if schema_format == "email":
            return fake.email()
        elif schema_format == "uri" or schema_format == "url":
            return fake.url()
        elif schema_format == "date":
            return fake.date()
        elif schema_format == "date-time":
            return fake.iso8601()
        elif schema_format == "uuid":
            return fake.uuid4()
        elif schema.get("enum"):
            return random.choice(schema["enum"])
        else:
            return fake.sentence(nb_words=3).rstrip(".")

    elif schema_type == "integer":
        minimum = schema.get("minimum", 1)
        maximum = schema.get("maximum", 1000)
        return random.randint(minimum, maximum)

    elif schema_type == "number":
        minimum = schema.get("minimum", 1.0)
        maximum = schema.get("maximum", 1000.0)
        return round(random.uniform(minimum, maximum), 2)

    elif schema_type == "boolean":
        return fake.boolean()

    elif schema_type == "array":
        items_schema = schema.get("items", {})
        min_items = schema.get("minItems", 1)
        max_items = schema.get("maxItems", 5)
        count = random.randint(min_items, max_items)
        return [generate_fake_data(items_schema) for _ in range(count)]

    elif schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        obj = {}

        for prop_name, prop_schema in properties.items():
            if prop_name in required or random.choice([True, False]):
                obj[prop_name] = generate_fake_data(prop_schema)

        return obj

    return None


def generate_response_from_schema(response_schema: Dict[str, Any], custom_data: Optional[Dict] = None) -> Any:
    """Generate a complete response based on OpenAPI response schema"""
    content = response_schema.get("content", {})

    # Try to find JSON content
    for content_type in ["application/json", "*/*"]:
        if content_type in content:
            schema = content[content_type].get("schema", {})

            # Check if there's a $ref to a component
            if "$ref" in schema:
                ref_path = schema["$ref"].split("/")
                # Navigate to the referenced schema
                ref_schema = OPENAPI_SPEC
                for part in ref_path:
                    if part == "#":
                        continue
                    ref_schema = ref_schema.get(part, {})
                schema = ref_schema

            return generate_fake_data(schema, custom_data)

    return {"message": "Success"}


def register_mock_endpoint(app, path: str, method: str, operation: Dict[str, Any], custom_responses: Dict[str, Any] = None):
    """
    Dynamically register a mock endpoint based on OpenAPI operation definition
    """
    operation_id = operation.get("operationId", f"{method}_{path.replace('/', '_')}")
    summary = operation.get("summary", "")
    description = operation.get("description", "")
    responses = operation.get("responses", {})

    # Get custom response data if available
    custom_data = None
    if custom_responses and path in custom_responses:
        custom_data = custom_responses[path].get(method.lower())

    async def mock_handler(request: Request):
        """Generic handler for mock endpoints"""
        # Default to 200 response
        status_code = 200
        response_schema = responses.get("200") or responses.get("201") or responses.get("default")

        if not response_schema:
            return JSONResponse({"message": "Success"}, status_code=200)

        # Generate response data
        response_data = generate_response_from_schema(response_schema, custom_data)

        return JSONResponse(response_data, status_code=status_code)

    # Register the route dynamically
    route_path = f"/mockapi{path}"

    if method.lower() == "get":
        app.get(route_path, summary=summary, description=description, tags=["Mock API"])(mock_handler)
    elif method.lower() == "post":
        app.post(route_path, summary=summary, description=description, tags=["Mock API"])(mock_handler)
    elif method.lower() == "put":
        app.put(route_path, summary=summary, description=description, tags=["Mock API"])(mock_handler)
    elif method.lower() == "patch":
        app.patch(route_path, summary=summary, description=description, tags=["Mock API"])(mock_handler)
    elif method.lower() == "delete":
        app.delete(route_path, summary=summary, description=description, tags=["Mock API"])(mock_handler)

    print(f"   📍 Registered: {method.upper()} {route_path}")


def load_mock_apis(app):
    """
    Load mock APIs from OpenAPI YAML configuration
    Dynamically registers all endpoints defined in the spec
    """
    from src.config import settings

    global OPENAPI_SPEC, MOCK_APIS

    try:
        # Load OpenAPI spec
        OPENAPI_SPEC = load_openapi_spec(settings.mockapi_config_path)

        print(f"\n🔧 Loading Mock APIs from: {settings.mockapi_config_path}")
        print(f"   API Title: {OPENAPI_SPEC.get('info', {}).get('title', 'Unknown')}")
        print(f"   Version: {OPENAPI_SPEC.get('info', {}).get('version', '1.0.0')}")

        # Get custom response data if defined
        custom_responses = OPENAPI_SPEC.get("x-custom-responses", {})

        # Register all paths
        paths = OPENAPI_SPEC.get("paths", {})
        endpoint_count = 0

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "patch", "delete"]:
                if method in path_item:
                    operation = path_item[method]
                    register_mock_endpoint(app, path, method, operation, custom_responses)
                    endpoint_count += 1

                    # Store for listing
                    if path not in MOCK_APIS:
                        MOCK_APIS[path] = {}
                    MOCK_APIS[path][method.upper()] = operation

        print(f"   ✅ Loaded {endpoint_count} mock endpoints\n")

    except Exception as e:
        print(f"   ❌ Failed to load mock APIs: {str(e)}\n")


@router.get("/list")
def list_mock_apis():
    """List all registered mock API endpoints"""
    endpoints = []

    for path, methods in MOCK_APIS.items():
        for method, operation in methods.items():
            endpoints.append({
                "path": f"/mockapi{path}",
                "method": method,
                "summary": operation.get("summary", ""),
                "description": operation.get("description", ""),
                "operationId": operation.get("operationId", ""),
            })

    return {
        "total": len(endpoints),
        "endpoints": endpoints,
    }


@router.get("/openapi.json")
def get_openapi_spec():
    """Return the loaded OpenAPI specification"""
    if not OPENAPI_SPEC:
        raise HTTPException(status_code=404, detail="OpenAPI spec not loaded")

    return OPENAPI_SPEC
