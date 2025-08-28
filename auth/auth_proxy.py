"""
Authentication Proxy for Crawl4AI
Intercepts requests and validates authentication before forwarding to Crawl4AI
"""

import os
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import uvicorn

# Configuration
CRAWL4AI_PORT = 11235
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8000")
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "true").lower() == "true"

# Create proxy app
app = FastAPI(title="Crawl4AI Auth Proxy")

# HTTP client for forwarding requests
client = httpx.AsyncClient(timeout=300.0)


async def forward_request(request: Request, path: str) -> Response:
    """Forward request to Crawl4AI service"""
    # Build target URL
    target_url = f"http://localhost:{CRAWL4AI_PORT}{path}"
    
    # Get request body
    body = await request.body()
    
    # Forward the request
    response = await client.request(
        method=request.method,
        url=target_url,
        headers=dict(request.headers),
        content=body,
        params=request.query_params
    )
    
    # Return response
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )


async def forward_stream(request: Request, path: str) -> StreamingResponse:
    """Forward streaming request to Crawl4AI service"""
    target_url = f"http://localhost:{CRAWL4AI_PORT}{path}"
    body = await request.body()
    
    async def stream_response():
        async with client.stream(
            request.method,
            target_url,
            headers=dict(request.headers),
            content=body,
            params=request.query_params
        ) as response:
            async for chunk in response.aiter_bytes():
                yield chunk
    
    return StreamingResponse(
        stream_response(),
        media_type="application/x-ndjson"
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
async def proxy_request(request: Request, path: str):
    """
    Proxy all requests to Crawl4AI
    Authentication is handled by Traefik ForwardAuth
    """
    # Public endpoints that don't need authentication
    public_paths = ["health", "metrics", "docs", "openapi.json", "redoc"]
    
    # Check if path is public
    is_public = any(path.startswith(p) for p in public_paths)
    
    if not is_public and ENABLE_AUTH:
        # Check for auth headers added by Traefik
        if not request.headers.get("X-Api-Key-Id") and not request.headers.get("X-User-Id"):
            raise HTTPException(status_code=401, detail="Authentication required")
    
    # Handle streaming endpoints
    if path.endswith("/stream"):
        return await forward_stream(request, f"/{path}")
    
    # Forward regular requests
    return await forward_request(request, f"/{path}")


@app.on_event("startup")
async def startup():
    """Start the actual Crawl4AI service in background"""
    import subprocess
    import time
    
    # Start Crawl4AI service
    subprocess.Popen(["uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(CRAWL4AI_PORT)])
    
    # Wait for service to be ready
    time.sleep(5)
    print(f"✅ Crawl4AI service started on port {CRAWL4AI_PORT}")
    print(f"✅ Auth proxy listening on port 11235")
    print(f"✅ Authentication enabled: {ENABLE_AUTH}")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup"""
    await client.aclose()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=11235)