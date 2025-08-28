"""
Authentication Service for Crawl4AI
Provides API key validation and JWT token management
"""

import os
import json
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import redis.asyncio as redis
from passlib.context import CryptContext
from jose import JWTError, jwt
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import httpx

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")

# Metrics
auth_requests = Counter('auth_requests_total', 'Total authentication requests', ['method', 'status'])
auth_duration = Histogram('auth_duration_seconds', 'Authentication request duration')
api_key_validations = Counter('api_key_validations_total', 'API key validation attempts', ['status'])
rate_limit_hits = Counter('rate_limit_hits_total', 'Rate limit hits', ['key_id'])

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer(auto_error=False)

# Redis client
redis_client: Optional[redis.Redis] = None

# API Keys storage
api_keys_store: Dict[str, Dict] = {}


class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: List[str] = []


class ApiKeyConfig(BaseModel):
    name: str
    key: str
    rate_limit: str = "100/minute"
    scopes: List[str] = ["crawl"]
    enabled: bool = True


async def get_redis() -> redis.Redis:
    """Get Redis client"""
    return redis_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global redis_client, api_keys_store
    
    # Initialize Redis
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    await redis_client.ping()
    print(f"✅ Connected to Redis at {REDIS_URL}")
    
    # Load API keys from environment
    api_keys_json = os.getenv("API_KEYS_CONFIG", "{}")
    try:
        api_keys_config = json.loads(api_keys_json)
        for key_id, config in api_keys_config.items():
            # Hash the actual key for secure storage
            key_hash = hashlib.sha256(config["key"].encode()).hexdigest()
            api_keys_store[key_hash] = {
                "id": key_id,
                "name": config.get("name", f"Key {key_id}"),
                "rate_limit": config.get("rate_limit", "100/minute"),
                "scopes": config.get("scopes", ["crawl"]),
                "enabled": config.get("enabled", True)
            }
        print(f"✅ Loaded {len(api_keys_store)} API keys")
    except json.JSONDecodeError as e:
        print(f"⚠️ Failed to load API keys: {e}")
    
    yield
    
    # Cleanup
    if redis_client:
        await redis_client.close()


app = FastAPI(
    title="Crawl4AI Authentication Service",
    version="1.0.0",
    lifespan=lifespan
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


async def verify_token(token: str) -> Optional[Dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


async def check_rate_limit(key_id: str, limit_str: str, redis_conn: redis.Redis) -> bool:
    """Check rate limiting for API key"""
    # Parse rate limit (e.g., "100/minute")
    parts = limit_str.split("/")
    if len(parts) != 2:
        return True
    
    try:
        limit = int(parts[0])
        period = parts[1].lower()
    except ValueError:
        return True
    
    # Convert period to seconds
    period_seconds = {
        "second": 1,
        "minute": 60,
        "hour": 3600,
        "day": 86400
    }.get(period, 60)
    
    # Create rate limit key
    current_window = int(time.time() // period_seconds)
    rate_key = f"rate_limit:{key_id}:{current_window}"
    
    # Check and increment counter
    try:
        current = await redis_conn.incr(rate_key)
        if current == 1:
            await redis_conn.expire(rate_key, period_seconds)
        
        if current > limit:
            rate_limit_hits.labels(key_id=key_id).inc()
            return False
        return True
    except Exception as e:
        print(f"Rate limit check failed: {e}")
        return True  # Fail open


async def validate_api_key(credentials: HTTPAuthorizationCredentials, redis_conn: redis.Redis) -> Optional[Dict]:
    """Validate API key"""
    if not credentials:
        return None
    
    # Hash the provided key
    key_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    
    # Check if key exists and is enabled
    key_data = api_keys_store.get(key_hash)
    if not key_data or not key_data.get("enabled", True):
        api_key_validations.labels(status="invalid").inc()
        return None
    
    # Check rate limit
    if not await check_rate_limit(key_data["id"], key_data["rate_limit"], redis_conn):
        api_key_validations.labels(status="rate_limited").inc()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded"
        )
    
    api_key_validations.labels(status="success").inc()
    return key_data


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        if redis_client:
            await redis_client.ping()
        return {"status": "healthy", "service": "auth"}
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "error": str(e)}
        )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/verify")
async def verify_request(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    redis_conn: redis.Redis = Depends(get_redis)
):
    """
    Verify API key for Traefik ForwardAuth
    Returns 200 if valid, 401 if invalid
    """
    with auth_duration.time():
        # Check for API key
        if not credentials:
            auth_requests.labels(method="api_key", status="missing").inc()
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)
        
        # Validate API key
        key_data = await validate_api_key(credentials, redis_conn)
        if not key_data:
            auth_requests.labels(method="api_key", status="invalid").inc()
            return Response(status_code=status.HTTP_401_UNAUTHORIZED)
        
        # Return success with headers for downstream service
        auth_requests.labels(method="api_key", status="success").inc()
        return Response(
            status_code=status.HTTP_200_OK,
            headers={
                "X-Api-Key-Id": key_data["id"],
                "X-Scopes": ",".join(key_data["scopes"]),
                "X-Rate-Limit": key_data["rate_limit"]
            }
        )


@app.post("/token")
async def login(username: str, password: str):
    """
    Login endpoint for playground access
    Returns JWT token for authenticated users
    """
    # Check admin credentials
    admin_password_hash = get_password_hash(ADMIN_PASSWORD)
    
    if username != ADMIN_USERNAME or not verify_password(password, admin_password_hash):
        auth_requests.labels(method="password", status="invalid").inc()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Create access token
    access_token = create_access_token(
        data={"sub": username, "scopes": ["playground", "admin"]}
    )
    
    auth_requests.labels(method="password", status="success").inc()
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


@app.get("/api-keys")
async def list_api_keys(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    List all API keys (admin only)
    """
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
    # Verify JWT token
    token_data = await verify_token(credentials.credentials)
    if not token_data or "admin" not in token_data.get("scopes", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Return API keys info (without actual keys)
    keys_info = []
    for key_hash, key_data in api_keys_store.items():
        keys_info.append({
            "id": key_data["id"],
            "name": key_data["name"],
            "rate_limit": key_data["rate_limit"],
            "scopes": key_data["scopes"],
            "enabled": key_data["enabled"]
        })
    
    return {"api_keys": keys_info}


@app.post("/api-keys/{key_id}/disable")
async def disable_api_key(
    key_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Disable an API key (admin only)
    """
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
    # Verify JWT token
    token_data = await verify_token(credentials.credentials)
    if not token_data or "admin" not in token_data.get("scopes", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Find and disable the key
    for key_hash, key_data in api_keys_store.items():
        if key_data["id"] == key_id:
            key_data["enabled"] = False
            return {"message": f"API key {key_id} disabled"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"API key {key_id} not found"
    )


@app.post("/api-keys/{key_id}/enable")
async def enable_api_key(
    key_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Enable an API key (admin only)
    """
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
    # Verify JWT token
    token_data = await verify_token(credentials.credentials)
    if not token_data or "admin" not in token_data.get("scopes", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Find and enable the key
    for key_hash, key_data in api_keys_store.items():
        if key_data["id"] == key_id:
            key_data["enabled"] = True
            return {"message": f"API key {key_id} enabled"}
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"API key {key_id} not found"
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)