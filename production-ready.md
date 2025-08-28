# Secure Crawl4AI Production Deployment

## Project Structure

```
crawl4ai-production/
├── docker-compose.yml
├── .env
├── .llm.env
├── config/
│   ├── crawl4ai-config.yml
│   └── nginx.conf
├── auth/
│   ├── auth_middleware.py
│   └── requirements.txt
├── scripts/
│   └── generate_secrets.py
└── ssl/
    ├── cert.pem
    └── key.pem
```

## 1. Docker Compose Configuration

### `docker-compose.yml`

```yaml
version: "3.8"

services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    networks:
      - crawl4ai-network

  crawl4ai:
    build:
      context: .
      dockerfile: Dockerfile.custom
    restart: unless-stopped
    environment:
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - API_KEY_SALT=${API_KEY_SALT}
      - ENABLE_AUTH=true
    env_file:
      - .llm.env
    volumes:
      - ./config/crawl4ai-config.yml:/app/config.yml:ro
      - ./auth:/app/auth:ro
    shm_size: 2g
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: "4"
    networks:
      - crawl4ai-network
    depends_on:
      - redis

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./config/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    networks:
      - crawl4ai-network
    depends_on:
      - crawl4ai
      - auth-service

  auth-service:
    build:
      context: ./auth
      dockerfile: Dockerfile
    restart: unless-stopped
    environment:
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
      - ADMIN_USERNAME=${ADMIN_USERNAME}
      - ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
      - API_KEYS=${API_KEYS}
    networks:
      - crawl4ai-network
    depends_on:
      - redis

networks:
  crawl4ai-network:
    driver: bridge

volumes:
  redis-data:
```

## 2. Custom Dockerfile with Authentication

### `Dockerfile.custom`

```dockerfile
FROM unclecode/crawl4ai:latest

# Install additional dependencies for authentication
RUN pip install --no-cache-dir \
    python-jose[cryptography]==3.3.0 \
    passlib[bcrypt]==1.7.4 \
    python-multipart==0.0.6 \
    redis==5.0.1 \
    argon2-cffi==23.1.0

# Copy custom authentication middleware
COPY ./auth/auth_middleware.py /app/auth_middleware.py

# Override the main application with auth wrapper
COPY ./auth/secure_app.py /app/secure_app.py

# Use the secure app as entrypoint
CMD ["uvicorn", "secure_app:app", "--host", "0.0.0.0", "--port", "11235"]
```

## 3. Authentication Middleware

### `auth/auth_middleware.py`

```python
import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.hash import argon2
import redis
import json

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
API_KEY_SALT = os.getenv("API_KEY_SALT").encode()

# Redis client for session management
redis_client = redis.from_url(os.getenv("REDIS_URL"))

# Security schemes
api_key_scheme = HTTPBearer()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

class AuthenticationService:
    def __init__(self):
        self.api_keys = self._load_api_keys()
        self.users = self._load_users()

    def _load_api_keys(self) -> Dict[str, Dict]:
        """Load API keys from environment or database"""
        api_keys_json = os.getenv("API_KEYS", "{}")
        keys = json.loads(api_keys_json)

        # Hash API keys for secure storage
        hashed_keys = {}
        for key_id, key_data in keys.items():
            hashed_key = hashlib.sha256(
                key_data["key"].encode() + API_KEY_SALT
            ).hexdigest()
            hashed_keys[hashed_key] = {
                "id": key_id,
                "name": key_data.get("name", "Unknown"),
                "rate_limit": key_data.get("rate_limit", "100/minute"),
                "scopes": key_data.get("scopes", ["crawl"])
            }
        return hashed_keys

    def _load_users(self) -> Dict[str, Dict]:
        """Load users for Playground access"""
        users = {}

        # Load admin user from environment
        admin_username = os.getenv("ADMIN_USERNAME")
        admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH")

        if admin_username and admin_password_hash:
            users[admin_username] = {
                "username": admin_username,
                "password_hash": admin_password_hash,
                "roles": ["admin", "playground"]
            }

        return users

    def verify_api_key(self, credentials: HTTPAuthorizationCredentials) -> Dict:
        """Verify API key for API endpoints"""
        key = credentials.credentials
        hashed_key = hashlib.sha256(key.encode() + API_KEY_SALT).hexdigest()

        if hashed_key not in self.api_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )

        key_data = self.api_keys[hashed_key]

        # Check rate limiting
        if not self._check_rate_limit(key_data["id"], key_data["rate_limit"]):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )

        return key_data

    def verify_user_password(self, username: str, password: str) -> Optional[Dict]:
        """Verify username and password for Playground access"""
        user = self.users.get(username)
        if not user:
            return None

        if not argon2.verify(password, user["password_hash"]):
            return None

        return user

    def create_access_token(self, data: dict) -> str:
        """Create JWT token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        # Store session in Redis
        session_id = secrets.token_urlsafe(32)
        redis_client.setex(
            f"session:{session_id}",
            JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            json.dumps(data)
        )

        return encoded_jwt

    def verify_token(self, token: str) -> Dict:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials"
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )

    def _check_rate_limit(self, key_id: str, limit: str) -> bool:
        """Check rate limiting using Redis"""
        # Parse limit (e.g., "100/minute")
        count, period = limit.split("/")
        count = int(count)

        period_seconds = {
            "second": 1,
            "minute": 60,
            "hour": 3600,
            "day": 86400
        }.get(period, 60)

        key = f"rate_limit:{key_id}:{int(datetime.utcnow().timestamp()) // period_seconds}"

        current = redis_client.incr(key)
        if current == 1:
            redis_client.expire(key, period_seconds)

        return current <= count

# Singleton instance
auth_service = AuthenticationService()

# Dependency functions
async def get_api_key(credentials: HTTPAuthorizationCredentials = Security(api_key_scheme)) -> Dict:
    """Dependency for API key authentication"""
    return auth_service.verify_api_key(credentials)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    """Dependency for JWT authentication"""
    return auth_service.verify_token(token)
```

## 4. Secure FastAPI Application Wrapper

### `auth/secure_app.py`

```python
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn
from auth_middleware import auth_service, get_api_key, get_current_user

# Import the original Crawl4AI app
import sys
sys.path.append('/app')
from main import app as crawl4ai_app

# Create secure wrapper app
app = FastAPI(title="Secure Crawl4AI API", version="1.0.0")

# Authentication endpoints
@app.post("/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login endpoint for Playground access"""
    user = auth_service.verify_user_password(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = auth_service.create_access_token(data={"sub": user["username"], "roles": user["roles"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/api-key/validate")
async def validate_api_key(key_data: Dict = Depends(get_api_key)):
    """Validate API key endpoint"""
    return {"valid": True, "key_id": key_data["id"], "scopes": key_data["scopes"]}

# Security middleware
class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Public endpoints (health, metrics, auth)
        public_paths = ["/health", "/metrics", "/auth/token", "/docs", "/openapi.json"]
        if any(path.startswith(p) for p in public_paths):
            return await call_next(request)

        # Playground requires JWT authentication
        if path.startswith("/playground"):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Playground requires authentication"}
                )

            token = auth_header.split(" ")[1]
            try:
                user = auth_service.verify_token(token)
                if "playground" not in user.get("roles", []):
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "Insufficient permissions for Playground"}
                    )
            except:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid authentication"}
                )

        # API endpoints require API key
        elif path.startswith("/crawl") or path.startswith("/api"):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "API key required"}
                )

            try:
                key = auth_header.split(" ")[1]
                auth_service.verify_api_key(type('obj', (object,), {'credentials': key})())
            except:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid API key"}
                )

        # Security headers
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response

# Add middleware
app.add_middleware(SecurityMiddleware)

# Mount the original Crawl4AI app
app.mount("/", crawl4ai_app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=11235)
```

## 5. Environment Configuration

### `.env`

```bash
# Security Keys (generate these using the script below)
JWT_SECRET_KEY=your-generated-jwt-secret-key-here
API_KEY_SALT=your-generated-api-key-salt-here
REDIS_PASSWORD=your-strong-redis-password-here

# Admin credentials for Playground
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=$argon2id$v=19$m=65536,t=3,p=4$...

# API Keys configuration (JSON format)
API_KEYS='{
  "key1": {
    "key": "sk-prod-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "name": "Production API Key",
    "rate_limit": "1000/minute",
    "scopes": ["crawl", "screenshot", "pdf"]
  },
  "key2": {
    "key": "sk-dev-yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
    "name": "Development API Key",
    "rate_limit": "100/minute",
    "scopes": ["crawl"]
  }
}'
```

### `.llm.env`

```bash
# LLM API Keys
OPENAI_API_KEY=sk-your-openai-key
ANTHROPIC_API_KEY=your-anthropic-key
GROQ_API_KEY=your-groq-key
GEMINI_API_TOKEN=your-gemini-token
```

## 6. Nginx Configuration

### `config/nginx.conf`

```nginx
events {
    worker_connections 1024;
}

http {
    upstream crawl4ai {
        server crawl4ai:11235;
    }

    upstream auth_service {
        server auth-service:8000;
    }

    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=playground_limit:10m rate=5r/s;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

        # API endpoints with rate limiting
        location /crawl {
            limit_req zone=api_limit burst=20 nodelay;

            # Check API key
            if ($http_authorization = "") {
                return 401 '{"detail": "API key required"}';
            }

            proxy_pass http://crawl4ai;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # Timeouts for long-running crawls
            proxy_read_timeout 300s;
            proxy_connect_timeout 75s;
        }

        # Playground with authentication
        location /playground {
            limit_req zone=playground_limit burst=10 nodelay;

            # First check authentication
            auth_request /auth/verify;
            auth_request_set $auth_status $upstream_status;

            # If not authenticated, redirect to login
            error_page 401 = @login_redirect;

            proxy_pass http://crawl4ai;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Authentication verification endpoint
        location = /auth/verify {
            internal;
            proxy_pass http://auth_service/auth/verify;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Original-Method $request_method;
        }

        # Login redirect
        location @login_redirect {
            return 302 /auth/login?redirect=$request_uri;
        }

        # Authentication endpoints
        location /auth {
            proxy_pass http://auth_service;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            proxy_pass http://crawl4ai;
            access_log off;
        }

        # Metrics (restricted to internal)
        location /metrics {
            allow 10.0.0.0/8;
            deny all;
            proxy_pass http://crawl4ai;
        }
    }
}
```

## 7. Security Configuration

### `config/crawl4ai-config.yml`

```yaml
app:
  title: "Secure Crawl4AI API"
  version: "1.0.0"
  host: "0.0.0.0"
  port: 11235
  timeout_keep_alive: 120
  reload: false # Disable reload in production

security:
  enabled: true
  jwt_enabled: true
  trusted_hosts: ["your-domain.com"]
  cors:
    enabled: true
    origins: ["https://your-domain.com"]
    methods: ["GET", "POST"]
    headers: ["Authorization", "Content-Type"]

rate_limiting:
  enabled: true
  storage_uri: "redis://redis:6379"
  default_limit: "100/minute"

crawler:
  memory_threshold_percent: 90.0
  max_concurrent_requests: 10
  pool:
    max_pages: 40
    idle_ttl_sec: 1800
  timeouts:
    page_load: 30.0
    request: 60.0

logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "/var/log/crawl4ai/app.log"
  max_bytes: 10485760
  backup_count: 5
```

## 8. Helper Scripts

### `scripts/generate_secrets.py`

```python
#!/usr/bin/env python3
import secrets
import argon2
import json
import base64

def generate_jwt_secret():
    """Generate a secure JWT secret key"""
    return secrets.token_urlsafe(64)

def generate_api_key_salt():
    """Generate a secure salt for API key hashing"""
    return secrets.token_hex(32)

def generate_api_key():
    """Generate a secure API key"""
    return f"sk-prod-{secrets.token_urlsafe(32)}"

def hash_password(password):
    """Hash a password using Argon2"""
    ph = argon2.PasswordHasher()
    return ph.hash(password)

def generate_env_file():
    """Generate a complete .env file with secure values"""

    jwt_secret = generate_jwt_secret()
    api_salt = generate_api_key_salt()
    redis_password = secrets.token_urlsafe(32)

    # Get admin password
    admin_password = input("Enter admin password for Playground: ")
    admin_hash = hash_password(admin_password)

    # Generate API keys
    api_keys = {}
    num_keys = int(input("How many API keys to generate? "))

    for i in range(num_keys):
        key_name = input(f"Enter name for API key {i+1}: ")
        key = generate_api_key()
        api_keys[f"key{i+1}"] = {
            "key": key,
            "name": key_name,
            "rate_limit": "1000/minute",
            "scopes": ["crawl", "screenshot", "pdf"]
        }
        print(f"Generated API key for {key_name}: {key}")

    # Write .env file
    with open('.env', 'w') as f:
        f.write(f"# Generated Security Configuration\n")
        f.write(f"JWT_SECRET_KEY={jwt_secret}\n")
        f.write(f"API_KEY_SALT={api_salt}\n")
        f.write(f"REDIS_PASSWORD={redis_password}\n")
        f.write(f"\n# Admin Credentials\n")
        f.write(f"ADMIN_USERNAME=admin\n")
        f.write(f"ADMIN_PASSWORD_HASH={admin_hash}\n")
        f.write(f"\n# API Keys\n")
        f.write(f"API_KEYS='{json.dumps(api_keys)}'\n")

    print("\n✅ .env file generated successfully!")
    print("⚠️  Keep this file secure and never commit it to version control")

if __name__ == "__main__":
    generate_env_file()
```

## 9. Deployment Steps

### Step 1: Generate SSL Certificates

```bash
# For production, use Let's Encrypt
sudo apt-get install certbot
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem ssl/key.pem

# For testing, generate self-signed certificates
openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes
```

### Step 2: Generate Security Keys

```bash
# Run the script to generate secure keys and passwords
python scripts/generate_secrets.py
```

### Step 3: Configure LLM Keys

```bash
# Edit .llm.env with your actual LLM API keys
nano .llm.env
```

### Step 4: Build and Deploy

```bash
# Build custom images
docker-compose build

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f

# Verify health
curl https://your-domain.com/health
```

## 10. Usage Examples

### Using API with API Key

```python
import requests

API_KEY = "sk-prod-your-api-key-here"
BASE_URL = "https://your-domain.com"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Basic crawl
payload = {
    "urls": ["https://example.com"],
    "browser_config": {"type": "BrowserConfig", "params": {"headless": True}},
    "crawler_config": {"type": "CrawlerRunConfig", "params": {"cache_mode": "bypass"}}
}

response = requests.post(f"{BASE_URL}/crawl", json=payload, headers=headers)
print(response.json())
```

### Accessing Playground with Username/Password

```python
import requests

# Login to get JWT token
login_data = {
    "username": "admin",
    "password": "your-admin-password",
    "grant_type": "password"
}

response = requests.post(
    "https://your-domain.com/auth/token",
    data=login_data
)

token = response.json()["access_token"]

# Access playground with token
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(
    "https://your-domain.com/playground",
    headers=headers
)
```

## 11. Monitoring and Maintenance

### Health Checks

```bash
# Check service health
curl https://your-domain.com/health

# View metrics (internal only)
curl http://localhost/metrics

# Check Redis
docker-compose exec redis redis-cli -a $REDIS_PASSWORD ping
```

### Log Management

```bash
# View logs
docker-compose logs -f crawl4ai

# Rotate logs
docker-compose exec crawl4ai logrotate /etc/logrotate.conf

# Export logs
docker-compose logs --since 24h > logs_backup.txt
```

### Backup API Keys and Configuration

```bash
# Backup configuration
tar -czf config_backup.tar.gz config/ .env .llm.env

# Backup Redis data
docker-compose exec redis redis-cli -a $REDIS_PASSWORD --rdb /data/backup.rdb
```

## 12. Security Best Practices

1. **Regular Updates**: Keep all Docker images updated

   ```bash
   docker-compose pull
   docker-compose up -d
   ```

2. **Key Rotation**: Rotate API keys regularly

   ```bash
   python scripts/generate_secrets.py
   docker-compose restart
   ```

3. **Monitor Rate Limits**: Check Redis for rate limit violations

   ```bash
   docker-compose exec redis redis-cli -a $REDIS_PASSWORD
   KEYS rate_limit:*
   ```

4. **Audit Logs**: Regularly review access logs

   ```bash
   docker-compose logs crawl4ai | grep "401\|403\|429"
   ```

5. **Network Security**: Use firewall rules
   ```bash
   # Allow only HTTPS
   sudo ufw allow 443/tcp
   sudo ufw deny 11235/tcp
   ```

## Troubleshooting

### Common Issues

1. **API Key Not Working**

   - Verify the key format in .env
   - Check Redis connectivity
   - Review auth-service logs

2. **Playground Access Denied**

   - Verify JWT token is valid
   - Check user roles include "playground"
   - Ensure cookies are enabled

3. **Rate Limiting Issues**

   - Adjust limits in config
   - Clear Redis rate limit keys
   - Check client retry logic

4. **SSL Certificate Issues**
   - Verify certificate paths
   - Check certificate expiration
   - Ensure proper permissions

This deployment provides enterprise-grade security with proper authentication, rate limiting, and monitoring while avoiding the use of `.passwd` files as requested.
