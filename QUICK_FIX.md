# Quick Fix for Dokploy Deployment

## Current Issues Fixed

1. ✅ **Environment variable parsing errors** - Fixed by:
   - Removing special characters from passwords
   - Converting JSON to single line
   - Escaping dollar signs in bcrypt hash

2. ✅ **Build errors** - Fixed by:
   - Using simpler Dockerfile without external scripts
   - Embedding startup script directly in Dockerfile
   - Removing dependency on auth proxy (Traefik handles auth)

## Deployment Steps

### Option 1: Simplified Deployment (Recommended)

Use the `Dockerfile.simple` which:
- Uses base Crawl4AI image
- Waits for Redis to be ready
- Starts service directly
- No auth proxy needed (Traefik handles authentication)

### Option 2: Add LLM Keys in Dokploy

In Dokploy environment variables, add:
```
OPENAI_API_KEY=your-key-here
ANTHROPIC_API_KEY=your-key-here
GEMINI_API_TOKEN=your-key-here
GROQ_API_KEY=your-key-here
```

### Option 3: Manual File Mount

If LLM env file issues persist:
1. In Dokploy, create a file mount
2. Path: `/app/.llm.env`
3. Add content:
```
OPENAI_API_KEY=your-key
ANTHROPIC_API_KEY=your-key
```

## Current Working Configuration

```yaml
services:
  redis:
    image: redis:7-alpine
    # Redis with password, works fine
  
  auth-service:
    # Handles API key validation
    # Works with single-line JSON config
  
  crawl4ai:
    build:
      dockerfile: Dockerfile.simple  # Simplified version
    # Authentication handled by Traefik labels
```

## Test Commands

### Health Check
```bash
curl https://crawl.betlandpro.com/health
```

### API Test (with your key)
```bash
curl -X POST "https://crawl.betlandpro.com/crawl" \
  -H "Authorization: Bearer sk-prod-a3R05rgDpLGeTihjW3ZTw1X6PKEgoChV" \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://example.com"]}'
```

### Playground Access
```
URL: https://crawl.betlandpro.com/playground
Username: kenan
Password: M0rt3z2264
```

## If Still Having Issues

1. **Check Dokploy logs** for specific error messages
2. **Verify network**: Ensure `dokploy-network` exists
3. **Check Traefik**: Verify domain is correctly configured
4. **Test locally first**: 
   ```bash
   docker-compose up -d
   ```

## Minimal Test Setup

For testing, you can disable auth temporarily:
```yaml
environment:
  - ENABLE_AUTH=false
```

Then remove auth middlewares from Traefik labels.