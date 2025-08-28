# Dokploy Environment Variables Setup

## ⚠️ Important Notes for Dokploy

Dokploy's Docker Compose parser has specific requirements for environment variables:

1. **No special characters in passwords**: Avoid `&`, `@`, `!`, `$` in passwords
2. **Single-line JSON**: Multi-line JSON breaks the parser
3. **Escape dollar signs**: Use `$$` instead of `$` for bcrypt hashes

## Fixed Environment Variables

Copy these exact values to your Dokploy environment settings:

```bash
# Domain Configuration
DOMAIN=crawl.betlandpro.com

# Security Keys
JWT_SECRET_KEY=BAwguy9wo2ACJ_Ylph3X8RT5mHU9nzoaxyf1JemDUeDlijUHW8nrbxCR1rVEFKfe1l5JJRKY6MOlhHPnzbX5Iw
REDIS_PASSWORD=tRRxev29G0SLdfoaMYsReK

# Admin credentials (simplified password without special chars)
ADMIN_USERNAME=kenan
ADMIN_PASSWORD=M0rt3z2264

# Playground Basic Auth (with escaped dollars)
PLAYGROUND_AUTH=kenan:$$2y$$05$$e04KxKGnzLl.yysALc1Rqe8Ywup7.g6b3XGyfsGnsf4zflSbtCP5G

# API Keys Configuration (single line)
API_KEYS_CONFIG={"prod-001":{"name":"Production Key 1","key":"sk-prod-a3R05rgDpLGeTihjW3ZTw1X6PKEgoChV","rate_limit":"1000/minute","scopes":["crawl","screenshot","pdf","md"],"enabled":true},"prod-002":{"name":"Production Key 2","key":"sk-prod-AxDbldAhhIb6na3IB6kCJxWb0YuWtZUy","rate_limit":"1000/minute","scopes":["crawl","screenshot","pdf","md"],"enabled":true}}

# Resource Limits
MEMORY_LIMIT=2G
CPU_LIMIT=2
MAX_CONCURRENT_CRAWLS=4

# Logging
LOG_LEVEL=INFO
```

## How to Add in Dokploy

1. Go to your Docker Compose project in Dokploy
2. Click on "Environment" tab
3. Add each variable one by one (or use bulk import if available)
4. Save the configuration
5. Redeploy the project

## Your API Keys

Save these securely:

```
API Key 1: sk-prod-a3R05rgDpLGeTihjW3ZTw1X6PKEgoChV
API Key 2: sk-prod-AxDbldAhhIb6na3IB6kCJxWb0YuWtZUy
```

## Playground Access

```
URL: https://crawl.betlandpro.com/playground
Username: kenan
Password: M0rt3z2264
```

## Testing API Access

```bash
# Test with curl
curl -X POST "https://crawl.betlandpro.com/crawl" \
  -H "Authorization: Bearer sk-prod-a3R05rgDpLGeTihjW3ZTw1X6PKEgoChV" \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://example.com"],"browser_config":{"type":"BrowserConfig","params":{"headless":true}},"crawler_config":{"type":"CrawlerRunConfig","params":{"cache_mode":"bypass"}}}'
```

## Troubleshooting

If you still get parsing errors:

1. **Check for hidden characters**: Copy-paste might introduce invisible characters
2. **Validate JSON**: Use `echo $API_KEYS_CONFIG | jq .` to validate
3. **Use Dokploy's text editor**: Paste directly into Dokploy's environment editor
4. **Alternative**: Store API keys in a mounted file instead of environment variable

## Alternative: File-based Configuration

If environment variables continue to cause issues, create a mounted file:

1. In Dokploy, go to "Mounts" 
2. Create a file mount: `/config/api_keys.json`
3. Add the JSON configuration there
4. Update `auth_service.py` to read from file instead of environment