# Crawl4AI Dokploy Deployment Guide

## Pre-Deployment Checklist

- [ ] Dokploy instance running with Traefik
- [ ] Domain DNS configured (A record pointing to server)
- [ ] Python 3.8+ installed locally for setup scripts
- [ ] Access to Dokploy dashboard

## Step-by-Step Deployment

### Step 1: Prepare Configuration

```bash
# Generate secrets and configuration
python scripts/generate_secrets.py

# You'll be prompted for:
# - Domain name (e.g., crawl4ai.yourdomain.com)
# - Admin username/password
# - Number of API keys to generate
# - Resource limits
```

### Step 2: Configure LLM Providers

```bash
# Copy template
cp .llm.env.example .llm.env

# Edit with your API keys
nano .llm.env
```

Required keys (at least one):
- `OPENAI_API_KEY` for OpenAI GPT models
- `ANTHROPIC_API_KEY` for Claude models
- `GEMINI_API_TOKEN` for Google Gemini
- `GROQ_API_KEY` for Groq

### Step 3: Deploy in Dokploy

1. **Login to Dokploy Dashboard**

2. **Create New Docker Compose Project**
   - Click "Create Project"
   - Select "Docker Compose"
   - Name: "crawl4ai-production"

3. **Upload Configuration**
   - Copy contents of `docker-compose.yml`
   - Paste into Dokploy editor

4. **Add Environment Variables**
   - Go to "Environment" tab
   - Add all variables from `.env` file
   - Add all variables from `.llm.env` file

5. **Configure Domain**
   - Go to "Domains" tab
   - Click "Add Domain"
   - Enter your domain (must match DOMAIN in .env)
   - Enable HTTPS
   - Select "Let's Encrypt" for certificate

6. **Deploy**
   - Click "Deploy" button
   - Wait for all services to start (3-5 minutes)

### Step 4: Verify Deployment

```bash
# Check service health
curl https://your-domain.com/health

# Test with provided script
python scripts/test_deployment.py your-domain.com
```

Expected output:
```
✅ Health check passed
✅ API authentication successful
✅ Playground authentication successful
✅ Successfully crawled: https://httpbin.org/html
✅ All tests passed successfully!
```

### Step 5: Test API Access

Using curl:
```bash
# Replace with your API key
API_KEY="sk-prod-xxxxxxxx"
DOMAIN="your-domain.com"

curl -X POST "https://${DOMAIN}/crawl" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://example.com"],
    "browser_config": {"type": "BrowserConfig", "params": {"headless": true}},
    "crawler_config": {"type": "CrawlerRunConfig", "params": {"cache_mode": "bypass"}}
  }'
```

Using Python:
```python
import httpx

api_key = "sk-prod-xxxxxxxx"
base_url = "https://your-domain.com"

client = httpx.Client()
response = client.post(
    f"{base_url}/crawl",
    json={
        "urls": ["https://example.com"],
        "browser_config": {"type": "BrowserConfig", "params": {"headless": True}},
        "crawler_config": {"type": "CrawlerRunConfig", "params": {"cache_mode": "bypass"}}
    },
    headers={"Authorization": f"Bearer {api_key}"}
)

print(response.json())
```

### Step 6: Access Playground

1. Navigate to: `https://your-domain.com/playground`
2. Enter admin credentials when prompted
3. Test crawling functionality

## Post-Deployment

### Monitor Services

In Dokploy Dashboard:
- Check "Logs" tab for real-time logs
- Monitor "Resources" for CPU/Memory usage
- Review "Deployments" history

### View Metrics

```bash
# Prometheus metrics
curl https://your-domain.com/metrics

# Parse specific metrics
curl -s https://your-domain.com/metrics | grep auth_requests_total
```

### Check Rate Limiting

```bash
# View current rate limit counters
docker exec -it redis redis-cli
> KEYS rate_limit:*
> GET rate_limit:prod-001:12345
```

## Troubleshooting

### Service Not Starting

1. Check logs in Dokploy:
   ```
   Logs → Select Service → View recent logs
   ```

2. Common issues:
   - Redis password mismatch
   - Missing environment variables
   - Port conflicts

### Authentication Failures

1. Verify API key format:
   ```bash
   echo $API_KEYS_CONFIG | jq .
   ```

2. Check auth service:
   ```bash
   curl https://your-domain.com/auth/health
   ```

### SSL Certificate Issues

1. Verify DNS:
   ```bash
   nslookup your-domain.com
   ```

2. Check Traefik:
   - In Dokploy, go to Traefik dashboard
   - Verify certificate is issued

### Performance Issues

1. Increase resources:
   ```yaml
   # Edit in Dokploy environment
   MEMORY_LIMIT=16G
   CPU_LIMIT=8
   MAX_CONCURRENT_CRAWLS=20
   ```

2. Check Redis memory:
   ```bash
   docker exec redis redis-cli INFO memory
   ```

## Maintenance Tasks

### Daily
- [ ] Check health endpoints
- [ ] Review error logs
- [ ] Monitor rate limit violations

### Weekly
- [ ] Review metrics and performance
- [ ] Check disk usage
- [ ] Verify backup completion

### Monthly
- [ ] Rotate API keys
- [ ] Update Docker images
- [ ] Review security logs
- [ ] Test disaster recovery

## Updating

### Update Crawl4AI

1. In Dokploy Dashboard:
   - Go to your project
   - Click "Rebuild"
   - Click "Deploy"

2. Or via Docker:
   ```bash
   docker-compose pull crawl4ai
   docker-compose up -d crawl4ai
   ```

### Update Configuration

1. Edit environment variables in Dokploy
2. Click "Save"
3. Click "Restart" for the affected service

## Backup and Recovery

### Backup Configuration

```bash
# Backup all config
tar -czf crawl4ai-backup-$(date +%Y%m%d).tar.gz \
  .env .llm.env config/ api_keys.json

# Store securely (e.g., encrypted S3)
```

### Backup Redis Data

```bash
# Create Redis backup
docker exec redis redis-cli --rdb /data/backup.rdb

# Copy backup
docker cp redis:/data/backup.rdb ./redis-backup-$(date +%Y%m%d).rdb
```

### Restore Process

1. Stop services in Dokploy
2. Restore configuration files
3. Import Redis data:
   ```bash
   docker cp backup.rdb redis:/data/dump.rdb
   docker restart redis
   ```
4. Restart services in Dokploy

## Security Considerations

### API Key Security
- Store keys in password manager
- Rotate every 90 days
- Monitor usage patterns
- Disable unused keys

### Network Security
- Use Dokploy's firewall rules
- Restrict admin access by IP
- Enable rate limiting
- Monitor for abuse

### Data Protection
- Encrypt backups
- Use secure channels for API
- Implement data retention policies
- Regular security audits

## Support Resources

- **Crawl4AI Documentation**: https://docs.crawl4ai.com
- **Dokploy Documentation**: https://docs.dokploy.com
- **GitHub Issues**: https://github.com/unclecode/crawl4ai/issues
- **Discord Community**: https://discord.gg/crawl4ai

---

Last Updated: 2024
Version: 1.0.0