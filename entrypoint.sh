#!/bin/bash
set -e

# Wait for Redis to be ready
echo "Waiting for Redis..."
until nc -z redis 6379; do
  echo "Redis is unavailable - sleeping"
  sleep 1
done
echo "Redis is ready!"

# Wait for Auth Service to be ready
echo "Waiting for Auth Service..."
until curl -f http://auth-service:8000/health > /dev/null 2>&1; do
  echo "Auth Service is unavailable - sleeping"
  sleep 1
done
echo "Auth Service is ready!"

# Start the Crawl4AI service with auth proxy if AUTH is enabled
if [ "${ENABLE_AUTH}" = "true" ]; then
  echo "Starting Crawl4AI with authentication proxy..."
  exec python /app/auth_proxy.py
else
  echo "Starting Crawl4AI without authentication..."
  exec uvicorn main:app --host 0.0.0.0 --port 11235
fi