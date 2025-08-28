FROM unclecode/crawl4ai:latest

# Install additional dependencies for authentication proxy
RUN pip install --no-cache-dir \
    httpx==0.27.2 \
    python-jose[cryptography]==3.3.0 \
    passlib[bcrypt]==1.7.4 \
    python-multipart==0.0.12 \
    && apt-get update \
    && apt-get install -y netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Copy authentication wrapper
COPY auth/auth_proxy.py /app/auth_proxy.py

# Create a simple startup script inline
RUN echo '#!/bin/bash\n\
set -e\n\
echo "Waiting for Redis..."\n\
while ! nc -z redis 6379; do\n\
  sleep 1\n\
done\n\
echo "Redis is ready!"\n\
echo "Waiting for Auth Service..."\n\
while ! curl -f http://auth-service:8000/health > /dev/null 2>&1; do\n\
  sleep 1\n\
done\n\
echo "Auth Service is ready!"\n\
if [ "${ENABLE_AUTH}" = "true" ]; then\n\
  echo "Starting Crawl4AI with authentication proxy..."\n\
  exec python /app/auth_proxy.py\n\
else\n\
  echo "Starting Crawl4AI without authentication..."\n\
  exec uvicorn main:app --host 0.0.0.0 --port 11235\n\
fi' > /app/start.sh && chmod +x /app/start.sh

ENTRYPOINT ["/app/start.sh"]