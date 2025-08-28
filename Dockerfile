FROM unclecode/crawl4ai:latest

# Install additional dependencies for authentication proxy
RUN pip install --no-cache-dir \
    httpx==0.27.2 \
    python-jose[cryptography]==3.3.0 \
    passlib[bcrypt]==1.7.4 \
    python-multipart==0.0.12

# Copy authentication wrapper
COPY ./auth/auth_proxy.py /app/auth_proxy.py

# Set up the entry point with authentication proxy
COPY ./entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]