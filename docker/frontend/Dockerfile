# ==============================================================================
# Autonomous SOC Analyst — Production Frontend Dockerfile
# Multi-stage build: Node.js 18 compiler -> Lightweight Nginx Alpine server
# ==============================================================================

# --- Stage 1: Build Static Assets ---
FROM node:18-alpine AS builder

WORKDIR /app

# Install dependencies with frozen lockfile / caching
COPY frontend/package.json ./
RUN npm install

# Copy source code and build production bundle
COPY frontend/ ./
RUN npm run build


# --- Stage 2: Serve with Nginx Alpine ---
FROM nginx:1.25-alpine

# Copy custom Nginx configuration for Single-Page Application (SPA)
COPY <<'EOF' /etc/nginx/conf.d/default.conf
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # Gzip Compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml;

    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # SPA routing fallback
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(?:css|js|woff2?|svg|png|jpg|jpeg|gif|ico)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Copy compiled artifacts from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
