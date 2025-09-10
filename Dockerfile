# Multi-stage Dockerfile for Secure Code Analyzer
# Production-ready with security hardening

# Build stage
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git \
    curl

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (including dev dependencies for build)
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Create non-root user for build
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Production stage  
FROM node:18-alpine AS production

# Security: Install security updates and necessary packages only
RUN apk update && apk upgrade && \
    apk add --no-cache \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S secure-analyzer -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Copy application files from builder
COPY --from=builder --chown=secure-analyzer:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=secure-analyzer:nodejs /app/src ./src
COPY --from=builder --chown=secure-analyzer:nodejs /app/dashboard ./dashboard
COPY --from=builder --chown=secure-analyzer:nodejs /app/package.json ./package.json

# Create required directories with proper permissions
RUN mkdir -p /app/logs /app/reports /app/temp && \
    chown -R secure-analyzer:nodejs /app

# Security: Remove unnecessary packages and files
RUN rm -rf /tmp/* /var/tmp/* /root/.npm

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Security: Run as non-root user
USER secure-analyzer

# Expose ports
EXPOSE 3000 8080

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV LOG_LEVEL=info

# Use dumb-init as PID 1 to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "src/app.js"]

# Labels for metadata
LABEL maintainer="DevSecOps Team <security@company.com>"
LABEL version="1.0.0"
LABEL description="Secure Code Analyzer - DevSecOps Integration Platform"
LABEL org.label-schema.name="secure-code-analyzer"
LABEL org.label-schema.description="Enterprise DevSecOps security scanning and analysis platform"
LABEL org.label-schema.version="1.0.0"
LABEL org.label-schema.schema-version="1.0"