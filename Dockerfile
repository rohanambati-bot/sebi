# ─── SentinelSEBI Docker Multi-Stage Build ───────────────────
# Node 20 (API server) + Python 3.11 (ML microservice)
# Build: docker build -t sentinel-sebi .
# Run:   docker run -p 8000:8000 sentinel-sebi

FROM node:20-slim AS base

# Install Python 3 for ML microservice
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    ffmpeg \
    libgl1-mesa-glx libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files and install Node dependencies
COPY backend/package*.json ./backend/
RUN cd backend && npm ci --omit=dev

# Install Python ML dependencies
COPY backend/requirements.txt ./backend/
RUN cd backend && python3 -m pip install --break-system-packages --no-cache-dir -r requirements.txt 2>/dev/null || \
    echo "⚠ Some Python ML libraries could not be installed. JS fallbacks will be used."

# Copy application code
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY extension/ ./extension/

# Remove legacy Python files (they're moved to python_legacy/ already)
RUN rm -rf backend/python_legacy/

EXPOSE 8000

WORKDIR /app/backend

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8000/ml-status', r => { process.exit(r.statusCode === 200 ? 0 : 1) })" || exit 1

CMD ["npm", "start"]
