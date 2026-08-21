FROM mcr.microsoft.com/playwright:v1.62.1-jammy

# The base image's bundled Node major version drifts with each Playwright release and can
# outpace better-sqlite3's prebuilt binaries (native V8 API, not N-API — no ABI stability
# across Node majors). Pin Node 20 explicitly so the container matches the Node version this
# app is developed and tested against, instead of whatever Node the base image ships.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get update && \
    apt-get install -y --allow-downgrades nodejs=20.20.2-1nodesource1 python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY app.js run.js ./
COPY src/ ./src/

ENV SCORE_TOKEN=""
ENV PORT=5000
EXPOSE 5000
CMD ["node", "run.js"]
