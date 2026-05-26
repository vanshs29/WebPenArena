FROM node:20-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY app.js run.js ./
COPY src/ ./src/

FROM node:20-slim
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/* && \
    npm install -g node-gyp
COPY package*.json ./
RUN npm ci --omit=dev && npm rebuild better-sqlite3
COPY --from=builder /app/node_modules/better-sqlite3/build ./node_modules/better-sqlite3/build
COPY app.js run.js ./
COPY src/ ./src/

ENV SCORE_TOKEN=""
EXPOSE 3000
CMD ["node", "run.js"]
