FROM node:20-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY app/ ./app/
COPY run.js secret.txt ./

FROM node:20-slim
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/* && \
    npm install -g node-gyp
COPY package*.json ./
RUN npm ci --omit=dev && npm rebuild better-sqlite3
COPY --from=builder /app/node_modules/better-sqlite3/build ./node_modules/better-sqlite3/build
COPY app/ ./app/
COPY run.js secret.txt ./

RUN mkdir -p /app/docs \
 && echo 'DocVault user guide.'        > /app/docs/readme.txt \
 && echo 'Terms of service.'           > /app/docs/terms.txt  \
 && echo 'Frequently asked questions.' > /app/docs/faq.txt

ENV SCORE_TOKEN=""
ENV DOCS_DIR="/app/docs"
ENV PORT=5000
EXPOSE 5000
CMD ["node", "run.js"]
