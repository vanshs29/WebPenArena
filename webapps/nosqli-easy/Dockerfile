FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends gnupg curl ca-certificates \
    && curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg] http://repo.mongodb.org/apt/debian bookworm/mongodb-org/7.0 main" > /etc/apt/sources.list.d/mongodb-org-7.0.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends mongodb-org \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/db

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY views ./views
RUN npm run build

ENV SCORE_TOKEN=""
ENV MONGO_URI="mongodb://127.0.0.1:27017/quickpoll"
ENV SQLITE_PATH="/app/data/scoring.db"
ENV PORT=5000
EXPOSE 5000

RUN mkdir -p /app/data
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
