FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      postgresql postgresql-contrib gosu \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/lib/postgresql/15/bin:${PATH}"

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

COPY app/ ./app/
COPY graphql/ ./graphql/
COPY db/ ./db/
COPY run.js .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV SCORE_TOKEN=""
ENV PGDATA=/var/lib/postgresql/data
ENV DATABASE_URL="postgres://meridian:meridian@127.0.0.1:5432/meridian"
EXPOSE 5000

CMD ["/entrypoint.sh"]
