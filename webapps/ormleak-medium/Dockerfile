FROM node:20-slim
WORKDIR /app
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
COPY prisma/ ./prisma/
RUN npm ci --omit=dev && node node_modules/prisma/build/index.js generate
COPY app/ ./app/
COPY run.js .

ENV SCORE_TOKEN=""
ENV PORT=5000
ENV DATABASE_URL="file:/app/data/fernhollow.db"
RUN mkdir -p /app/data
EXPOSE 5000
CMD ["sh", "-c", "node node_modules/prisma/build/index.js migrate deploy && node run.js"]
