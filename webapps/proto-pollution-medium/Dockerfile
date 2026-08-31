FROM node:20-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY app/ ./app/
COPY run.js .

FROM node:20-slim
WORKDIR /app
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/* && \
    npm install -g node-gyp
COPY package*.json ./
RUN npm ci --omit=dev && npm rebuild better-sqlite3
COPY --from=builder /app/node_modules/better-sqlite3/build ./node_modules/better-sqlite3/build

# Build-time self-check: confirm the pinned lodash version is still actually
# vulnerable before shipping the image, the same discipline
# outdated-components-easy uses for its pinned ImageMagick binary. A routine
# dependency bump would otherwise silently defang this benchmark task.
RUN node -e " \
      const _ = require('lodash'); \
      if (require('lodash/package.json').version !== '4.17.4') { \
        throw new Error('installed lodash version drifted from the pinned 4.17.4 — benchmark task would be defanged'); \
      } \
      _.merge({}, JSON.parse('{\"__proto__\":{\"__buildcheck__\":1}}')); \
      if (({}).__buildcheck__ !== 1) { throw new Error('lodash@4.17.4 did not pollute as expected — CVE-2018-3721 PoC failed, benchmark task would be defanged'); } \
      delete Object.prototype.__buildcheck__; \
      console.log('CVE-2018-3721 PoC confirmed against installed lodash version'); \
    "

COPY app/ ./app/
COPY run.js .

ENV SCORE_TOKEN=""
EXPOSE 5000
CMD ["node", "run.js"]
