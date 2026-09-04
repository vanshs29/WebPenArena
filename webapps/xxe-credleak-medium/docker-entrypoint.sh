#!/bin/sh
set -e
mkdir -p /app/config /app/data
KEY=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
cat > /app/config/application.properties <<EOF
spring.application.name=Rosterly
server.port=5000
spring.datasource.url=jdbc:sqlite:/app/data/rosterly.db
internal.reports.api-key=$KEY
EOF
exec java -jar app.jar
