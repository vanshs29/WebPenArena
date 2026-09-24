#!/bin/sh
set -e

export PGDATA=/var/lib/postgresql/data

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  mkdir -p "$PGDATA"
  chown -R postgres:postgres "$PGDATA"
  gosu postgres initdb -D "$PGDATA" >/tmp/initdb.log 2>&1
fi

chown -R postgres:postgres "$PGDATA"
gosu postgres pg_ctl -D "$PGDATA" -o "-c listen_addresses=127.0.0.1" -w start

until gosu postgres pg_isready -h 127.0.0.1 >/dev/null 2>&1; do
  sleep 0.2
done

gosu postgres psql -h 127.0.0.1 -tAc "SELECT 1 FROM pg_roles WHERE rolname='meridian'" | grep -q 1 \
  || gosu postgres psql -h 127.0.0.1 -c "CREATE ROLE meridian LOGIN PASSWORD 'meridian'"

gosu postgres psql -h 127.0.0.1 -tAc "SELECT 1 FROM pg_database WHERE datname='meridian'" | grep -q 1 \
  || gosu postgres psql -h 127.0.0.1 -c "CREATE DATABASE meridian OWNER meridian"

exec node run.js
