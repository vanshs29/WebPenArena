#!/bin/sh
set -e

mongod --bind_ip 127.0.0.1 --dbpath /data/db --fork --logpath /var/log/mongod.log

until mongosh --quiet --eval "db.runCommand({ ping: 1 })" > /dev/null 2>&1; do
  sleep 0.5
done

exec node dist/server.js
