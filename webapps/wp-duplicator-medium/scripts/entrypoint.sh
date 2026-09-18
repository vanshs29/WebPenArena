#!/bin/bash
# Container entrypoint for Larkspur (wp-duplicator-medium): brings up MariaDB
# and WordPress inside a single container, then execs the original image's
# apache2-foreground (passed in as "$@" via the Dockerfile's CMD) as PID 1.
#
# Ordering note (see PLAN.md 9, architecture decision 10): the MariaDB
# trigger on wp_users cannot be created until wp_users itself exists, so
# seed.sh (which runs `wp core install` first) owns creating that trigger --
# this script only creates the empty database/user WordPress installs into.
set -euo pipefail

STATE_DIR="${LARK_STATE_DIR:-/opt/wp-duplicator/state}"
DB_DATADIR=/var/lib/mysql
DB_SOCKET=/run/mysqld/mysqld.sock
WP_PATH=/var/www/html
WP_CLI="php /vendor/wp-cli.phar --allow-root --path=$WP_PATH"

mkdir -p /run/mysqld "$STATE_DIR"
chown -R mysql:mysql /run/mysqld

if [ ! -d "$DB_DATADIR/mysql" ]; then
  echo "entrypoint.sh: initializing MariaDB data directory"
  mariadb-install-db --user=mysql --datadir="$DB_DATADIR" >/dev/null
fi

echo "entrypoint.sh: starting mariadbd"
mariadbd --user=mysql --datadir="$DB_DATADIR" --socket="$DB_SOCKET" --bind-address=127.0.0.1 &

for i in $(seq 1 60); do
  if mysqladmin --socket="$DB_SOCKET" ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! mysqladmin --socket="$DB_SOCKET" ping >/dev/null 2>&1; then
  echo "entrypoint.sh: mariadbd did not become ready in time" >&2
  exit 1
fi

if [ ! -f "$STATE_DIR/.db-user-created" ]; then
  echo "entrypoint.sh: creating wordpress database/user"
  DB_USER_VAL="$($WP_CLI config get DB_USER)"
  DB_PASSWORD_VAL="$($WP_CLI config get DB_PASSWORD)"
  DB_NAME_VAL="$($WP_CLI config get DB_NAME)"
  mysql --socket="$DB_SOCKET" -u root <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME_VAL\`;
CREATE USER IF NOT EXISTS '$DB_USER_VAL'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD_VAL';
CREATE USER IF NOT EXISTS '$DB_USER_VAL'@'localhost' IDENTIFIED BY '$DB_PASSWORD_VAL';
GRANT ALL PRIVILEGES ON \`$DB_NAME_VAL\`.* TO '$DB_USER_VAL'@'127.0.0.1';
GRANT ALL PRIVILEGES ON \`$DB_NAME_VAL\`.* TO '$DB_USER_VAL'@'localhost';
FLUSH PRIVILEGES;
SQL
  touch "$STATE_DIR/.db-user-created"
fi

# Idempotent every boot: guarantees the Duplicator traversal payload's path
# resolution has something to resolve against even before seed.sh's own
# wp-snapshots step (see PLAN.md 0).
mkdir -p "$WP_PATH/wp-snapshots"
chown -R www-data:www-data "$WP_PATH/wp-snapshots"

# Boot-time SQLite scoring schema, needed before access-log-tail.sh (which
# only knows how to UPDATE existing rows) starts. Runs as root (this script's
# own user), so the resulting file must be handed to www-data afterward --
# Apache/PHP runs scoring.php as www-data and needs write access to fire
# checkpoints; access-log-tail.sh itself runs as root regardless and would
# work either way.
php /opt/wp-duplicator/init-scoring-db.php
chown -R www-data:www-data /app/data

/opt/wp-duplicator/seed.sh

if [ ! -f "$STATE_DIR/.phpmyadmin-configured" ]; then
  echo "entrypoint.sh: writing phpMyAdmin config"
  export PMA_BLOWFISH_SECRET
  PMA_BLOWFISH_SECRET="$(openssl rand -base64 32)"
  envsubst '${PMA_BLOWFISH_SECRET}' \
    < /var/www/phpmyadmin/config.inc.php.template \
    > /var/www/phpmyadmin/config.inc.php
  chown www-data:www-data /var/www/phpmyadmin/config.inc.php
  chmod 640 /var/www/phpmyadmin/config.inc.php
  touch "$STATE_DIR/.phpmyadmin-configured"
fi

echo "entrypoint.sh: starting access-log tailer"
/opt/wp-duplicator/access-log-tail.sh &

echo "entrypoint.sh: handing off to apache"
exec "$@"
