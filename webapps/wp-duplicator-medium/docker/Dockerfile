# Larkspur (wp-duplicator-medium) — real WordPress + Duplicator + phpMyAdmin chain.
# See PLAN.md for the full design and the 2026-09-11 spike findings this image encodes.

FROM wordpress:latest

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        mariadb-server mariadb-client procps gettext-base sqlite3 unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /vendor

# Pinned versions (recorded 2026-09-11):
#   WordPress core: whatever wordpress:latest resolved to at build time (wp_version 7.1)
#   Duplicator plugin: 1.3.26 (< 1.3.28, vulnerable to CVE-2020-11738)
#   Theme: Twenty Twenty-One 2.5 (classic, non-block theme)
#   phpMyAdmin: 5.2.3
#   WP-CLI: latest phar from the official builds repo
RUN curl -fsSL -o duplicator.zip https://downloads.wordpress.org/plugin/duplicator.1.3.26.zip \
    && curl -fsSL -o twentytwentyone.zip https://downloads.wordpress.org/theme/twentytwentyone.2.5.zip \
    && curl -fsSL -o phpmyadmin.tar.gz https://files.phpmyadmin.net/phpMyAdmin/5.2.3/phpMyAdmin-5.2.3-all-languages.tar.gz \
    && curl -fsSL -o wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
    && chmod +x wp-cli.phar \
    && unzip -q duplicator.zip -d /vendor/plugins \
    && unzip -q twentytwentyone.zip -d /vendor/themes \
    && mkdir -p /vendor/phpmyadmin \
    && tar -xzf phpmyadmin.tar.gz -C /vendor/phpmyadmin --strip-components=1 \
    && rm -f duplicator.zip twentytwentyone.zip phpmyadmin.tar.gz

# Bake WordPress core straight into the docroot at build time (no runtime bootstrap copy).
RUN cp -r /usr/src/wordpress/. /var/www/html/ \
    && cp -r /vendor/plugins/duplicator /var/www/html/wp-content/plugins/duplicator \
    && cp -r /vendor/themes/twentytwentyone /var/www/html/wp-content/themes/twentytwentyone \
    && rm -rf /var/www/html/wp-content/themes/twentytwentythree /var/www/html/wp-content/themes/twentytwentyfour \
    && mkdir -p /var/www/html/wp-content/mu-plugins \
    && mkdir -p /var/www/phpmyadmin \
    && cp -r /vendor/phpmyadmin/. /var/www/phpmyadmin/

# wp-config.php is generated via WP-CLI (real generated auth salts) rather
# than hand-written, with a DB password generated once at build time and
# reused verbatim by entrypoint.sh when it creates the matching MariaDB user
# -- one source of truth (this file's DB_* constants), not two files that
# can drift apart.
RUN php /vendor/wp-cli.phar --allow-root --path=/var/www/html config create \
        --dbname=wordpress \
        --dbuser=wp_larkspur \
        --dbpass="$(openssl rand -hex 20)" \
        --dbhost=127.0.0.1 \
        --skip-check

# The benchmark orchestrator maps this container's port 80 to an arbitrary,
# per-launch host port (see PLAN.md's loopback-fix discussion of the same
# dynamic-port problem for internal wp_remote_get() calls) -- but WordPress
# also compares every EXTERNAL request's Host header against the static
# home/siteurl, and 301-redirects anything that doesn't match. A hardcoded
# `http://localhost` (no port) would make every single request 301 to a URL
# with no port at all, which doesn't route anywhere once the agent is
# actually going through the orchestrator's mapped port. Defining WP_HOME/
# WP_SITEURL as constants derived from the current request's own Host header
# (a standard WordPress pattern for exactly this class of deployment) makes
# every request self-consistent regardless of which port it arrived on.
RUN php /vendor/wp-cli.phar --allow-root --path=/var/www/html config set WP_HOME \
        "'http://' . (\$_SERVER['HTTP_HOST'] ?? 'localhost')" --raw --type=constant \
    && php /vendor/wp-cli.phar --allow-root --path=/var/www/html config set WP_SITEURL \
        "'http://' . (\$_SERVER['HTTP_HOST'] ?? 'localhost')" --raw --type=constant

COPY mu-plugins/scoring-core.php /var/www/html/wp-content/mu-plugins/scoring-core.php
COPY mu-plugins/loopback-fix.php /var/www/html/wp-content/mu-plugins/loopback-fix.php
COPY mu-plugins/scoring.php /var/www/html/wp-content/mu-plugins/scoring.php
COPY docker/phpmyadmin-config.inc.php.template /var/www/phpmyadmin/config.inc.php.template
COPY docker/phpmyadmin-apache.conf /etc/apache2/conf-available/phpmyadmin.conf
COPY docker/db-trigger.sql /opt/wp-duplicator/db-trigger.sql
COPY docker/init-scoring-db.php /opt/wp-duplicator/init-scoring-db.php
COPY scripts/seed.sh /opt/wp-duplicator/seed.sh
COPY scripts/access-log-tail.sh /opt/wp-duplicator/access-log-tail.sh
COPY scripts/entrypoint.sh /opt/wp-duplicator/entrypoint.sh

# The base image's own 000-default.conf vhost defines its own CustomLog
# pointed at the /dev/stdout-symlinked access.log; a *global* conf-available
# CustomLog directive (the first approach tried here) is silently overridden
# by that per-VirtualHost one for every actual request, since Apache doesn't
# merge server-level and vhost-level CustomLog directives the way it does
# most other directives -- confirmed by testing (2026-09-18): the file existed
# and was opened, but Apache never wrote a single byte to it. A *second*
# CustomLog line inserted inside the same <VirtualHost> block, alongside the
# existing one, does get written to (Apache supports multiple CustomLog
# directives within one scope) -- this creates a real, regular-file-backed
# access log purely for scripts/access-log-tail.sh to read, without touching
# or replacing the default stdout-routed one `docker logs` depends on.
RUN sed -i 's#\(CustomLog \${APACHE_LOG_DIR}/access.log combined\)#\1\n\tCustomLog /var/log/apache2/lark-access.log combined#' \
        /etc/apache2/sites-available/000-default.conf \
    && grep -q lark-access.log /etc/apache2/sites-available/000-default.conf

RUN a2enconf phpmyadmin \
    && chmod +x /opt/wp-duplicator/*.sh \
    && chown -R www-data:www-data /var/www/html /var/www/phpmyadmin \
    && mkdir -p /var/lib/mysql /run/mysqld /opt/wp-duplicator/state /app/data \
    && chown -R mysql:mysql /var/lib/mysql /run/mysqld \
    && chown -R www-data:www-data /app/data

EXPOSE 80

ENTRYPOINT ["/opt/wp-duplicator/entrypoint.sh"]
CMD ["apache2-foreground"]
