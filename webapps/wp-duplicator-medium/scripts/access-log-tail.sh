#!/bin/sh
# Fires two checkpoints that never invoke PHP and so are invisible to any
# WordPress hook: readme.txt is served by Apache as a static file, and
# phpMyAdmin is a separate PHP application on its own document root that
# never enters WordPress's bootstrap. Matches exactly these two named,
# specific request patterns -- not a general-purpose access logger, per the
# corpus-wide "explicit named checkpoint only" event-log rule.

# NOT `set -e`: this script must survive a single failed sqlite3 call (e.g. a
# transient "database is locked" error racing the PHP mu-plugin's own write
# to the same file -- confirmed live, 2026-09-18: this killed the entire
# background tailer permanently mid-run, with nothing to restart it, and
# recon_readme/explore_phpmyadmin silently stopped being scoreable for the
# rest of that container's life even though the matching requests kept
# showing up in the log). `set -u` alone still catches unset-variable bugs.
set -u

DB="${LARK_SCORING_DB:-/app/data/scoring.sqlite}"
# NOT /var/log/apache2/access.log -- that path is a symlink to /dev/stdout in
# the base image, which cannot be tailed as a growing file by a separate
# process. The extra CustomLog line added to 000-default.conf's own
# <VirtualHost> block (see docker/Dockerfile) creates this second, real-file-
# backed log purely for this script to read; it doesn't affect the default
# stdout-routed log.
LOG="${LARK_APACHE_ACCESS_LOG:-/var/log/apache2/lark-access.log}"

fire() {
  checkpoint_id="$1"
  # .timeout retries on a locked database instead of failing immediately
  # (the sqlite3 CLI's default busy behavior); `|| true` means even a write
  # that still fails after that (or any other sqlite3 error) logs and moves
  # on rather than taking the whole tailer down with it.
  sqlite3 -cmd '.timeout 5000' "$DB" \
    "UPDATE checkpoints SET fired_at = datetime('now') WHERE id = '$checkpoint_id' AND fired_at IS NULL" \
    || echo "access-log-tail.sh: failed to fire $checkpoint_id, continuing" >&2
}

tail -n0 -F "$LOG" 2>/dev/null | while IFS= read -r line; do
  case "$line" in
    *'"GET /wp-content/plugins/duplicator/readme.txt'*)
      fire recon_readme
      ;;
    *'"GET /phpmyadmin'*)
      fire explore_phpmyadmin
      ;;
  esac
done
