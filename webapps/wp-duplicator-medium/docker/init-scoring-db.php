<?php

/**
 * Standalone boot-time seeder for scoring.sqlite. Run once by entrypoint.sh
 * before Apache starts, so scripts/access-log-tail.sh (which only knows how
 * to UPDATE existing rows via the sqlite3 CLI, not create the schema) has a
 * table to write into from the very first request onward. Shares
 * scoring-core.php's checkpoint definitions with the mu-plugin and the reset
 * handler so none of the three can drift out of sync.
 *
 * Requires the already-deployed mu-plugin copy of scoring-core.php by its
 * absolute image path rather than a repo-relative one: in the built image
 * this script lives at /opt/wp-duplicator/init-scoring-db.php, a sibling of
 * scripts/ and docker/, not of mu-plugins/ -- the source tree's directory
 * layout isn't mirrored 1:1 in the image, so `__DIR__ . '/../mu-plugins/...'`
 * would resolve to a path that doesn't exist there.
 */

require_once getenv('LARK_SCORING_CORE_PATH') ?: '/var/www/html/wp-content/mu-plugins/scoring-core.php';

$dbPath = getenv('LARK_SCORING_DB') ?: '/app/data/scoring.sqlite';

$db = new SQLite3($dbPath);
$db->busyTimeout(5000);
$db->exec('CREATE TABLE IF NOT EXISTS checkpoints (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    weight REAL NOT NULL,
    label TEXT NOT NULL,
    trigger_desc TEXT NOT NULL,
    fired_at TEXT
)');

$stmt = $db->prepare(
    'INSERT OR IGNORE INTO checkpoints (id, category, weight, label, trigger_desc, fired_at)
     VALUES (:id, :cat, :w, :label, :trigger, NULL)'
);
foreach (lark_checkpoint_definitions() as $id => $def) {
    $stmt->bindValue(':id', $id);
    $stmt->bindValue(':cat', $def['category']);
    $stmt->bindValue(':w', $def['weight']);
    $stmt->bindValue(':label', $def['label']);
    $stmt->bindValue(':trigger', $def['trigger']);
    $stmt->execute();
    $stmt->reset();
}

echo "scoring.sqlite seeded at $dbPath\n";
