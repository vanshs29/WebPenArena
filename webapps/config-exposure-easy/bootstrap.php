<?php

require_once __DIR__ . '/src/Scoring.php';

function opsdesk_scoring(): \OpsDesk\Scoring
{
    static $scoring = null;

    if ($scoring === null) {
        $dbPath = getenv('DB_PATH') ?: (__DIR__ . '/data/scoring.db');
        $dir = dirname($dbPath);
        if ($dbPath !== ':memory:' && !is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        $scoring = \OpsDesk\Scoring::connect($dbPath);
    }

    return $scoring;
}
