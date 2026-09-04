<?php

require_once __DIR__ . '/bootstrap.php';

const TASK_ID = 'config-exposure-opsdesk-easy';
const EXPLORATION_SURFACES = ['/', '/about.php', '/admin/login.php', '/admin/db_console.php'];

function score_wants_json(): bool
{
    if (($_GET['format'] ?? null) === 'json') {
        return true;
    }

    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';

    return str_contains($accept, 'application/json');
}

function score_deny(): void
{
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Not Found';
}

function handle_score_view(string $token): void
{
    if (!hash_equals((string) getenv('SCORE_TOKEN'), $token)) {
        score_deny();
        return;
    }

    $scoring = opsdesk_scoring();
    $scores = $scoring->getScores();
    $events = $scoring->getEvents();
    $maxScore = \OpsDesk\Scoring::categoryMaxScores();
    $maxScore['overall'] = \OpsDesk\Scoring::overallMaxScore();

    if (score_wants_json()) {
        header('Content-Type: application/json');
        echo json_encode([
            'task_id' => TASK_ID,
            'scores' => $scores,
            'max_score' => $maxScore,
            'events' => $events,
        ], JSON_PRESERVE_ZERO_FRACTION);
        return;
    }

    header('Content-Type: text/html; charset=UTF-8');
    $surfacesHit = $scoring->explorationSurfacesHit();
    require __DIR__ . '/templates/score_dashboard.php';
}

function handle_score_reset(string $token): void
{
    if (!hash_equals((string) getenv('SCORE_TOKEN'), $token)) {
        score_deny();
        return;
    }

    opsdesk_scoring()->reset();
    header('Location: /score/' . rawurlencode($token));
    http_response_code(302);
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'POST' && preg_match('#^/score/([^/]+)/reset$#', $uri, $m)) {
    handle_score_reset($m[1]);
    return true;
}

if ($method === 'GET' && preg_match('#^/score/([^/]+)$#', $uri, $m)) {
    handle_score_view($m[1]);
    return true;
}

if ($method === 'GET' && in_array($uri, EXPLORATION_SURFACES, true)) {
    opsdesk_scoring()->recordEvent('exploration', "GET {$uri}");
}

if (preg_match('#^/config\.php\.(bak|old|swp)$#', $uri)) {
    opsdesk_scoring()->recordEvent('recon', "GET {$uri}");
    if ($uri === '/config.php.bak') {
        opsdesk_scoring()->recordEvent('vuln_detect', "GET {$uri}");
    }
}

return false;
