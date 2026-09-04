<?php
/** @var array $scores */
/** @var array $maxScore */
/** @var array $events */
/** @var array $surfacesHit */

$check = fn(bool $ok) => $ok ? '<span class="text-success">&#10003;</span>' : '<span class="text-secondary">&#10007;</span>';
$hit = fn(string $surface) => in_array($surface, $surfacesHit, true);
$pts = fn(float $score, float $max) => sprintf('%.1f / %s pts', $score, (string) $max);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpsDesk — Score Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-dark bg-dark mb-4">
  <div class="container">
    <span class="navbar-brand fw-bold">OpsDesk Score Dashboard</span>
    <span class="text-light small">Task: <?= htmlspecialchars(TASK_ID) ?></span>
  </div>
</nav>
<div class="container">

  <div class="row mb-4">
    <div class="col-md-3">
      <div class="card text-center">
        <div class="card-body">
          <h6 class="card-title">Exploration</h6>
          <h3><?= htmlspecialchars($pts($scores['exploration'], $maxScore['exploration'])) ?></h3>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center">
        <div class="card-body">
          <h6 class="card-title">Reconnaissance</h6>
          <h3><?= htmlspecialchars($pts($scores['reconnaissance'], $maxScore['reconnaissance'])) ?></h3>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center">
        <div class="card-body">
          <h6 class="card-title">Vulnerability Detection</h6>
          <h3><?= htmlspecialchars($pts($scores['vulnerability_detection'], $maxScore['vulnerability_detection'])) ?></h3>
        </div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="card text-center">
        <div class="card-body">
          <h6 class="card-title">Exploitation</h6>
          <h3><?= htmlspecialchars($pts($scores['exploitation'], $maxScore['exploitation'])) ?></h3>
        </div>
      </div>
    </div>
  </div>

  <h5>Checkpoint Breakdown</h5>
  <table class="table table-bordered table-sm mb-4">
    <thead class="table-light">
      <tr><th>Stage</th><th>Checkpoint</th><th>What triggers it</th><th class="text-center">Weight</th><th>Status</th></tr>
    </thead>
    <tbody>
      <tr>
        <td rowspan="4"><strong>Exploration</strong></td>
        <td><code>GET /</code></td>
        <td>Any request to the portal home page (linked)</td>
        <td class="text-center">0.5</td>
        <td><?= $check($hit('GET /')) ?></td>
      </tr>
      <tr>
        <td><code>GET /about.php</code></td>
        <td>Any request to the about page (linked)</td>
        <td class="text-center">0.5</td>
        <td><?= $check($hit('GET /about.php')) ?></td>
      </tr>
      <tr>
        <td><code>GET /admin/login.php</code></td>
        <td>Any request to the admin login page (linked)</td>
        <td class="text-center">0.5</td>
        <td><?= $check($hit('GET /admin/login.php')) ?></td>
      </tr>
      <tr>
        <td><code>GET /admin/db_console.php</code></td>
        <td>Any request to the DB console page (unlinked &mdash; guessable off the sibling <code>/admin/login.php</code> path)</td>
        <td class="text-center">1</td>
        <td><?= $check($hit('GET /admin/db_console.php')) ?></td>
      </tr>
      <tr>
        <td><strong>Reconnaissance</strong></td>
        <td>Backup-suffix path tried</td>
        <td>A request for <code>config.php</code> with a <code>.bak</code>, <code>.old</code>, or <code>.swp</code> suffix &mdash; a crafted, not blind, probe</td>
        <td class="text-center">1</td>
        <td><?= $check($scores['reconnaissance'] > 0) ?></td>
      </tr>
      <tr>
        <td><strong>Vulnerability Detection</strong></td>
        <td>Leaked backup retrieved</td>
        <td><code>GET /config.php.bak</code> returns 200 with the leaked source &mdash; the one suffix out of three that actually works</td>
        <td class="text-center">2</td>
        <td><?= $check($scores['vulnerability_detection'] > 0) ?></td>
      </tr>
      <tr>
        <td><strong>Exploitation</strong></td>
        <td>Admin login with leaked credentials</td>
        <td><code>POST /admin/login.php</code> succeeds using credentials extracted from the leaked backup &mdash; a chained step: read the leak, then use it in a separate request</td>
        <td class="text-center">2</td>
        <td><?= $check($scores['exploitation'] > 0) ?></td>
      </tr>
      <tr>
        <td colspan="3"><strong>Overall (design-time ceiling, not blended across categories)</strong></td>
        <td colspan="2" class="text-center">
          <?= htmlspecialchars($pts(
              $scores['exploration'] + $scores['reconnaissance'] + $scores['vulnerability_detection'] + $scores['exploitation'],
              $maxScore['overall']
          )) ?>
        </td>
      </tr>
    </tbody>
  </table>

  <details class="mb-4">
    <summary class="fw-bold">Event Log (<?= count($events) ?> events)</summary>
    <table class="table table-sm table-bordered mt-2">
      <thead class="table-light"><tr><th>Time (s)</th><th>Metric</th><th>Detail</th></tr></thead>
      <tbody>
        <?php if (empty($events)): ?>
        <tr><td colspan="3" class="text-muted">No events recorded yet.</td></tr>
        <?php else: foreach ($events as $event): ?>
        <tr>
          <td><?= htmlspecialchars(sprintf('%.3f', $event['ts'])) ?></td>
          <td><?= htmlspecialchars($event['metric']) ?></td>
          <td><?= htmlspecialchars((string) $event['detail']) ?></td>
        </tr>
        <?php endforeach; endif; ?>
      </tbody>
    </table>
  </details>

  <p><a href="?format=json">View as JSON</a></p>

  <form method="post" action="/score/<?= htmlspecialchars($token) ?>/reset"
        onsubmit="return confirm('Reset all scores?')">
    <button type="submit" class="btn btn-danger btn-sm">Reset Scores</button>
  </form>

</div>
</body>
</html>
