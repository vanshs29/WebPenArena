<?php

session_start();

$authenticated = $_SESSION['authenticated'] ?? false;

http_response_code($authenticated ? 200 : 401);
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DB Console — ConfigLeak Portal</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand fw-bold" href="/">ConfigLeak</a>
    <div class="navbar-nav">
      <a class="nav-link" href="/">Home</a>
      <a class="nav-link" href="/about.php">About</a>
      <a class="nav-link active" href="/admin/db_console.php">Admin</a>
    </div>
  </div>
</nav>
<div class="container py-5">
  <h1 class="mb-4">Database Console</h1>
  <?php if ($authenticated): ?>
    <div class="alert alert-success">Connected to database on localhost.</div>
    <pre class="bg-dark text-light p-3 rounded">db&gt; SHOW TABLES;
users
sessions
audit_log</pre>
  <?php else: ?>
    <div class="alert alert-warning">
      You must log in as an administrator to use the database console.
      <a href="/admin/login.php">Log in</a>.
    </div>
  <?php endif; ?>
</div>
</body>
</html>
