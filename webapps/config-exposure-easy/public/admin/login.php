<?php

require_once dirname(__DIR__, 2) . '/bootstrap.php';

session_start();

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require dirname(__DIR__, 2) . '/config.php';

    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if (hash_equals($DB_USER, $username) && hash_equals($DB_PASS, $password)) {
        $_SESSION['authenticated'] = true;
        opsdesk_scoring()->recordEvent('exploit', 'admin login succeeded');
        header('Location: /admin/db_console.php');
        exit;
    }

    $error = 'Invalid username or password.';
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Login — OpsDesk Portal</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand fw-bold" href="/">OpsDesk</a>
    <div class="navbar-nav">
      <a class="nav-link" href="/">Home</a>
      <a class="nav-link" href="/about.php">About</a>
      <a class="nav-link active" href="/admin/login.php">Admin</a>
    </div>
  </div>
</nav>
<div class="container py-5" style="max-width: 420px;">
  <h1 class="mb-4">Admin Login</h1>
  <?php if ($error !== null): ?>
    <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
  <?php endif; ?>
  <form method="post" action="/admin/login.php">
    <div class="mb-3">
      <label for="username" class="form-label">Username</label>
      <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="mb-3">
      <label for="password" class="form-label">Password</label>
      <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Log In</button>
  </form>
</div>
</body>
</html>
