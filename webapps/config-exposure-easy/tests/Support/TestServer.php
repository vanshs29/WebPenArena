<?php

namespace ConfigLeak\Tests\Support;

class TestServer
{
    /** @var resource */
    private $process;

    private string $baseUrl;
    private string $dbPath;

    private function __construct($process, string $baseUrl, string $dbPath)
    {
        $this->process = $process;
        $this->baseUrl = $baseUrl;
        $this->dbPath = $dbPath;
    }

    public static function start(string $scoreToken = 'test-token'): self
    {
        $port = random_int(20000, 60000);
        $dbPath = sys_get_temp_dir() . '/configleak_test_' . bin2hex(random_bytes(8)) . '.db';

        $env = array_merge(
            array_filter($_SERVER, static fn($v) => is_scalar($v)),
            ['SCORE_TOKEN' => $scoreToken, 'DB_PATH' => $dbPath]
        );

        $cmd = sprintf(
            'exec php -S 127.0.0.1:%d -t %s %s',
            $port,
            escapeshellarg(PROJECT_ROOT . '/public'),
            escapeshellarg(PROJECT_ROOT . '/router.php')
        );

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($cmd, $descriptors, $pipes, PROJECT_ROOT, $env);

        if ($process === false) {
            throw new \RuntimeException('failed to start PHP built-in server');
        }

        $baseUrl = "http://127.0.0.1:{$port}";
        $server = new self($process, $baseUrl, $dbPath);
        $server->waitUntilReady();

        return $server;
    }

    private function waitUntilReady(): void
    {
        $deadline = microtime(true) + 5;
        while (microtime(true) < $deadline) {
            $ch = curl_init($this->baseUrl . '/score/__health__');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT_MS, 200);
            curl_exec($ch);
            $errno = curl_errno($ch);
            curl_close($ch);
            if ($errno === 0) {
                return;
            }
            usleep(50000);
        }

        throw new \RuntimeException('PHP built-in server did not become ready in time');
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
        }
        if (file_exists($this->dbPath)) {
            unlink($this->dbPath);
        }
    }
}
