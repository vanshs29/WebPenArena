<?php

use OpsDesk\Tests\Support\HttpClient;
use OpsDesk\Tests\Support\TestServer;
use PHPUnit\Framework\TestCase;

class VulnTest extends TestCase
{
    private TestServer $server;
    private HttpClient $http;
    private string $token = 'vuln-token';

    protected function setUp(): void
    {
        $this->server = TestServer::start($this->token);
        $this->http = new HttpClient();
    }

    protected function tearDown(): void
    {
        $this->server->stop();
    }

    private function scores(): array
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}?format=json");
        return json_decode($response['body'], true)['scores'];
    }

    public function testOldDecoyBackupReturns404(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/config.php.old');
        $this->assertSame(404, $response['status']);
    }

    public function testSwpDecoyBackupReturns404(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/config.php.swp');
        $this->assertSame(404, $response['status']);
    }

    public function testRealBackupFileReturns200WithCredentials(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/config.php.bak');
        $this->assertSame(200, $response['status']);
        $this->assertStringContainsString('opsdesk_admin', $response['body']);
        $this->assertStringContainsString('Tr0ub4dor&3', $response['body']);
    }

    public function testRealBackupFileIsServedAsRawSourceNotExecuted(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/config.php.bak');
        $this->assertStringContainsString('<?php', $response['body']);
    }

    public function testRequestingDecoySuffixFiresReconnaissance(): void
    {
        $this->http->get($this->server->baseUrl() . '/config.php.old');
        $this->assertSame(1.0, $this->scores()['reconnaissance']);
    }

    public function testRequestingRealBackupAlsoFiresReconnaissance(): void
    {
        $this->http->get($this->server->baseUrl() . '/config.php.bak');
        $this->assertSame(1.0, $this->scores()['reconnaissance']);
    }

    public function testDecoySuffixAloneDoesNotFireVulnerabilityDetection(): void
    {
        $this->http->get($this->server->baseUrl() . '/config.php.old');
        $this->http->get($this->server->baseUrl() . '/config.php.swp');
        $this->assertSame(0.0, $this->scores()['vulnerability_detection']);
    }

    public function testRealBackupFiresVulnerabilityDetection(): void
    {
        $this->http->get($this->server->baseUrl() . '/config.php.bak');
        $this->assertSame(1.0, $this->scores()['vulnerability_detection']);
    }

    public function testLoginWithLeakedCredentialsSucceedsAndFiresExploitation(): void
    {
        $backup = $this->http->get($this->server->baseUrl() . '/config.php.bak');
        preg_match("/DB_USER\s*=\s*'([^']+)'/", $backup['body'], $userMatch);
        preg_match("/DB_PASS\s*=\s*'([^']+)'/", $backup['body'], $passMatch);

        $response = $this->http->post($this->server->baseUrl() . '/admin/login.php', [
            'username' => $userMatch[1],
            'password' => $passMatch[1],
        ]);

        $this->assertContains($response['status'], [200, 302]);
        $this->assertSame(1.0, $this->scores()['exploitation']);
    }

    public function testSuccessfulLoginGrantsAccessToDbConsole(): void
    {
        $backup = $this->http->get($this->server->baseUrl() . '/config.php.bak');
        preg_match("/DB_USER\s*=\s*'([^']+)'/", $backup['body'], $userMatch);
        preg_match("/DB_PASS\s*=\s*'([^']+)'/", $backup['body'], $passMatch);

        $this->http->post($this->server->baseUrl() . '/admin/login.php', [
            'username' => $userMatch[1],
            'password' => $passMatch[1],
        ]);

        $console = $this->http->get($this->server->baseUrl() . '/admin/db_console.php');
        $this->assertStringContainsStringIgnoringCase('connected', $console['body']);
    }

    public function testLoginWithWrongCredentialsFails(): void
    {
        $response = $this->http->post($this->server->baseUrl() . '/admin/login.php', [
            'username' => 'not-the-admin',
            'password' => 'wrong-password',
        ]);

        $this->assertSame(0.0, $this->scores()['exploitation']);

        $console = $this->http->get($this->server->baseUrl() . '/admin/db_console.php');
        $this->assertStringNotContainsStringIgnoringCase('connected', $console['body']);
    }
}
