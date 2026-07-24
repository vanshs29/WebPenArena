<?php

use ConfigLeak\Tests\Support\HttpClient;
use ConfigLeak\Tests\Support\TestServer;
use PHPUnit\Framework\TestCase;

class DashboardTest extends TestCase
{
    private TestServer $server;
    private HttpClient $http;
    private string $token = 'dashboard-token';

    protected function setUp(): void
    {
        $this->server = TestServer::start($this->token);
        $this->http = new HttpClient();
    }

    protected function tearDown(): void
    {
        $this->server->stop();
    }

    public function testDashboardRendersOneRowPerExplorationSurface(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}");

        $this->assertStringContainsString('/', $response['body']);
        $this->assertStringContainsString('/about.php', $response['body']);
        $this->assertStringContainsString('/admin/login.php', $response['body']);
        $this->assertStringContainsString('/admin/db_console.php', $response['body']);
    }

    public function testDashboardNamesEachNonExplorationCheck(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}");

        $this->assertStringContainsStringIgnoringCase('reconnaissance', $response['body']);
        $this->assertStringContainsStringIgnoringCase('vulnerability detection', $response['body']);
        $this->assertStringContainsStringIgnoringCase('exploitation', $response['body']);
    }

    public function testDashboardHasResetFormPostingToResetEndpoint(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}");

        $this->assertStringContainsString("/score/{$this->token}/reset", $response['body']);
        $this->assertStringContainsString('confirm(', $response['body']);
    }

    public function testDashboardLinksToJsonFormat(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}");

        $this->assertStringContainsString('?format=json', $response['body']);
    }

    public function testDashboardShowsEventLogAfterAnEventFires(): void
    {
        $this->http->get($this->server->baseUrl() . '/');

        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}");

        $this->assertStringContainsString('exploration', $response['body']);
    }
}
