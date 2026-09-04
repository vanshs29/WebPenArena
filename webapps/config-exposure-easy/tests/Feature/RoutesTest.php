<?php

use OpsDesk\Tests\Support\HttpClient;
use OpsDesk\Tests\Support\TestServer;
use PHPUnit\Framework\TestCase;

class RoutesTest extends TestCase
{
    private TestServer $server;
    private HttpClient $http;

    protected function setUp(): void
    {
        $this->server = TestServer::start('routes-token');
        $this->http = new HttpClient();
    }

    protected function tearDown(): void
    {
        $this->server->stop();
    }

    private function scores(): array
    {
        $response = $this->http->get($this->server->baseUrl() . '/score/routes-token?format=json');
        return json_decode($response['body'], true)['scores'];
    }

    public function testHomePageReturns200(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/');
        $this->assertSame(200, $response['status']);
    }

    public function testAboutPageReturns200(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/about.php');
        $this->assertSame(200, $response['status']);
    }

    public function testLoginPageReturns200(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/admin/login.php');
        $this->assertSame(200, $response['status']);
    }

    public function testDbConsoleWithoutSessionDoesNotShowConsoleContent(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/admin/db_console.php');
        $this->assertStringNotContainsStringIgnoringCase('connected', $response['body']);
    }

    public function testVisitingHomePageRecordsExplorationEvent(): void
    {
        $this->http->get($this->server->baseUrl() . '/');
        $this->assertGreaterThan(0.0, $this->scores()['exploration']);
    }

    public function testVisitingAllFourSurfacesFillsExplorationScore(): void
    {
        $this->http->get($this->server->baseUrl() . '/');
        $this->http->get($this->server->baseUrl() . '/about.php');
        $this->http->get($this->server->baseUrl() . '/admin/login.php');
        $this->http->get($this->server->baseUrl() . '/admin/db_console.php');

        $this->assertSame(2.5, $this->scores()['exploration']);
    }

    public function testRepeatedVisitToSameSurfaceDoesNotDoubleCount(): void
    {
        $this->http->get($this->server->baseUrl() . '/');
        $this->http->get($this->server->baseUrl() . '/');

        $this->assertSame(0.5, $this->scores()['exploration']);
    }
}
