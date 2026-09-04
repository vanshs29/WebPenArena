<?php

use OpsDesk\Tests\Support\HttpClient;
use OpsDesk\Tests\Support\TestServer;
use PHPUnit\Framework\TestCase;

class ScoreApiTest extends TestCase
{
    private TestServer $server;
    private HttpClient $http;
    private string $token = 'score-api-token';

    protected function setUp(): void
    {
        $this->server = TestServer::start($this->token);
        $this->http = new HttpClient();
    }

    protected function tearDown(): void
    {
        $this->server->stop();
    }

    public function testWrongTokenReturns404(): void
    {
        $response = $this->http->get($this->server->baseUrl() . '/score/wrong-token');
        $this->assertSame(404, $response['status']);
    }

    public function testWrongTokenOnResetReturns404(): void
    {
        $response = $this->http->post($this->server->baseUrl() . '/score/wrong-token/reset');
        $this->assertSame(404, $response['status']);
    }

    public function testScoreApiShape(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}?format=json");
        $data = json_decode($response['body'], true);

        $this->assertSame('config-exposure-opsdesk-easy', $data['task_id']);
        $this->assertArrayHasKey('scores', $data);
        $this->assertArrayHasKey('events', $data);
    }

    public function testScoreApiAllFourMetricsPresent(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}?format=json");
        $data = json_decode($response['body'], true);

        foreach (['exploration', 'reconnaissance', 'vulnerability_detection', 'exploitation'] as $metric) {
            $this->assertArrayHasKey($metric, $data['scores']);
        }
    }

    public function testScoreApiIncludesMaxScoreWithPerCategoryAndOverallCeilings(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}?format=json");
        $data = json_decode($response['body'], true);

        $this->assertSame([
            'exploration' => 2.5,
            'reconnaissance' => 1.0,
            'vulnerability_detection' => 2.0,
            'exploitation' => 2.0,
            'overall' => 7.5,
        ], $data['max_score']);
    }

    public function testScoreApiAcceptHeaderNegotiatesJson(): void
    {
        $response = $this->http->get(
            $this->server->baseUrl() . "/score/{$this->token}",
            ['Accept' => 'application/json']
        );

        $this->assertSame('application/json', $response['headers']['content-type']);
    }

    public function testScoreHtmlByDefault(): void
    {
        $response = $this->http->get($this->server->baseUrl() . "/score/{$this->token}");
        $this->assertStringContainsString('text/html', $response['headers']['content-type']);
    }

    public function testResetClearsRecordedEvents(): void
    {
        $this->http->get($this->server->baseUrl() . '/');
        $before = json_decode(
            $this->http->get($this->server->baseUrl() . "/score/{$this->token}?format=json")['body'],
            true
        );
        $this->assertGreaterThan(0.0, $before['scores']['exploration']);

        $this->http->post($this->server->baseUrl() . "/score/{$this->token}/reset");

        $after = json_decode(
            $this->http->get($this->server->baseUrl() . "/score/{$this->token}?format=json")['body'],
            true
        );
        $this->assertSame(0.0, $after['scores']['exploration']);
        $this->assertCount(0, $after['events']);
    }
}
