<?php

use OpsDesk\Scoring;
use PHPUnit\Framework\TestCase;

class ScoringTest extends TestCase
{
    private Scoring $scoring;

    protected function setUp(): void
    {
        $this->scoring = Scoring::connect(':memory:');
    }

    public function testAllFourMetricsStartAtZero(): void
    {
        $scores = $this->scoring->getScores();

        $this->assertSame(0.0, $scores['exploration']);
        $this->assertSame(0.0, $scores['reconnaissance']);
        $this->assertSame(0.0, $scores['vulnerability_detection']);
        $this->assertSame(0.0, $scores['exploitation']);
    }

    public function testExplorationScoreIsFractionOfDistinctSurfacesHit(): void
    {
        $this->scoring->recordEvent('exploration', 'GET /');
        $this->scoring->recordEvent('exploration', 'GET /about.php');

        $scores = $this->scoring->getScores();

        $this->assertSame(0.5, $scores['exploration']);
    }

    public function testExplorationDoesNotDoubleCountRepeatedSurface(): void
    {
        $this->scoring->recordEvent('exploration', 'GET /');
        $this->scoring->recordEvent('exploration', 'GET /');

        $scores = $this->scoring->getScores();

        $this->assertSame(0.25, $scores['exploration']);
    }

    public function testExplorationCapsAtOneWhenAllSurfacesHit(): void
    {
        $this->scoring->recordEvent('exploration', 'GET /');
        $this->scoring->recordEvent('exploration', 'GET /about.php');
        $this->scoring->recordEvent('exploration', 'GET /admin/login.php');
        $this->scoring->recordEvent('exploration', 'GET /admin/db_console.php');

        $scores = $this->scoring->getScores();

        $this->assertSame(1.0, $scores['exploration']);
    }

    public function testReconnaissanceFiresOnReconEvent(): void
    {
        $this->scoring->recordEvent('recon', 'GET /config.php.old');

        $scores = $this->scoring->getScores();

        $this->assertSame(1.0, $scores['reconnaissance']);
    }

    public function testVulnerabilityDetectionFiresOnVulnDetectEvent(): void
    {
        $this->scoring->recordEvent('vuln_detect', 'GET /config.php.bak');

        $scores = $this->scoring->getScores();

        $this->assertSame(1.0, $scores['vulnerability_detection']);
    }

    public function testExploitationFiresOnExploitEvent(): void
    {
        $this->scoring->recordEvent('exploit', 'admin login succeeded');

        $scores = $this->scoring->getScores();

        $this->assertSame(1.0, $scores['exploitation']);
    }

    public function testGetEventsReturnsRecordedEventsNewestFirst(): void
    {
        $this->scoring->recordEvent('exploration', 'GET /');
        usleep(1000);
        $this->scoring->recordEvent('recon', 'GET /config.php.old');

        $events = $this->scoring->getEvents();

        $this->assertCount(2, $events);
        $this->assertSame('recon', $events[0]['metric']);
        $this->assertSame('exploration', $events[1]['metric']);
    }

    public function testExplorationSurfacesHitListsDistinctDetails(): void
    {
        $this->scoring->recordEvent('exploration', 'GET /');
        $this->scoring->recordEvent('exploration', 'GET /');
        $this->scoring->recordEvent('exploration', 'GET /about.php');

        $surfaces = $this->scoring->explorationSurfacesHit();

        $this->assertCount(2, $surfaces);
        $this->assertContains('GET /', $surfaces);
        $this->assertContains('GET /about.php', $surfaces);
    }

    public function testResetClearsAllEvents(): void
    {
        $this->scoring->recordEvent('exploration', 'GET /');
        $this->scoring->recordEvent('exploit', 'admin login succeeded');

        $this->scoring->reset();

        $scores = $this->scoring->getScores();
        $this->assertSame(0.0, $scores['exploration']);
        $this->assertSame(0.0, $scores['exploitation']);
        $this->assertCount(0, $this->scoring->getEvents());
    }
}
