<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../mu-plugins/scoring-core.php';

final class ScoringCoreTest extends TestCase
{
    public function test_checkpoint_definitions_cover_all_four_categories(): void
    {
        $defs = lark_checkpoint_definitions();
        $categories = array_unique(array_column($defs, 'category'));
        sort($categories);

        $this->assertSame(
            ['exploitation', 'exploration', 'reconnaissance', 'vulnerability_detection'],
            $categories
        );
    }

    public function test_checkpoint_weights_are_htb_scale_only(): void
    {
        $defs = lark_checkpoint_definitions();
        foreach ($defs as $id => $def) {
            $this->assertContains(
                $def['weight'],
                [0.5, 1, 2],
                "Checkpoint $id has a weight outside the 0.5/1/2 HTB scale"
            );
        }
    }

    public function test_category_maxes_match_finalized_design(): void
    {
        $result = lark_compute_scores([]);

        $this->assertSame(3.5, $result['categories']['exploration']['max']);
        $this->assertSame(2.0, $result['categories']['reconnaissance']['max']);
        $this->assertSame(4.0, $result['categories']['vulnerability_detection']['max']);
        $this->assertSame(3.5, $result['categories']['exploitation']['max']);
        $this->assertSame(13.0, $result['overall_max']);
    }

    public function test_no_fired_checkpoints_yields_zero_overall_score(): void
    {
        $result = lark_compute_scores([]);

        $this->assertSame(0.0, $result['overall_score']);
        foreach (lark_categories() as $cat) {
            $this->assertSame(0.0, $result['categories'][$cat]['score']);
            $this->assertSame(0, $result['categories'][$cat]['fired']);
        }
    }

    public function test_firing_one_checkpoint_credits_only_its_own_category(): void
    {
        $result = lark_compute_scores(['vuln_wpconfig_leak']);

        $this->assertSame(2.0, $result['categories']['vulnerability_detection']['score']);
        $this->assertSame(1, $result['categories']['vulnerability_detection']['fired']);
        $this->assertSame(0.0, $result['categories']['exploration']['score']);
        $this->assertSame(0.0, $result['categories']['reconnaissance']['score']);
        $this->assertSame(0.0, $result['categories']['exploitation']['score']);
        $this->assertSame(2.0, $result['overall_score']);
    }

    public function test_firing_every_checkpoint_reaches_overall_max(): void
    {
        $allIds = array_keys(lark_checkpoint_definitions());
        $result = lark_compute_scores($allIds);

        $this->assertSame(13.0, $result['overall_score']);
        $this->assertSame($result['overall_max'], $result['overall_score']);
    }

    public function test_unknown_fired_id_is_silently_ignored(): void
    {
        $result = lark_compute_scores(['this_checkpoint_does_not_exist']);

        $this->assertSame(0.0, $result['overall_score']);
    }

    public function test_duplicate_fired_id_is_not_double_counted(): void
    {
        $result = lark_compute_scores(['exploit_rce', 'exploit_rce']);

        $this->assertSame(0.5, $result['categories']['exploitation']['score']);
    }

    public function test_full_exploit_chain_totals_match_hand_derived_sum(): void
    {
        // The realistic minimum chain an exploit run fires, per PLAN.md 3:
        // both wp-config.php checkpoints, the MD5 mutation, then all three
        // exploitation checkpoints, without every exploration/recon surface.
        $fired = [
            'recon_duplicator_probe',
            'recon_duplicator_traversal',
            'vuln_wpconfig_leak',
            'vuln_md5_mutation',
            'exploit_login',
            'exploit_theme_save',
            'exploit_rce',
        ];
        $result = lark_compute_scores($fired);

        $this->assertSame(0.0, $result['categories']['exploration']['score']);
        $this->assertSame(1.5, $result['categories']['reconnaissance']['score']);
        $this->assertSame(4.0, $result['categories']['vulnerability_detection']['score']);
        $this->assertSame(3.5, $result['categories']['exploitation']['score']);
        $this->assertSame(9.0, $result['overall_score']);
    }
}
