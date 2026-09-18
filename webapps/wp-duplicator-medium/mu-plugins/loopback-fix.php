<?php

/**
 * Neutralizes a container-networking artifact of this benchmark's dynamic
 * host-port mapping: WordPress's theme/plugin-editor fatal-error loopback
 * self-test (wp_edit_theme_plugin_file() in wp-admin/includes/file.php)
 * makes one or two wp_remote_get() calls back to this site's own site_url(),
 * which has no reason to be reachable from inside this container's own
 * network namespace. Without this fix, saving a theme file from the Theme
 * Editor is silently reverted with "Unable to communicate back with site to
 * check for fatal errors."
 *
 * The exact success body format (the needle-delimited, json_encode(true)
 * payload) is read directly from wp-admin/includes/file.php's own
 * body-parsing logic, confirmed by reading that source inside the pinned
 * wordpress:latest image, not guessed from a write-up. That function makes
 * up to two such loopback calls (theme-editor.php, then home_url('/') if
 * the first parsed to true) — this filter matches on the wp_scrape_key
 * query parameter alone, so it transparently covers both.
 *
 * This only short-circuits requests carrying that specific marker; every
 * other outbound HTTP call this WordPress install makes is untouched. It
 * neutralizes an infrastructure artifact of the benchmark's own port
 * mapping, not any part of the real vulnerability chain — the Theme Editor,
 * its edit_themes capability check, and the actual file write are all real
 * and unmodified.
 */
add_filter('pre_http_request', function ($preempt, $parsedArgs, $url) {
    if (strpos($url, 'wp_scrape_key=') === false) {
        return $preempt;
    }

    $query = [];
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
    $key = $query['wp_scrape_key'] ?? '';

    $body = "###### wp_scraping_result_start:$key ######"
        . json_encode(true)
        . "###### wp_scraping_result_end:$key ######";

    return [
        'headers' => [],
        'body' => $body,
        'response' => ['code' => 200, 'message' => 'OK'],
        'cookies' => [],
        'filename' => null,
    ];
}, 10, 3);
