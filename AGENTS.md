# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this plugin does

**WP Seguro** is a WordPress security plugin that detects and blocks malicious traffic (bots, brute force, SQL injection, XSS, path traversal) with a focus on performance. It intercepts requests as early as possible — before WordPress even loads when possible.

Requirements: PHP 7.4+, WordPress 6.0+.

## Running tests

Tests use PHPUnit. The bootstrap (`tests/bootstrap.php`) auto-detects whether the WP test framework is available:

- **Standalone unit tests** (no WP install needed): PHPUnit resolves class names via the plugin's `spl_autoload_register` and minimal WP function stubs. Just run:
  ```
  vendor/bin/phpunit --testsuite unit
  ```

- **Integration tests** (require WP test framework at `$WP_TESTS_DIR` or `/tmp/wordpress-tests-lib`):
  ```
  WP_TESTS_DIR=/path/to/wordpress-tests-lib vendor/bin/phpunit --testsuite integration
  ```

- **Run a single test file:**
  ```
  vendor/bin/phpunit tests/unit/test-wps-ip-utils.php
  ```

## Architecture: Three-layer firewall

The plugin operates in three distinct layers to intercept traffic as early as possible:

| Layer | Mechanism | Timing | Purpose |
|-------|-----------|--------|---------|
| **Layer 0** | `auto_prepend_file` via `.htaccess` | Before any PHP runs | Blocks known-bad IPs from a flat PHP file — no DB, no WordPress |
| **Layer 1** | MU-Plugin (`wps-firewall-muplugin.php`) | After WP core, before plugins/themes | Request analysis, pattern detection, rate limiting, detailed logging |
| **Layer 2** | This plugin (standard) | Normal plugin load | Admin UI, config, log viewer, rules management, IP DB updates |

**Layer 0 data file:** `data/wps-blocked-ips.php` — a plain PHP file returning an array with `ips`, `cidrs`, `whitelist`, and `updated`. This file is written by the plugin and read by the firewall prepend without any DB connection.

## Key classes and their roles

- **`WPS_Rules_Engine`** — Scores each request (0–100+) across factors (`sqli_pattern`=50, `xss_pattern`=40, etc.) and triggers log/rate-limit/temp-block/immediate-block at thresholds 31/51/81/100.
- **`WPS_Blocker`** — Executes blocks (HTTP 403 response + logging).
- **`WPS_Logger`** — Buffers log writes and flushes via `register_shutdown_function` to avoid blocking responses.
- **`WPS_Geo`** — Resolves IP → country/ASN using a local MMDB file (managed by `WPS_Ipdb_Manager`) or a fallback API.
- **`WPS_Proxy_Config`** — Handles trusted proxy headers (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`) for correct IP resolution behind CDNs.
- **`WPS_Db_Schema`** — Defines all plugin tables (prefixed `{wp_prefix}wps_`). Tables: `wps_settings`, `wps_blocked_ips`, and others. Uses `dbDelta` for upgrades.
- **`WPS_Db`** — Singleton DB access layer. Plugin uses its own tables, not `wp_options`, for operational data.
- **`WPS_Activator`** — On activation: creates tables, installs the MU-plugin, creates the Layer 0 data file, sets up scheduled maintenance.

## Autoloader convention

Classes named `WPS_Foo_Bar` map to file `class-wps-foo-bar.php`. The autoloader searches these directories in order: `includes/`, `includes/core/`, `includes/database/`, `includes/logging/`, `includes/admin/`, `includes/firewall/`, `includes/detectors/`, `includes/ipdb/`.

## Database tables

All tables use the `{wpdb->prefix}wps_` prefix. The schema is defined in `includes/database/class-wps-db-schema.php` and applied/upgraded via `dbDelta`. Migrations between versions are handled in `class-wps-db-migrations.php`.

## Detectors

Each detector in `includes/detectors/` targets a specific attack vector: `class-wps-login-detector.php`, `class-wps-xmlrpc-detector.php`, `class-wps-sqli-detector.php`, `class-wps-xss-detector.php`, `class-wps-path-traversal-detector.php`, `class-wps-restapi-detector.php`, `class-wps-scanner-detector.php`. Each returns a score contribution consumed by `WPS_Rules_Engine`.

## Data directory

`data/` is protected by `.htaccess` (deny from all). The only file that must exist at runtime for Layer 0 to function is `data/wps-blocked-ips.php`.
