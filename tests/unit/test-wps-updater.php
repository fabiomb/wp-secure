<?php
/**
 * Tests del actualizador desde los releases de GitHub.
 */
class Test_WPS_Updater extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wps_test_transients']   = array();
		$GLOBALS['wps_test_http_calls']   = 0;
		$GLOBALS['wps_test_http_response'] = array( 'code' => 200, 'body' => json_encode( $this->release( '9.1.0' ) ) );
		$GLOBALS['wps_test_hooks']        = array();
	}

	protected function tearDown(): void {
		unset( $GLOBALS['wps_test_http_response'], $GLOBALS['wps_test_is_admin'], $_GET['force-check'] );
		$GLOBALS['wps_test_transients'] = array();
	}

	/*──────────────────────────────────────────────
	 * Validación del release
	 *──────────────────────────────────────────────*/

	public function test_valid_release_is_parsed(): void {
		$release = WPS_Updater::parse_release( $this->release( '0.7.1' ) );

		$this->assertSame( '0.7.1', $release['version'] );
		$this->assertSame( 'https://github.com/fabiomb/wp-secure/releases/download/v0.7.1/wp-secure-0.7.1.zip', $release['package'] );
	}

	public function test_prereleases_drafts_and_odd_tags_are_ignored(): void {
		$this->assertNull( WPS_Updater::parse_release( array( 'prerelease' => true ) + $this->release( '0.7.1' ) ) );
		$this->assertNull( WPS_Updater::parse_release( array( 'draft' => true ) + $this->release( '0.7.1' ) ) );
		$this->assertNull( WPS_Updater::parse_release( array( 'tag_name' => 'v0.7.1-beta' ) + $this->release( '0.7.1' ) ) );
	}

	public function test_package_must_be_this_versions_zip_in_this_repo(): void {
		$release = $this->release( '0.7.1' );

		$release['assets'][0]['browser_download_url'] = 'https://evil.example/wp-secure-0.7.1.zip';
		$this->assertNull( WPS_Updater::parse_release( $release ), 'Otro host.' );

		$release['assets'][0]['browser_download_url'] = 'https://github.com/otro/wp-secure/releases/download/v0.7.1/wp-secure-0.7.1.zip';
		$this->assertNull( WPS_Updater::parse_release( $release ), 'Otro repositorio.' );

		$release = $this->release( '0.7.1' );
		$release['assets'][0]['name'] = 'wp-secure-0.7.0.zip';
		$this->assertNull( WPS_Updater::parse_release( $release ), 'Zip de otra versión.' );
	}

	/*──────────────────────────────────────────────
	 * Filtros
	 *──────────────────────────────────────────────*/

	public function test_update_info_for_this_plugin_only(): void {
		$updater = $this->updater();

		$this->assertFalse( $updater->update_info( false, array(), 'otro/otro.php' ) );

		$info = $updater->update_info( false, array( 'RequiresPHP' => '7.4' ), WPS_PLUGIN_BASENAME );
		$this->assertSame( '9.1.0', $info['version'] );
		$this->assertSame( 'wp-secure', $info['slug'] );
		$this->assertStringEndsWith( '/wp-secure-9.1.0.zip', $info['package'] );
	}

	public function test_github_failure_leaves_no_update(): void {
		$GLOBALS['wps_test_http_response'] = array( 'code' => 503, 'body' => '' );

		$this->assertFalse( $this->updater()->update_info( false, array(), WPS_PLUGIN_BASENAME ) );
	}

	public function test_release_is_cached_and_force_check_skips_the_cache(): void {
		$updater = $this->updater();
		$updater->latest_release();
		$updater->latest_release();
		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'] );

		$GLOBALS['wps_test_is_admin'] = true;
		$_GET['force-check']          = '1';
		$updater->latest_release();
		$this->assertSame( 2, $GLOBALS['wps_test_http_calls'] );
	}

	public function test_failures_are_cached_too(): void {
		$GLOBALS['wps_test_http_response'] = array( 'code' => 403, 'body' => '' );
		$updater = $this->updater();

		$updater->latest_release();
		$updater->latest_release();

		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'], 'Sin martillar la API si GitHub limita.' );
	}

	public function test_request_does_not_send_the_site_url(): void {
		$args = WPS_Updater::request_args();

		$this->assertSame( 'WP-Seguro/' . WPS_VERSION, $args['user-agent'] );
	}

	public function test_plugin_details_show_the_release_notes(): void {
		$info = $this->updater()->plugin_info( false, 'plugin_information', (object) array( 'slug' => 'wp-secure' ) );

		$this->assertSame( '9.1.0', $info->version );
		$this->assertStringContainsString( '<h3>Corrección</h3>', $info->sections['changelog'] );

		$this->assertFalse( $this->updater()->plugin_info( false, 'plugin_information', (object) array( 'slug' => 'akismet' ) ) );
	}

	public function test_disabled_updater_registers_nothing(): void {
		$this->updater( array( 'update_check_enabled' => false ) )->init();
		$this->assertSame( array(), $GLOBALS['wps_test_hooks'] );

		$this->updater()->init();
		$this->assertContains( 'update_plugins_github.com', array_column( $GLOBALS['wps_test_hooks'], 'hook' ) );
	}

	/*──────────────────────────────────────────────
	 * Carpeta y notas
	 *──────────────────────────────────────────────*/

	public function test_installed_folder_name_is_kept(): void {
		$this->assertSame( '/tmp/up/wp-secure/', WPS_Updater::target_source( '/tmp/up/wp-secure/', '/tmp/up', 'wp-secure' ) );
		$this->assertSame( '/tmp/up/wp-secure-main/', WPS_Updater::target_source( '/tmp/up/wp-secure/', '/tmp/up', 'wp-secure-main' ) );
	}

	public function test_markdown_notes_are_escaped_and_converted(): void {
		$html = WPS_Updater::markdown_to_html( "### Corrección ([#24](https://github.com/fabiomb/wp-secure/issues/24))\n\n- **Nuevo** `WPS_Request::is_cli()`\n- <script>x</script>\n\nTexto." );

		$this->assertStringContainsString( '<h4>Corrección (<a href="https://github.com/fabiomb/wp-secure/issues/24">#24</a>)</h4>', $html );
		$this->assertStringContainsString( '<li><strong>Nuevo</strong> <code>WPS_Request::is_cli()</code></li>', $html );
		$this->assertStringContainsString( '&lt;script&gt;', $html );
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringEndsWith( '<p>Texto.</p>', $html );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function release( string $version ): array {
		return array(
			'tag_name'     => 'v' . $version,
			'draft'        => false,
			'prerelease'   => false,
			'html_url'     => 'https://github.com/fabiomb/wp-secure/releases/tag/v' . $version,
			'published_at' => '2026-10-02T12:00:00Z',
			'body'         => "## Corrección\n\n- Algo.",
			'assets'       => array(
				array(
					'name'                 => 'wp-secure-' . $version . '.zip',
					'browser_download_url' => 'https://github.com/fabiomb/wp-secure/releases/download/v' . $version . '/wp-secure-' . $version . '.zip',
				),
			),
		);
	}

	private function updater( array $settings = array() ): WPS_Updater {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		return new WPS_Updater( $loader );
	}
}
