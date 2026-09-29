<?php
/**
 * Tests de las rutas trampa.
 */
class Test_WPS_Honeypot extends \PHPUnit\Framework\TestCase {

	private $server_backup;

	protected function setUp(): void {
		$this->server_backup = $_SERVER;
		$GLOBALS['wpdb']->reset_queries();
		// Modo Inseguro: send_block_response() no corta la ejecución del test.
		$GLOBALS['wps_test_options'] = array( 'wps_unsafe_mode' => true );
		$GLOBALS['wps_test_caps']    = array();
	}

	protected function tearDown(): void {
		$_SERVER                     = $this->server_backup;
		$GLOBALS['wps_test_options'] = array();
		$GLOBALS['wps_test_caps']    = array();
		$this->reset_request();
	}

	/*──────────────────────────────────────────────
	 * Coincidencias
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider trap_requests
	 */
	public function test_default_traps_match_scanner_probes( string $path ): void {
		$this->assertNotNull( WPS_Honeypot::match( $path, WPS_Honeypot::DEFAULT_PATHS ) );
	}

	public function trap_requests(): array {
		return array(
			'env'                  => array( '/.env' ),
			'env con sufijo'       => array( '/.env.production' ),
			'env en subdirectorio' => array( '/wordpress/.env' ),
			'mayusculas'           => array( '/.ENV' ),
			'repo git'             => array( '/.git/config' ),
			'copia de wp-config'   => array( '/wp-config.php.bak' ),
			'wp-config con tilde'  => array( '/wp-config.php~' ),
			'credenciales aws'     => array( '/.aws/credentials' ),
			'phpunit expuesto'     => array( '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' ),
			'codificado'           => array( '/%2Eenv' ),
		);
	}

	/**
	 * @dataProvider legitimate_requests
	 */
	public function test_default_traps_ignore_legitimate_paths( string $path ): void {
		$this->assertNull( WPS_Honeypot::match( $path, WPS_Honeypot::DEFAULT_PATHS ) );
	}

	public function legitimate_requests(): array {
		return array(
			'inicio'              => array( '/' ),
			'post sobre env'      => array( '/2026/05/variables-env-en-php/' ),
			'wp-config real'      => array( '/wp-config.php' ),
			'archivo terminado'   => array( '/descargas/config.env' ),
			'post sobre git'      => array( '/tutorial-git/' ),
			'admin'               => array( '/wp-admin/' ),
		);
	}

	public function test_custom_traps_and_blank_lines(): void {
		$traps = "\n  /admin-viejo/ \n\n/secreto/*\n/*\n/";

		$this->assertSame( '/admin-viejo/', WPS_Honeypot::match( '/admin-viejo/', $traps ) );
		$this->assertSame( '/secreto/*', WPS_Honeypot::match( '/secreto/archivo.txt', $traps ) );
		$this->assertNull( WPS_Honeypot::match( '/cualquier-pagina/', $traps ), 'Una trampa que abarca todo el sitio se ignora.' );
	}

	/*──────────────────────────────────────────────
	 * Bloqueo
	 *──────────────────────────────────────────────*/

	public function test_trap_blocks_the_client_for_a_long_time(): void {
		$this->request( '/.env' );

		( new WPS_Honeypot( $this->loader() ) )->check( WPS_Request::get_instance() );

		$block = $this->last_block();
		$this->assertNotNull( $block );
		$this->assertSame( 'auto_honeypot', $block['block_type'] );
		$minutes = ( strtotime( $block['expires_at'] . ' UTC' ) - time() ) / 60;
		$this->assertGreaterThan( 1400, $minutes );
	}

	public function test_nothing_happens_when_disabled(): void {
		$this->request( '/.env' );

		( new WPS_Honeypot( $this->loader( array( 'honeypot_enabled' => false ) ) ) )->check( WPS_Request::get_instance() );

		$this->assertNull( $this->last_block() );
	}

	public function test_logged_in_editors_are_never_trapped(): void {
		$GLOBALS['wps_test_caps'] = array( 'edit_posts' => true );
		$this->request( '/.env' );

		$check = new \ReflectionMethod( 'WPS_Loader', 'check_honeypot' );
		$check->setAccessible( true );
		$check->invoke( $this->loader() );

		$this->assertNull( $this->last_block() );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function request( string $uri ): void {
		$_SERVER['REQUEST_URI']    = $uri;
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['REMOTE_ADDR']    = '45.33.32.156';
		$this->reset_request();
	}

	private function loader( array $settings = array() ): WPS_Loader {
		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );
		return $loader;
	}

	private function last_block(): ?array {
		$rows = array_filter( $GLOBALS['wpdb']->inserts, function ( $insert ) {
			return 'wp_wps_blocked_ips' === $insert[0];
		} );
		return $rows ? end( $rows )[1] : null;
	}

	private function reset_request(): void {
		$prop = new \ReflectionProperty( 'WPS_Request', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}
}
