<?php
/**
 * Tests del límite de búsquedas.
 */
class Test_WPS_Search_Guard extends \PHPUnit\Framework\TestCase {

	private $server_backup;

	protected function setUp(): void {
		$this->server_backup         = $_SERVER;
		$GLOBALS['wps_test_options'] = array();
		$GLOBALS['wps_test_caps']    = array();
		$GLOBALS['wpdb']->reset_queries();
		$_SERVER['REQUEST_URI']      = '/wp-json/wp/v2/search?search=hola';
		$_SERVER['REQUEST_METHOD']   = 'GET';
		$_SERVER['REMOTE_ADDR']      = '45.33.32.156';
		$this->reset_singletons();
	}

	protected function tearDown(): void {
		$_SERVER                  = $this->server_backup;
		$GLOBALS['wps_test_caps'] = array();
		$this->reset_singletons();
	}

	/*──────────────────────────────────────────────
	 * Qué es una búsqueda
	 *──────────────────────────────────────────────*/

	public function test_site_search_is_recognized(): void {
		$this->assertTrue( WPS_Search_Guard::is_search_query( array( 's' => 'zapatillas' ) ) );
		$this->assertFalse( WPS_Search_Guard::is_search_query( array( 's' => '  ' ) ) );
		$this->assertFalse( WPS_Search_Guard::is_search_query( array( 's' => array( 'x' ) ) ) );
		$this->assertFalse( WPS_Search_Guard::is_search_query( array( 'p' => '12' ) ) );
	}

	public function test_rest_searches_are_recognized(): void {
		$this->assertTrue( WPS_Search_Guard::is_rest_search( '/wp/v2/search', null ) );
		$this->assertTrue( WPS_Search_Guard::is_rest_search( '/WP/V2/Search/', null ) );
		$this->assertTrue( WPS_Search_Guard::is_rest_search( '/wp/v2/posts', 'hola' ) );
		$this->assertFalse( WPS_Search_Guard::is_rest_search( '/wp/v2/posts', null ) );
		$this->assertFalse( WPS_Search_Guard::is_rest_search( '/wp/v2/posts', '' ) );
	}

	/*──────────────────────────────────────────────
	 * Límite
	 *──────────────────────────────────────────────*/

	public function test_rest_search_over_the_limit_gets_429_without_blocking(): void {
		$GLOBALS['wpdb']->insert_id = 21; // Búsqueda 21 del minuto (límite 20).

		$result = $this->guard()->check_rest( null, null, $this->rest_request( '/wp/v2/search' ) );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'wps_search_rate_limited', $result->get_error_code() );
		$this->assertCount( 0, array_filter( $GLOBALS['wpdb']->inserts, function ( $i ) {
			return 'wp_wps_blocked_ips' === $i[0];
		} ) );
	}

	public function test_rest_search_within_the_limit_passes(): void {
		$this->assertNull( $this->guard()->check_rest( null, null, $this->rest_request( '/wp/v2/search' ) ) );
	}

	public function test_non_search_rest_requests_are_not_counted(): void {
		$this->guard()->check_rest( null, null, $this->rest_request( '/wp/v2/posts' ) );

		$this->assertCount( 0, $GLOBALS['wpdb']->queries );
	}

	public function test_editors_are_not_limited(): void {
		$GLOBALS['wps_test_caps']   = array( 'edit_posts' => true );
		$GLOBALS['wpdb']->insert_id = 999;

		$this->assertNull( $this->guard()->check_rest( null, null, $this->rest_request( '/wp/v2/search' ) ) );
	}

	public function test_zero_disables_the_limit(): void {
		$GLOBALS['wps_test_hooks'] = array();

		$this->guard( array( 'rate_search_per_min' => 0 ) )->init();

		$this->assertSame( array(), $GLOBALS['wps_test_hooks'] );
	}

	public function test_search_check_runs_before_the_query(): void {
		$GLOBALS['wps_test_hooks'] = array();
		$this->guard()->init();

		$hooks = array_column( $GLOBALS['wps_test_hooks'], 'hook' );
		$this->assertContains( 'parse_request', $hooks, 'En template_redirect la consulta ya se ejecutó.' );
		$this->assertContains( 'rest_pre_dispatch', $hooks );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function guard( array $settings = array() ): WPS_Search_Guard {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );
		return new WPS_Search_Guard( $loader );
	}

	private function rest_request( string $route, $search = null ) {
		return new class( $route, $search ) {
			private $route;
			private $search;
			public function __construct( $route, $search ) {
				$this->route  = $route;
				$this->search = $search;
			}
			public function get_route() { return $this->route; }
			public function get_param( $key ) { return 'search' === $key ? $this->search : null; }
		};
	}

	private function reset_singletons(): void {
		foreach ( array( 'WPS_Request', 'WPS_Rate_Limiter' ) as $class ) {
			$prop = new \ReflectionProperty( $class, 'instance' );
			$prop->setAccessible( true );
			$prop->setValue( null, null );
		}
		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), array() );
	}
}
