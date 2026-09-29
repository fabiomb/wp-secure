<?php
/**
 * Tests del límite de intentos por cuenta (fuerza bruta distribuida).
 */
class Test_WPS_Account_Throttle extends \PHPUnit\Framework\TestCase {

	private $server_backup;

	protected function setUp(): void {
		$this->server_backup           = $_SERVER;
		$GLOBALS['wps_test_options']   = array();
		$GLOBALS['wps_test_user_meta'] = array();
		$GLOBALS['wps_test_users']     = array( 'admin' => $this->admin() );
		$GLOBALS['wpdb']->reset_queries();
		$_SERVER['REQUEST_URI']    = '/wp-login.php';
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['REMOTE_ADDR']    = '45.33.32.156';
		$this->reset_request();
	}

	protected function tearDown(): void {
		$_SERVER                       = $this->server_backup;
		$GLOBALS['wps_test_users']     = array();
		$GLOBALS['wps_test_user_meta'] = array();
		$GLOBALS['wpdb']->reset_queries();
		$this->reset_request();
	}

	public function test_account_below_the_limit_is_not_throttled(): void {
		$GLOBALS['wpdb']->var_result = 9;

		$this->assertFalse( $this->detector()->is_account_throttled( $this->admin(), '45.33.32.156' ) );
	}

	public function test_account_under_attack_rejects_unknown_clients(): void {
		$GLOBALS['wpdb']->var_result = 10;

		$this->assertTrue(
			$this->detector()->is_account_throttled( $this->admin(), '45.33.32.156' ),
			'Una botnet que reparte los intentos entre miles de IPs tiene que frenarse por cuenta.'
		);
	}

	public function test_owner_keeps_access_from_a_known_network(): void {
		WPS_Known_Clients::record( 1, '190.1.2.3' );
		$GLOBALS['wpdb']->var_result = 500;

		$this->assertFalse( $this->detector()->is_account_throttled( $this->admin(), '190.1.2.3' ) );
	}

	public function test_zero_disables_the_account_limit(): void {
		$GLOBALS['wpdb']->var_result = 500;

		$this->assertFalse( $this->detector( array( 'login_user_max_attempts' => 0 ) )->is_account_throttled( $this->admin(), '45.33.32.156' ) );
	}

	public function test_failures_are_counted_by_username_and_email(): void {
		$this->detector()->is_account_throttled( $this->admin(), '45.33.32.156' );

		$this->assertContains( array( 'admin', 'admin@example.com' ), array_map( function ( $args ) {
			return array_slice( $args, 0, 2 );
		}, $GLOBALS['wpdb']->prepared_args ) );
	}

	public function test_login_to_a_throttled_account_is_rejected_before_checking_the_password(): void {
		$GLOBALS['wpdb']->var_result = 10;

		$result = $this->detector()->check_before_auth( null, 'admin', 'clave' );

		$this->assertInstanceOf( WP_Error::class, $result );
	}

	public function test_password_reset_makes_the_network_known(): void {
		$this->detector()->on_password_reset( $this->admin() );

		$this->assertTrue( WPS_Known_Clients::is_known( 1, '45.33.32.156' ) );
	}

	public function test_known_networks_follow_the_ipv6_prefix(): void {
		WPS_Known_Clients::record( 1, '2001:db8:1:2::1' );

		$this->assertTrue( WPS_Known_Clients::is_known( 1, '2001:db8:1:2:ffff::9' ) );
		$this->assertFalse( WPS_Known_Clients::is_known( 1, '2001:db8:1:3::1' ) );
	}

	private function admin(): object {
		return (object) array( 'ID' => 1, 'user_login' => 'admin', 'user_email' => 'admin@example.com' );
	}

	private function detector( array $settings = array() ): WPS_Login_Detector {
		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		// Todos los ajustes explícitos: la base simulada devuelve el conteo de prueba.
		$cache->setValue( $loader, $settings + array( 'login_user_max_attempts' => 10, 'login_whitelist_only' => false, 'login_block_unknown_user' => true ) );
		return new WPS_Login_Detector( $loader );
	}

	private function reset_request(): void {
		$prop = new \ReflectionProperty( 'WPS_Request', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}
}
