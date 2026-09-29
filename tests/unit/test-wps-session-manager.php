<?php
/**
 * Tests de la gestión de sesiones activas.
 */
class Test_WPS_Session_Manager extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$now = time();

		$GLOBALS['wps_test_user_meta'] = array(
			1 => array(
				WPS_Session_Manager::META_KEY => array(
					'aaa' => array( 'expiration' => $now + 3600, 'ip' => '1.1.1.1', 'ua' => 'Firefox', 'login' => $now - 300 ),
					'bbb' => array( 'expiration' => $now + 3600, 'ip' => '2.2.2.2', 'ua' => 'Chrome', 'login' => $now - 100 ),
					'ccc' => array( 'expiration' => $now + 3600, 'ip' => '3.3.3.3', 'ua' => 'Safari', 'login' => $now - 10 ),
					'old' => array( 'expiration' => $now - 60, 'ip' => '4.4.4.4', 'ua' => 'Viejo', 'login' => $now - 90000 ),
				),
			),
		);
		$GLOBALS['wps_test_user_caps'] = array( 1 => array( 'manage_options' => true ) );
	}

	protected function tearDown(): void {
		$GLOBALS['wps_test_user_meta'] = array();
		unset( $GLOBALS['wps_test_user_caps'] );
	}

	public function test_active_sessions_are_listed_newest_first(): void {
		$sessions = WPS_Session_Manager::for_user( 1 );

		$this->assertSame( array( 'ccc', 'bbb', 'aaa' ), array_column( $sessions, 'verifier' ) );
		$this->assertSame( '3.3.3.3', $sessions[0]['ip'] );
	}

	public function test_expired_sessions_are_not_listed(): void {
		$this->assertNotContains( 'old', array_column( WPS_Session_Manager::for_user( 1 ), 'verifier' ) );
	}

	public function test_a_single_session_can_be_closed(): void {
		$this->assertTrue( WPS_Session_Manager::destroy( 1, 'bbb' ) );

		$this->assertSame( array( 'ccc', 'aaa' ), array_column( WPS_Session_Manager::for_user( 1 ), 'verifier' ) );
		$this->assertFalse( WPS_Session_Manager::destroy( 1, 'bbb' ), 'Cerrar una sesión que ya no existe no es un éxito.' );
	}

	public function test_limit_keeps_the_newest_sessions(): void {
		$closed = WPS_Session_Manager::enforce_limit( 1, 2 );

		$this->assertSame( 1, $closed );
		$this->assertSame( array( 'ccc', 'bbb' ), array_column( WPS_Session_Manager::for_user( 1 ), 'verifier' ) );
	}

	public function test_zero_means_no_limit(): void {
		$this->assertSame( 0, WPS_Session_Manager::enforce_limit( 1, 0 ) );
		$this->assertCount( 3, WPS_Session_Manager::for_user( 1 ) );
	}

	public function test_login_enforces_the_limit_only_for_admins(): void {
		$loader = $this->loader( array( 'admin_max_sessions' => 1 ) );

		$loader->limit_admin_sessions( 'cliente', (object) array( 'ID' => 2 ) );
		$loader->limit_admin_sessions( 'admin', (object) array( 'ID' => 1 ) );

		$this->assertSame( array( 'ccc' ), array_column( WPS_Session_Manager::for_user( 1 ), 'verifier' ) );
	}

	public function test_login_does_nothing_without_a_limit(): void {
		$this->loader( array( 'admin_max_sessions' => 0 ) )->limit_admin_sessions( 'admin', (object) array( 'ID' => 1 ) );

		$this->assertCount( 3, WPS_Session_Manager::for_user( 1 ) );
	}

	private function loader( array $settings ): WPS_Loader {
		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );
		return $loader;
	}
}
