<?php
/**
 * Test del kill switch WPS_DISABLE_BLOCKING.
 *
 * Corre en un proceso aparte porque define una constante, que no se puede
 * deshacer y afectaría al resto de la suite.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class Test_WPS_Kill_Switch extends \PHPUnit\Framework\TestCase {

	public function test_blocking_is_active_by_default(): void {
		$this->assertFalse( WPS_Blocker::blocking_disabled() );
	}

	public function test_constant_suspends_blocking(): void {
		define( 'WPS_DISABLE_BLOCKING', true );

		$this->assertTrue( WPS_Blocker::blocking_disabled() );
	}

	public function test_constant_lets_a_blocked_ip_log_in(): void {
		define( 'WPS_DISABLE_BLOCKING', true );

		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, array( 'login_whitelist_only' => true ) );

		$detector = new WPS_Login_Detector( $loader );
		$user     = (object) array( 'ID' => 1 );

		$this->assertSame(
			$user,
			$detector->check_before_auth( $user, 'admin', 'clave' ),
			'Con el bloqueo suspendido el login no puede rechazarse.'
		);
	}
}
