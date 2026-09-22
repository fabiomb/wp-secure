<?php
/**
 * Tests unitarios para WPS_Rate_Limiter.
 */
class Test_WPS_Rate_Limiter extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$this->reset_singleton();
		$GLOBALS['wpdb']->reset_queries();
	}

	private function reset_singleton(): void {
		$prop = new \ReflectionProperty( 'WPS_Rate_Limiter', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}

	private function limiter_with( array $settings ): WPS_Rate_Limiter {
		$loader     = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache_prop = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache_prop->setAccessible( true );
		$cache_prop->setValue( $loader, $settings );

		return WPS_Rate_Limiter::get_instance( $loader );
	}

	/*──────────────────────────────────────────────
	 * Costo por petición
	 *──────────────────────────────────────────────*/

	public function test_recording_a_hit_uses_a_single_query(): void {
		$limiter = $this->limiter_with( array( 'rate_total_per_min' => 240 ) );
		$GLOBALS['wpdb']->reset_queries();

		$limiter->record_hit( '45.33.32.156', 'total' );

		$this->assertCount(
			1,
			$GLOBALS['wpdb']->queries,
			'Contar una petición no puede costar un INSERT más un SELECT: se registran dos tipos de hit por visita.'
		);
	}

	public function test_disabled_limit_does_not_touch_the_database(): void {
		$limiter = $this->limiter_with( array( 'rate_xmlrpc_per_hour' => 0 ) );
		$GLOBALS['wpdb']->reset_queries();

		$this->assertTrue( $limiter->record_hit( '45.33.32.156', 'xmlrpc' ) );
		$this->assertCount( 0, $GLOBALS['wpdb']->queries );
	}

	/*──────────────────────────────────────────────
	 * Ventanas de tiempo
	 *──────────────────────────────────────────────*/

	public function test_login_and_xmlrpc_use_an_hourly_window(): void {
		$limiter = $this->limiter_with( array() );
		$method  = new \ReflectionMethod( 'WPS_Rate_Limiter', 'get_window_seconds' );
		$method->setAccessible( true );

		$this->assertEquals( 3600, $method->invoke( $limiter, 'login' ) );
		$this->assertEquals( 3600, $method->invoke( $limiter, 'xmlrpc' ) );
	}

	public function test_other_limits_use_a_one_minute_window(): void {
		$limiter = $this->limiter_with( array() );
		$method  = new \ReflectionMethod( 'WPS_Rate_Limiter', 'get_window_seconds' );
		$method->setAccessible( true );

		$this->assertEquals( 60, $method->invoke( $limiter, 'total' ) );
		$this->assertEquals( 60, $method->invoke( $limiter, 'pages' ) );
		$this->assertEquals( 60, $method->invoke( $limiter, '404' ) );
	}

	/*──────────────────────────────────────────────
	 * Un solo conteo por petición
	 *──────────────────────────────────────────────*/

	public function test_each_type_is_counted_once_per_request(): void {
		$limiter = $this->limiter_with( array( 'rate_pages_per_min' => 60, 'rate_total_per_min' => 240 ) );
		$GLOBALS['wpdb']->reset_queries();

		// Capa 1 (MU-plugin) y Capa 2 (loader) registran la misma visita.
		$limiter->record_hit( '45.33.32.156', 'total' );
		$limiter->record_hit( '45.33.32.156', 'pages' );
		$limiter->record_hit( '45.33.32.156', 'total' );
		$limiter->record_hit( '45.33.32.156', 'pages' );

		$this->assertCount(
			2,
			$GLOBALS['wpdb']->queries,
			'Una visita contada dos veces reduce a la mitad los límites configurados.'
		);
	}

	public function test_server_ip_is_never_rate_limited(): void {
		$limiter = $this->limiter_with( array( 'rate_total_per_min' => 240 ) );
		$GLOBALS['wpdb']->reset_queries();

		$this->assertTrue( $limiter->record_hit( '127.0.0.1', 'total' ) );
		$this->assertCount( 0, $GLOBALS['wpdb']->queries );
	}
}
