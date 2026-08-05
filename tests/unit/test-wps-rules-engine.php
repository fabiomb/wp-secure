<?php
/**
 * Tests unitarios para WPS_Rules_Engine (puntuación de riesgo).
 */
class Test_WPS_Rules_Engine extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$this->reset_singleton( 'WPS_Rules_Engine' );
		$this->reset_singleton( 'WPS_Rate_Limiter' );
		$this->reset_singleton( 'WPS_Request' );
		$GLOBALS['wpdb']->reset_queries();
	}

	protected function tearDown(): void {
		$this->reset_singleton( 'WPS_Request' );
		unset( $GLOBALS['wps_test_caps'] );
	}

	private function reset_singleton( string $class ): void {
		$prop = new \ReflectionProperty( $class, 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}

	private function engine_with( array $settings = array() ): WPS_Rules_Engine {
		$loader     = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache_prop = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache_prop->setAccessible( true );
		$cache_prop->setValue( $loader, $settings );

		return WPS_Rules_Engine::get_instance( $loader );
	}

	private function request( string $uri, array $headers = array() ): WPS_Request {
		$this->reset_singleton( 'WPS_Request' );

		$_SERVER['REMOTE_ADDR']    = '45.33.32.156';
		$_SERVER['REQUEST_URI']    = $uri;
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['HTTP_USER_AGENT'] = '';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'] );

		foreach ( $headers as $key => $value ) {
			$_SERVER[ $key ] = $value;
		}

		return WPS_Request::get_instance();
	}

	/*──────────────────────────────────────────────
	 * Modos de operación
	 *──────────────────────────────────────────────*/

	public function test_engine_is_off_by_default(): void {
		$engine = $this->engine_with();

		$this->assertFalse(
			$engine->is_enabled(),
			'El motor debe venir apagado: encenderlo solo cambia el comportamiento de un sitio si el usuario lo decide.'
		);
	}

	public function test_shadow_mode_is_enabled_but_does_not_enforce(): void {
		$engine = $this->engine_with( array( 'risk_engine_mode' => 'shadow' ) );

		$this->assertTrue( $engine->is_enabled() );
		$this->assertFalse(
			$engine->is_enforcing(),
			'El modo sombra mide y registra, nunca bloquea.'
		);
	}

	public function test_enforce_mode_blocks(): void {
		$engine = $this->engine_with( array( 'risk_engine_mode' => 'enforce' ) );

		$this->assertTrue( $engine->is_enabled() );
		$this->assertTrue( $engine->is_enforcing() );
	}

	public function test_unknown_mode_falls_back_to_off(): void {
		$engine = $this->engine_with( array( 'risk_engine_mode' => 'cualquier-cosa' ) );

		$this->assertFalse( $engine->is_enabled() );
	}

	/*──────────────────────────────────────────────
	 * Umbrales
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider score_to_action
	 */
	public function test_action_for_score( int $score, string $expected ): void {
		$engine = $this->engine_with();

		$this->assertEquals( $expected, $engine->action_for_score( $score ) );
	}

	public function score_to_action(): array {
		return array(
			'sin riesgo'      => array( 0, 'none' ),
			'apenas debajo'   => array( 30, 'none' ),
			'log'             => array( 31, 'log' ),
			'tope de log'     => array( 50, 'log' ),
			'rate estricto'   => array( 51, 'strict_rate' ),
			'tope de rate'    => array( 80, 'strict_rate' ),
			'bloqueo temp'    => array( 81, 'temp_block' ),
			'tope de temp'    => array( 100, 'temp_block' ),
			'bloqueo duro'    => array( 101, 'hard_block' ),
			'muy por encima'  => array( 500, 'hard_block' ),
		);
	}

	/*──────────────────────────────────────────────
	 * Puntuación
	 *──────────────────────────────────────────────*/

	public function test_ordinary_browser_request_scores_zero(): void {
		$engine  = $this->engine_with( array( 'risk_engine_mode' => 'shadow' ) );
		$request = $this->request( '/2026/mi-articulo/', array(
			'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
		) );

		$assessment = $engine->assess( $request );

		$this->assertEquals( 0, $assessment['score'] );
		$this->assertEmpty( $assessment['factors'] );
		$this->assertEquals( 'none', $assessment['action'] );
	}

	public function test_empty_user_agent_raises_the_score(): void {
		$engine  = $this->engine_with( array( 'risk_engine_mode' => 'shadow' ) );
		$request = $this->request( '/2026/mi-articulo/' );

		$assessment = $engine->assess( $request );

		$this->assertGreaterThan( 0, $assessment['score'] );
		$this->assertContains( 'empty_ua', $assessment['factors'] );
	}

	public function test_tool_user_agent_raises_the_score(): void {
		$engine  = $this->engine_with( array( 'risk_engine_mode' => 'shadow' ) );
		$request = $this->request( '/', array( 'HTTP_USER_AGENT' => 'curl/8.4.0' ) );

		$assessment = $engine->assess( $request );

		$this->assertContains( 'tool_ua', $assessment['factors'] );
	}

	public function test_suspicious_path_raises_the_score(): void {
		$engine  = $this->engine_with( array( 'risk_engine_mode' => 'shadow' ) );
		$request = $this->request( '/wp-admin/install.php', array(
			'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome/120.0',
		) );

		$assessment = $engine->assess( $request );

		$this->assertContains( 'suspicious_path', $assessment['factors'] );
	}

	public function test_detector_context_accumulates(): void {
		$engine  = $this->engine_with( array( 'risk_engine_mode' => 'shadow' ) );
		$request = $this->request( '/', array( 'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome/120.0' ) );

		$clean   = $engine->assess( $request );
		$with_sqli = $engine->assess( $request, array( 'sqli' => true ) );

		$this->assertGreaterThan( $clean['score'], $with_sqli['score'] );
		$this->assertContains( 'sqli_pattern', $with_sqli['factors'] );
	}

	public function test_assessment_reports_the_action_for_its_score(): void {
		$engine  = $this->engine_with( array( 'risk_engine_mode' => 'shadow' ) );
		$request = $this->request( '/', array( 'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome/120.0' ) );

		$assessment = $engine->assess( $request, array( 'sqli' => true, 'xss' => true, 'traversal' => true ) );

		$this->assertEquals( $engine->action_for_score( $assessment['score'] ), $assessment['action'] );
	}

	/*──────────────────────────────────────────────
	 * Costo cuando está apagado
	 *──────────────────────────────────────────────*/

	public function test_disabled_engine_does_not_query_the_database(): void {
		$engine  = $this->engine_with( array( 'risk_engine_mode' => 'off' ) );
		$request = $this->request( '/', array( 'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome/120.0' ) );
		$GLOBALS['wpdb']->reset_queries();

		$engine->evaluate_and_act( $request );

		$this->assertCount(
			0,
			$GLOBALS['wpdb']->queries,
			'Con el motor apagado no debe costar ni una consulta.'
		);
	}
}
