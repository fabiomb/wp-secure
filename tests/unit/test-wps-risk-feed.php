<?php
/**
 * Tests de las señales de comportamiento que alimentan al motor de riesgo
 * y de lo que el reporte muestra que está midiendo.
 */
class Test_WPS_Risk_Feed extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $server;

	protected function setUp(): void {
		$this->server = $_SERVER;
		$this->reset_singleton( 'WPS_Rules_Engine' );
		$this->reset_singleton( 'WPS_Request' );
		$GLOBALS['wpdb']->reset_queries();
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
		$this->reset_singleton( 'WPS_Rules_Engine' );
		$this->reset_singleton( 'WPS_Request' );
	}

	/*──────────────────────────────────────────────
	 * Señales de comportamiento
	 *──────────────────────────────────────────────*/

	public function test_behavior_signals_add_up(): void {
		$assessment = $this->engine()->assess( $this->request(), array(
			'page_count'       => 0,
			'count_404'        => 8,
			'login_fails'      => 3,
			'nonexistent_user' => true,
		) );

		// 8 × 5 + 3 × 15 + 25 + User-Agent vacío (20).
		$this->assertSame( 130, $assessment['score'] );
		$this->assertContains( '404:8', $assessment['factors'] );
		$this->assertContains( 'login_fail:3', $assessment['factors'] );
		$this->assertContains( 'nonexistent_user', $assessment['factors'] );
	}

	public function test_page_count_from_context_skips_its_own_query(): void {
		$this->engine()->assess( $this->request(), array( 'page_count' => 50 ) );

		$rate_queries = array_filter( $GLOBALS['wpdb']->queries, function ( $sql ) {
			return false !== strpos( (string) $sql, 'rate_limits' );
		} );
		$this->assertSame( array(), $rate_queries );
	}

	public function test_high_rate_uses_the_page_count_from_context(): void {
		$assessment = $this->engine( array( 'rate_pages_per_min' => 60 ) )->assess( $this->request(), array( 'page_count' => 50 ) );

		$this->assertContains( 'high_rate:50', $assessment['factors'] );
	}

	public function test_behavior_context_costs_two_queries(): void {
		$context = $this->engine()->behavior_context( '203.0.113.5' );

		$this->assertCount( 2, $GLOBALS['wpdb']->queries, 'Contadores del rate limiter y logins de la última hora.' );
		$this->assertSame( array( 'page_count' => 0, 'count_404' => 0, 'login_fails' => 0, 'nonexistent_user' => false ), $context );
	}

	public function test_rate_limiter_reads_several_counters_in_one_query(): void {
		$counts = WPS_Rate_Limiter::get_instance( WPS_Loader::get_instance() )->get_counts( '203.0.113.5', array( 'pages', '404' ) );

		$this->assertSame( array( 'pages' => 0, '404' => 0 ), $counts );
		$this->assertCount( 1, $GLOBALS['wpdb']->queries );

		$args = $GLOBALS['wpdb']->prepared_args[0];
		$this->assertSame( array( '203.0.113.5', 'pages' ), array_slice( $args, 0, 2 ) );
		$this->assertSame( '404', $args[3] );
	}

	/*──────────────────────────────────────────────
	 * Qué está midiendo
	 *──────────────────────────────────────────────*/

	public function test_report_lists_every_measured_factor_including_low_scores(): void {
		$report = WPS_Risk_Report::aggregate( array(
			$this->event( '198.51.100.1', 35, 'tool_ua, 404:2' ),
			$this->event( '198.51.100.2', 45, 'tool_ua, high_rate:48' ),
			$this->event( '198.51.100.2', 45, 'tool_ua, high_rate:50' ),
		), array(), 81 );

		$measured = array_column( $report['measured'], null, 'factor' );

		$this->assertSame( 'tool_ua', $report['measured'][0]['factor'] );
		$this->assertSame( array( 3, 2 ), array( $measured['tool_ua']['events'], $measured['tool_ua']['clients'] ) );
		$this->assertSame( 2, $measured['high_rate']['events'] );
		$this->assertSame( 0, $report['would_block'], 'Riesgo bajo: nada que bloquear, pero se ve qué mide.' );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function engine( array $settings = array() ): WPS_Rules_Engine {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		return WPS_Rules_Engine::get_instance( $loader );
	}

	private function request(): WPS_Request {
		$_SERVER['REMOTE_ADDR']     = '203.0.113.5';
		$_SERVER['REQUEST_URI']     = '/';
		$_SERVER['REQUEST_METHOD']  = 'GET';
		$_SERVER['HTTP_USER_AGENT'] = '';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_REAL_IP'] );

		return WPS_Request::get_instance();
	}

	private function event( string $ip, int $score, string $factors ): array {
		return array(
			'ip_address' => $ip,
			'details'    => json_encode( array( 'score' => $score, 'factors' => $factors ) ),
			'created_at' => '2026-10-02 10:00:00',
		);
	}

	private function reset_singleton( string $class ): void {
		$prop = new \ReflectionProperty( $class, 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}
}
