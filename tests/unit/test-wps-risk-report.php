<?php
/**
 * Tests del reporte guiado del modo sombra y de los umbrales configurables.
 */
class Test_WPS_Risk_Report extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * Umbrales configurables
	 *──────────────────────────────────────────────*/

	public function test_block_threshold_is_configurable(): void {
		$engine = $this->engine( array( 'risk_block_threshold' => 121, 'risk_hard_block_threshold' => 0 ) );

		$this->assertSame( 'strict_rate', $engine->action_for_score( 100 ) );
		$this->assertSame( 'temp_block', $engine->action_for_score( 121 ) );
		$this->assertSame( 'temp_block', $engine->action_for_score( 999 ), 'Con 0 nunca es permanente.' );
	}

	public function test_hard_threshold_below_the_temporary_one_is_raised(): void {
		$thresholds = $this->engine( array( 'risk_block_threshold' => 151, 'risk_hard_block_threshold' => 101 ) )->get_thresholds();

		$this->assertSame( 152, $thresholds['hard_block'] );
	}

	public function test_block_threshold_below_strict_rate_is_ignored(): void {
		$this->assertSame( 81, $this->engine( array( 'risk_block_threshold' => 10 ) )->get_thresholds()['temp_block'] );
	}

	public function test_defaults_keep_the_original_table(): void {
		$this->assertSame(
			array( 'log' => 31, 'strict_rate' => 51, 'temp_block' => 81, 'hard_block' => 101 ),
			$this->engine( array() )->get_thresholds()
		);
	}

	/*──────────────────────────────────────────────
	 * Agregación
	 *──────────────────────────────────────────────*/

	public function test_factor_names_drop_counts_and_values(): void {
		$this->assertSame(
			array( 'tool_ua', 'login_fail', '404', 'risky_country' ),
			WPS_Risk_Report::factor_names( 'tool_ua, login_fail:3, 404:4, risky_country:CN, tool_ua' )
		);
	}

	public function test_clients_use_their_worst_score(): void {
		$report = WPS_Risk_Report::aggregate( array(
			$this->event( '203.0.113.5', 60, 'tool_ua, 404:7' ),
			$this->event( '203.0.113.5', 95, 'tool_ua, suspicious_path, 404:8' ),
		), array(), 81 );

		$this->assertSame( 1, $report['clients'] );
		$this->assertSame( 1, $report['would_block'] );
		$this->assertSame( 95, $report['new_clients'][0]['max_score'] );
		$this->assertSame( 2, $report['new_clients'][0]['events'] );
	}

	public function test_simulation_separates_confirmed_and_new_clients(): void {
		$report = WPS_Risk_Report::aggregate( array(
			$this->event( '203.0.113.5', 130, 'sqli_pattern, tool_ua, 404:9' ),   // Atacante que otra regla ya bloqueó.
			$this->event( '2001:db8:1:2::7', 90, 'tool_ua, suspicious_path' ),     // Ídem, por red IPv6.
			$this->event( '198.51.100.9', 85, 'tool_ua, high_rate:50, 404:3' ),  // Sólo el motor lo bloquearía.
		), array( '203.0.113.5', '2001:db8:1:2::/64' ), 81 );

		$rows = array_column( $report['simulation'], null, 'threshold' );

		$this->assertSame( array( 3, 2, 1 ), array( $rows[81]['clients'], $rows[81]['confirmed'], $rows[81]['new'] ) );
		$this->assertTrue( $rows[81]['current'] );
		$this->assertSame( 0, $rows[91]['new'], 'Con 91 ya no habría bloqueos nuevos.' );
		$this->assertSame( 91, $report['suggested'] );
		$this->assertSame( '198.51.100.9', $report['new_clients'][0]['ip'] );
	}

	public function test_factors_rank_new_clients_first(): void {
		$report = WPS_Risk_Report::aggregate( array(
			$this->event( '203.0.113.5', 130, 'sqli_pattern, tool_ua' ),
			$this->event( '198.51.100.9', 85, 'tool_ua, high_rate:50' ),
			$this->event( '198.51.100.10', 85, 'tool_ua, high_rate:50' ),
		), array( '203.0.113.5' ), 81 );

		$this->assertSame( 'tool_ua', $report['factors'][0]['factor'] );
		$this->assertSame( array( 3, 2 ), array( $report['factors'][0]['clients'], $report['factors'][0]['new_clients'] ) );
		$this->assertSame( 'sqli_pattern', end( $report['factors'] )['factor'] );
	}

	public function test_no_suggestion_without_blocks_or_when_every_threshold_has_new_clients(): void {
		$this->assertNull( WPS_Risk_Report::aggregate( array(), array(), 81 )['suggested'] );

		$report = WPS_Risk_Report::aggregate( array( $this->event( '198.51.100.9', 400, 'tool_ua' ) ), array(), 81 );
		$this->assertNull( $report['suggested'] );
	}

	public function test_custom_current_threshold_is_simulated(): void {
		$report = WPS_Risk_Report::aggregate( array( $this->event( '198.51.100.9', 88, 'tool_ua' ) ), array(), 88 );

		$this->assertContains( 88, array_column( $report['simulation'], 'threshold' ) );
	}

	public function test_malformed_events_are_skipped(): void {
		$report = WPS_Risk_Report::aggregate( array(
			array( 'ip_address' => '198.51.100.9', 'details' => 'no es json', 'created_at' => '2026-09-29 10:00:00' ),
			array( 'ip_address' => '', 'details' => '{"score":90}', 'created_at' => '2026-09-29 10:00:00' ),
		), array(), 81 );

		$this->assertSame( 0, $report['clients'] );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function event( string $ip, int $score, string $factors ): array {
		return array(
			'ip_address' => $ip,
			'details'    => json_encode( array( 'score' => $score, 'action' => 'x', 'factors' => $factors, 'enforced' => false ) ),
			'created_at' => '2026-09-29 10:00:00',
		);
	}

	private function engine( array $settings ): WPS_Rules_Engine {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		return WPS_Rules_Engine::get_instance( $loader );
	}
}
