<?php
/**
 * Tests del muestreo del log de tráfico.
 */
class Test_WPS_Traffic_Sampler extends \PHPUnit\Framework\TestCase {

	public function test_full_mode_logs_everything_with_weight_one(): void {
		$this->assertSame( 1, WPS_Traffic_Sampler::weight( 'full', 10, 'GET', 200, 7 ) );
	}

	public function test_off_mode_logs_nothing(): void {
		$this->assertSame( 0, WPS_Traffic_Sampler::weight( 'off', 10, 'POST', 500, 1 ) );
	}

	public function test_relevant_requests(): void {
		$this->assertTrue( WPS_Traffic_Sampler::is_relevant( 'POST', 200 ), 'Un POST a wp-login.php.' );
		$this->assertTrue( WPS_Traffic_Sampler::is_relevant( 'GET', 404 ) );
		$this->assertTrue( WPS_Traffic_Sampler::is_relevant( 'GET', 503 ) );
		$this->assertFalse( WPS_Traffic_Sampler::is_relevant( 'GET', 200 ) );
		$this->assertFalse( WPS_Traffic_Sampler::is_relevant( 'head', 301 ) );
		$this->assertFalse( WPS_Traffic_Sampler::is_relevant( 'GET', null ) );
	}

	public function test_relevant_mode_keeps_only_errors_and_non_get(): void {
		$this->assertSame( 1, WPS_Traffic_Sampler::weight( 'relevant', 10, 'GET', 404, 5 ) );
		$this->assertSame( 0, WPS_Traffic_Sampler::weight( 'relevant', 10, 'GET', 200, 1 ) );
	}

	public function test_sampled_mode_keeps_one_in_n_with_weight_n(): void {
		$this->assertSame( 10, WPS_Traffic_Sampler::weight( 'sampled', 10, 'GET', 200, 1 ) );
		$this->assertSame( 0, WPS_Traffic_Sampler::weight( 'sampled', 10, 'GET', 200, 2 ) );
	}

	public function test_sampled_mode_always_keeps_relevant_requests_with_weight_one(): void {
		$this->assertSame( 1, WPS_Traffic_Sampler::weight( 'sampled', 10, 'POST', 200, 9 ) );
		$this->assertSame( 1, WPS_Traffic_Sampler::weight( 'sampled', 10, 'GET', 404, 1 ), 'Peso 1: no se cuenta de más.' );
	}

	public function test_weighted_total_estimates_the_real_total(): void {
		mt_srand( 42 );
		$total = 0;
		$rows  = 0;
		for ( $i = 0; $i < 20000; $i++ ) {
			$weight = WPS_Traffic_Sampler::weight( 'sampled', 10, 'GET', 200, mt_rand( 1, 10 ) );
			$total += $weight;
			$rows  += $weight ? 1 : 0;
		}
		mt_srand();

		$this->assertEqualsWithDelta( 20000, $total, 1000, 'SUM(sample_weight) estima el total real.' );
		$this->assertEqualsWithDelta( 2000, $rows, 150, 'Se escribe una décima parte.' );
	}

	public function test_mode_and_rate_are_normalized(): void {
		$loader = $this->loader( array( 'traffic_log_mode' => 'raro', 'traffic_sample_rate' => 1 ) );

		$this->assertSame( 'full', WPS_Traffic_Sampler::mode( $loader ) );
		$this->assertSame( 2, WPS_Traffic_Sampler::rate( $loader ) );
		$this->assertSame( '', WPS_Traffic_Sampler::note( $loader ) );
	}

	public function test_note_explains_estimates(): void {
		$note = WPS_Traffic_Sampler::note( $this->loader( array( 'traffic_log_mode' => 'sampled', 'traffic_sample_rate' => 50 ) ) );

		$this->assertStringContainsString( '1 de cada 50', $note );
	}

	public function test_logger_stores_the_weight(): void {
		$GLOBALS['wpdb']->reset_queries();
		$logger = WPS_Logger::get_instance();

		$logger->traffic( array( 'ip_address' => '198.51.100.1', 'request_uri' => '/', 'sample_weight' => 10 ) );
		$logger->traffic( array( 'ip_address' => '198.51.100.2', 'request_uri' => '/' ) );
		$logger->flush();

		$this->assertSame( array( 10, 1 ), array_column( array_column( $GLOBALS['wpdb']->inserts, 1 ), 'sample_weight' ) );
	}

	private function loader( array $settings ): WPS_Loader {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );
		return $loader;
	}
}
