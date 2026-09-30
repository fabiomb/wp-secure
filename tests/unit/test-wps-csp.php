<?php
/**
 * Tests de HSTS y Content-Security-Policy: política, reportes y armador.
 */
class Test_WPS_Csp extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wps_test_options'] = array();
	}

	protected function tearDown(): void {
		$GLOBALS['wps_test_options'] = array();
	}

	/*──────────────────────────────────────────────
	 * Política
	 *──────────────────────────────────────────────*/

	public function test_policy_written_by_hand_becomes_one_header_line(): void {
		$policy = "default-src 'self'\nscript-src 'self'  https://cdn.example.com;\n\nimg-src 'self' data:;";

		$this->assertSame(
			"default-src 'self'; script-src 'self' https://cdn.example.com; img-src 'self' data:",
			WPS_Csp::normalize( $policy )
		);
	}

	public function test_report_destination_in_the_policy_is_ignored(): void {
		$this->assertSame( "default-src 'self'", WPS_Csp::normalize( "default-src 'self'; report-uri https://otro.example/r; report-to x" ) );
	}

	public function test_empty_policy_uses_the_base(): void {
		$csp = $this->csp( array() );

		$this->assertStringContainsString( "object-src 'none'", $csp->policy() );
		$this->assertStringContainsString( "frame-ancestors 'self'", $csp->policy() );
	}

	public function test_headers_by_mode(): void {
		$this->assertSame( array(), $this->csp( array( 'csp_mode' => 'off' ) )->headers() );

		$report = $this->csp( array( 'csp_mode' => 'report', 'csp_policy' => "default-src 'self'" ) )->headers();
		$this->assertSame(
			"default-src 'self'; report-uri https://example.com/?wps_csp_report=1; report-to wps-csp",
			$report['Content-Security-Policy-Report-Only']
		);
		$this->assertSame( 'wps-csp="https://example.com/?wps_csp_report=1"', $report['Reporting-Endpoints'] );

		$this->assertArrayHasKey( 'Content-Security-Policy', $this->csp( array( 'csp_mode' => 'enforce' ) )->headers() );
	}

	/*──────────────────────────────────────────────
	 * Reportes
	 *──────────────────────────────────────────────*/

	public function test_report_uri_format(): void {
		$body = json_encode( array( 'csp-report' => array(
			'document-uri'        => 'https://example.com/tienda/?utm=1',
			'effective-directive' => 'script-src-elem',
			'blocked-uri'         => 'https://cdn.example.net/lib.js?v=3',
		) ) );

		$this->assertSame(
			array( array( 'script-src', 'https://cdn.example.net', '/tienda/' ) ),
			WPS_Csp::extract_reports( $body )
		);
	}

	public function test_reporting_api_format(): void {
		$body = json_encode( array(
			array( 'type' => 'csp-violation', 'body' => array( 'documentURL' => 'https://example.com/', 'effectiveDirective' => 'img-src', 'blockedURL' => 'data' ) ),
			array( 'type' => 'deprecation', 'body' => array() ),
		) );

		$this->assertSame( array( array( 'img-src', 'data:', '/' ) ), WPS_Csp::extract_reports( $body ) );
	}

	public function test_sources_are_reduced_to_origins_or_keywords(): void {
		$this->assertSame( "'unsafe-inline'", WPS_Csp::normalize_source( 'inline' ) );
		$this->assertSame( "'unsafe-eval'", WPS_Csp::normalize_source( 'eval' ) );
		$this->assertSame( 'https://fonts.example.com:8443', WPS_Csp::normalize_source( 'https://fonts.example.com:8443/a.woff2?x=<b>' ) );
		$this->assertSame( 'blob:', WPS_Csp::normalize_source( 'blob:https://example.com/uuid' ) );
		$this->assertNull( WPS_Csp::normalize_source( 'javascript:alert(1)' ) );
		$this->assertNull( WPS_Csp::normalize_source( "https://ex'ample.com/" ) );
	}

	public function test_invalid_reports_are_ignored(): void {
		$this->assertSame( array(), WPS_Csp::extract_reports( 'no es json' ) );
		$this->assertSame( array(), WPS_Csp::extract_reports( json_encode( array( 'csp-report' => array( 'effective-directive' => 'script-src; x', 'blocked-uri' => 'https://a.example' ) ) ) ) );
		$this->assertNull( WPS_Csp::normalize_directive( 'report-uri' ) );
		$this->assertSame( 'frame-ancestors', WPS_Csp::normalize_directive( 'frame-ancestors' ) );
	}

	public function test_repeated_reports_are_throttled(): void {
		$csp    = $this->csp( array( 'csp_mode' => 'report' ) );
		$report = array( array( 'script-src', 'https://cdn.example.net', '/' ) );

		$csp->record( $report, 1000 );
		$csp->record( $report, 1000 + 60 );
		$csp->record( $report, 1000 + WPS_Csp::THROTTLE );

		$stored = $csp->reports()['script-src https://cdn.example.net'];
		$this->assertSame( 2, $stored['count'] );
		$this->assertSame( 1000 + WPS_Csp::THROTTLE, $stored['last'] );
	}

	public function test_stored_combinations_are_capped(): void {
		$csp     = $this->csp( array( 'csp_mode' => 'report' ) );
		$reports = array();
		for ( $i = 0; $i < WPS_Csp::MAX_REPORTS + 20; $i++ ) {
			$reports[] = array( 'img-src', "https://h{$i}.example.com", '/' );
		}

		$csp->record( $reports, 1000 );

		$this->assertCount( WPS_Csp::MAX_REPORTS, $csp->reports() );
	}

	/*──────────────────────────────────────────────
	 * Política sugerida
	 *──────────────────────────────────────────────*/

	public function test_suggested_policy_adds_reported_sources(): void {
		$csp = $this->csp( array( 'csp_mode' => 'report', 'csp_policy' => "default-src 'self'; script-src 'self'; object-src 'none'" ) );
		$csp->record( array(
			array( 'script-src', 'https://cdn.example.net', '/' ),
			array( 'script-src', "'unsafe-inline'", '/' ),
			array( 'worker-src', 'blob:', '/' ),
		), 1000 );

		$this->assertSame(
			"default-src 'self'; script-src 'self' https://cdn.example.net 'unsafe-inline'; object-src 'none'; worker-src 'self' blob:",
			$csp->suggested()
		);
	}

	/*──────────────────────────────────────────────
	 * HSTS y headers existentes
	 *──────────────────────────────────────────────*/

	public function test_hsts_value(): void {
		$this->assertSame( '', WPS_Security_Hardener::hsts_value( 0, true ) );
		$this->assertSame( 'max-age=300', WPS_Security_Hardener::hsts_value( 300, false ) );
		$this->assertSame( 'max-age=31536000; includeSubDomains', WPS_Security_Hardener::hsts_value( 31536000, true ) );
	}

	public function test_existing_hsts_and_csp_headers_are_not_overwritten(): void {
		$extra = array(
			'Strict-Transport-Security'           => 'max-age=300',
			'Content-Security-Policy-Report-Only' => "default-src 'self'",
			'X-Frame-Options'                     => 'SAMEORIGIN',
		);

		$sent = WPS_Security_Hardener::headers_to_send(
			array( 'strict-transport-security: max-age=63072000; preload', 'Content-Security-Policy-Report-Only: default-src *' ),
			$extra
		);

		$this->assertSame( array( 'X-Frame-Options' => 'SAMEORIGIN' ), $sent );
	}

	public function test_default_headers_still_apply_without_extras(): void {
		$this->assertArrayHasKey( 'X-Content-Type-Options', WPS_Security_Hardener::headers_to_send( array() ) );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function csp( array $settings ): WPS_Csp {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		return new WPS_Csp( $loader );
	}
}
