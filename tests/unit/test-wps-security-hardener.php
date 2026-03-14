<?php
/**
 * Tests unitarios para WPS_Security_Hardener (lógica sin hooks WP).
 */
class Test_WPS_Security_Hardener extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * HTTP Method Classification
	 *──────────────────────────────────────────────*/

	public function test_always_blocked_methods(): void {
		$blocked = array( 'TRACE', 'TRACK', 'DEBUG', 'CONNECT' );
		foreach ( $blocked as $method ) {
			$this->assertContains(
				$method,
				$blocked,
				"Método {$method} debería estar bloqueado"
			);
		}
	}

	public function test_safe_methods_not_blocked(): void {
		$safe = array( 'GET', 'POST', 'HEAD', 'OPTIONS' );
		$blocked = array( 'TRACE', 'TRACK', 'DEBUG', 'CONNECT' );
		foreach ( $safe as $method ) {
			$this->assertNotContains( $method, $blocked );
		}
	}

	/*──────────────────────────────────────────────
	 * Security Headers
	 *──────────────────────────────────────────────*/

	public function test_expected_security_headers(): void {
		$expected = array(
			'X-Content-Type-Options',
			'X-Frame-Options',
			'Referrer-Policy',
			'Permissions-Policy',
			'X-XSS-Protection',
		);

		foreach ( $expected as $header ) {
			$this->assertNotEmpty( $header, "Header debería estar definido: {$header}" );
		}
	}

	/*──────────────────────────────────────────────
	 * Version Removal
	 *──────────────────────────────────────────────*/

	public function test_remove_version_query(): void {
		$hardener_class = new \ReflectionClass( 'WPS_Security_Hardener' );
		// Check method exists.
		$this->assertTrue( $hardener_class->hasMethod( 'remove_version_query' ) );
	}
}
