<?php
/**
 * Tests unitarios para WPS_Proxy_Config.
 */
class Test_WPS_Proxy_Config extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $fixtures;

	protected function setUp(): void {
		$this->fixtures = require dirname( __DIR__ ) . '/fixtures/ips.php';
	}

	/*──────────────────────────────────────────────
	 * CDN Range Detection
	 *──────────────────────────────────────────────*/

	public function test_cloudflare_ip_in_range(): void {
		$proxy = WPS_Proxy_Config::get_instance();

		foreach ( $this->fixtures['cloudflare'] as $ip ) {
			$this->assertTrue(
				$proxy->is_in_cdn_range( $ip, 'cloudflare' ),
				"Debería estar en rango Cloudflare: {$ip}"
			);
		}
	}

	public function test_non_cloudflare_ip_not_in_range(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$this->assertFalse( $proxy->is_in_cdn_range( '8.8.8.8', 'cloudflare' ) );
		$this->assertFalse( $proxy->is_in_cdn_range( '203.0.113.50', 'cloudflare' ) );
	}

	public function test_unknown_cdn_returns_empty(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$this->assertFalse( $proxy->is_in_cdn_range( '8.8.8.8', 'unknown_cdn' ) );
	}

	/*──────────────────────────────────────────────
	 * CDN Auto-Detection
	 *──────────────────────────────────────────────*/

	public function test_detect_cdn_without_headers_returns_null(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		// Sin headers CDN → null.
		$original_cf = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null;
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		unset( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		$this->assertNull( $proxy->detect_cdn( '8.8.8.8' ) );

		if ( null !== $original_cf ) {
			$_SERVER['HTTP_CF_CONNECTING_IP'] = $original_cf;
		}
	}

	public function test_detect_cloudflare(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.50';

		$this->assertEquals( 'cloudflare', $proxy->detect_cdn( '173.245.48.1' ) );

		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
	}

	/*──────────────────────────────────────────────
	 * IP Resolution
	 *──────────────────────────────────────────────*/

	public function test_get_real_ip_without_proxy_returns_remote_addr(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		// Sin loader → usa defaults (auto mode).
		$_SERVER['REMOTE_ADDR'] = '203.0.113.50';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		unset( $_SERVER['HTTP_X_REAL_IP'] );
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		unset( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		$ip = $proxy->get_real_ip();
		$this->assertEquals( '203.0.113.50', $ip );
	}

	public function test_get_real_ip_cloudflare_trusted(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$_SERVER['REMOTE_ADDR']           = '173.245.48.1';  // CF IP.
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '1.2.3.4';

		$ip = $proxy->get_real_ip();
		$this->assertEquals( '1.2.3.4', $ip );

		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
	}

	public function test_get_real_ip_untrusted_proxy_ignores_header(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$_SERVER['REMOTE_ADDR']           = '8.8.8.8';  // No es un proxy conocido.
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '1.2.3.4';  // Header spoofado.

		$ip = $proxy->get_real_ip();
		// Debería ignorar el header CF porque REMOTE_ADDR no es un IP de Cloudflare.
		$this->assertEquals( '8.8.8.8', $ip );

		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
	}

	public function test_get_real_ip_strips_port_from_remote_addr(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$_SERVER['REMOTE_ADDR'] = '69.171.230.40:53776';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		unset( $_SERVER['HTTP_X_REAL_IP'] );
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		unset( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		$ip = $proxy->get_real_ip();
		$this->assertEquals( '69.171.230.40', $ip );
	}

	public function test_get_real_ip_strips_port_same_ip_different_ports(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		unset( $_SERVER['HTTP_X_REAL_IP'] );
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		unset( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		$_SERVER['REMOTE_ADDR'] = '173.252.70.9:40020';
		$ip1 = $proxy->get_real_ip();

		$_SERVER['REMOTE_ADDR'] = '173.252.70.9:65000';
		$ip2 = $proxy->get_real_ip();

		$this->assertEquals( $ip1, $ip2, 'El mismo IP con distintos puertos debe resolverse igual' );
		$this->assertEquals( '173.252.70.9', $ip1 );
	}
}
