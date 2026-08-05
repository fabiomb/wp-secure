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

	/**
	 * @dataProvider cloudflare_ipv6_ranges
	 */
	public function test_cloudflare_ipv6_is_recognized( string $ip ): void {
		$proxy = WPS_Proxy_Config::get_instance();

		$this->assertTrue(
			$proxy->is_in_cdn_range( $ip, 'cloudflare' ),
			"Cloudflare puede conectar al origen por IPv6; sin este rango, {$ip} se toma como el visitante real."
		);
	}

	public function cloudflare_ipv6_ranges(): array {
		return array(
			array( '2400:cb00::1' ),
			array( '2606:4700::6810:85e5' ),
			array( '2803:f800::1' ),
			array( '2405:b500::1' ),
			array( '2405:8100::1' ),
			array( '2a06:98c0::1' ),
			array( '2c0f:f248::1' ),
		);
	}

	public function test_non_cloudflare_ipv6_is_not_in_range(): void {
		$proxy = WPS_Proxy_Config::get_instance();

		$this->assertFalse( $proxy->is_in_cdn_range( '2001:4860:4860::8888', 'cloudflare' ) );
		$this->assertFalse( $proxy->is_in_cdn_range( '2a06:98d0::1', 'cloudflare' ) );
	}

	public function test_visitor_ip_resolves_behind_cloudflare_over_ipv6(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		// Cloudflare llega al origen por IPv6 y declara al visitante real.
		$_SERVER['REMOTE_ADDR']           = '2606:4700::6810:85e5';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '45.33.32.156';
		unset( $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		$ip = $proxy->get_real_ip();

		unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );

		$this->assertEquals(
			'45.33.32.156',
			$ip,
			'Sin reconocer el IPv6 de Cloudflare, todos los visitantes colapsan en la IP del edge.'
		);
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

	/*──────────────────────────────────────────────
	 * Spoofing de headers detrás de un proxy local
	 *──────────────────────────────────────────────*/

	public function test_forwarded_for_uses_closest_hop_not_client_supplied_value(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		// Reverse proxy local (nginx → php-fpm): REMOTE_ADDR es privada.
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		// El cliente envía su propio X-Forwarded-For y el proxy le agrega la IP
		// real de la conexión al final. Sólo el último salto es confiable.
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 45.33.32.156';

		$this->assertEquals( '45.33.32.156', $proxy->get_real_ip() );

		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
	}

	public function test_forwarded_for_takes_precedence_over_spoofable_real_ip(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		// X-Real-IP es trivial de falsificar si el proxy no lo sobrescribe.
		$_SERVER['HTTP_X_REAL_IP']       = '1.2.3.4';
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '45.33.32.156';

		$this->assertEquals( '45.33.32.156', $proxy->get_real_ip() );

		unset( $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_FORWARDED_FOR'] );
	}

	public function test_forwarded_for_with_single_value_is_preserved(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		$_SERVER['HTTP_X_FORWARDED_FOR'] = '45.33.32.156';

		$this->assertEquals( '45.33.32.156', $proxy->get_real_ip() );

		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
	}

	public function test_forwarded_for_ignores_private_hops_at_the_end(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );

		// Cadena con saltos internos: la última IP pública es el cliente real.
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '45.33.32.156, 10.0.0.5, 192.168.1.20';

		$this->assertEquals( '45.33.32.156', $proxy->get_real_ip() );

		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
	}

	public function test_custom_mode_forwarded_for_uses_closest_hop(): void {
		$proxy = WPS_Proxy_Config::get_instance();
		$this->with_settings( $proxy, array(
			'proxy_mode'        => 'custom',
			'proxy_trusted_ips' => '10.0.0.1',
			'proxy_header'      => 'X-Forwarded-For',
		) );

		$_SERVER['REMOTE_ADDR'] = '10.0.0.1';
		unset( $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP'], $_SERVER['HTTP_X_SUCURI_CLIENTIP'] );
		$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4, 45.33.32.156';

		$ip = $proxy->get_real_ip();

		$this->reset_loader( $proxy );
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );

		$this->assertEquals( '45.33.32.156', $ip );
	}

	/**
	 * Inyectar un loader con settings predefinidos, sin tocar la base de datos.
	 */
	private function with_settings( WPS_Proxy_Config $proxy, array $settings ): void {
		$loader     = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache_prop = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache_prop->setAccessible( true );
		$cache_prop->setValue( $loader, $settings );

		$proxy->set_loader( $loader );
	}

	/**
	 * Quitar el loader inyectado para no filtrar estado entre tests.
	 */
	private function reset_loader( WPS_Proxy_Config $proxy ): void {
		$prop = new \ReflectionProperty( 'WPS_Proxy_Config', 'loader' );
		$prop->setAccessible( true );
		$prop->setValue( $proxy, null );
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
