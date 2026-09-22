<?php
/**
 * Tests unitarios para WPS_Ip_Utils.
 */
class Test_WPS_Ip_Utils extends \PHPUnit\Framework\TestCase {

	/**
	 * @var array
	 */
	private $fixtures;

	protected function setUp(): void {
		$this->fixtures = require dirname( __DIR__ ) . '/fixtures/ips.php';
	}

	/*──────────────────────────────────────────────
	 * Validación de IP
	 *──────────────────────────────────────────────*/

	public function test_valid_ipv4(): void {
		foreach ( $this->fixtures['valid_ipv4'] as $ip ) {
			$this->assertTrue( WPS_Ip_Utils::is_valid_ip( $ip ), "Debería ser válida: {$ip}" );
			$this->assertTrue( WPS_Ip_Utils::is_ipv4( $ip ), "Debería ser IPv4: {$ip}" );
		}
	}

	public function test_valid_ipv6(): void {
		foreach ( $this->fixtures['valid_ipv6'] as $ip ) {
			$this->assertTrue( WPS_Ip_Utils::is_valid_ip( $ip ), "Debería ser válida: {$ip}" );
			$this->assertTrue( WPS_Ip_Utils::is_ipv6( $ip ), "Debería ser IPv6: {$ip}" );
		}
	}

	public function test_invalid_ips(): void {
		foreach ( $this->fixtures['invalid'] as $ip ) {
			$this->assertFalse( WPS_Ip_Utils::is_valid_ip( $ip ), "No debería ser válida: {$ip}" );
		}
	}

	/*──────────────────────────────────────────────
	 * IPs privadas
	 *──────────────────────────────────────────────*/

	public function test_private_ips(): void {
		foreach ( $this->fixtures['private'] as $ip ) {
			$this->assertTrue( WPS_Ip_Utils::is_private_ip( $ip ), "Debería ser privada: {$ip}" );
		}
	}

	public function test_public_ips(): void {
		foreach ( $this->fixtures['public'] as $ip ) {
			$this->assertFalse( WPS_Ip_Utils::is_private_ip( $ip ), "Debería ser pública: {$ip}" );
		}
	}

	/*──────────────────────────────────────────────
	 * Conversión binaria
	 *──────────────────────────────────────────────*/

	public function test_ip_to_binary_and_back(): void {
		$ips = array( '8.8.8.8', '192.168.1.1', '::1', '2001:db8::1' );
		foreach ( $ips as $ip ) {
			$binary = WPS_Ip_Utils::ip_to_binary( $ip );
			$this->assertNotNull( $binary, "Debería convertir: {$ip}" );
			$this->assertEquals( 16, strlen( $binary ), "Debería ser 16 bytes: {$ip}" );

			$back = WPS_Ip_Utils::binary_to_ip( $binary );
			$this->assertNotNull( $back );
			// Normalizar para comparación.
			$this->assertEquals(
				inet_ntop( inet_pton( $ip ) ),
				inet_ntop( inet_pton( $back ) ),
				"Roundtrip debería coincidir: {$ip}"
			);
		}
	}

	public function test_ip_to_binary_invalid(): void {
		$this->assertNull( WPS_Ip_Utils::ip_to_binary( 'not-an-ip' ) );
	}

	/*──────────────────────────────────────────────
	 * CIDR
	 *──────────────────────────────────────────────*/

	public function test_ip_in_cidr(): void {
		foreach ( $this->fixtures['cidrs'] as $cidr => $data ) {
			$this->assertTrue(
				WPS_Ip_Utils::ip_in_cidr( $data['in'], $cidr ),
				"{$data['in']} debería estar en {$cidr}"
			);
			$this->assertFalse(
				WPS_Ip_Utils::ip_in_cidr( $data['out'], $cidr ),
				"{$data['out']} no debería estar en {$cidr}"
			);
		}
	}

	public function test_ip_in_cidr_exact_match(): void {
		$this->assertTrue( WPS_Ip_Utils::ip_in_cidr( '1.2.3.4', '1.2.3.4/32' ) );
		$this->assertFalse( WPS_Ip_Utils::ip_in_cidr( '1.2.3.5', '1.2.3.4/32' ) );
	}

	public function test_is_valid_cidr(): void {
		$this->assertTrue( WPS_Ip_Utils::is_valid_cidr( '192.168.1.0/24' ) );
		$this->assertTrue( WPS_Ip_Utils::is_valid_cidr( '10.0.0.0/8' ) );
		$this->assertTrue( WPS_Ip_Utils::is_valid_cidr( '2001:db8::/32' ) );
		$this->assertFalse( WPS_Ip_Utils::is_valid_cidr( '192.168.1.0' ) );
		$this->assertFalse( WPS_Ip_Utils::is_valid_cidr( '192.168.1.0/33' ) );
		$this->assertFalse( WPS_Ip_Utils::is_valid_cidr( 'invalid/24' ) );
	}

	/*──────────────────────────────────────────────
	 * Rangos
	 *──────────────────────────────────────────────*/

	public function test_cidr_to_range(): void {
		$range = WPS_Ip_Utils::cidr_to_range( '192.168.1.0/24' );
		$this->assertNotNull( $range );
		$this->assertArrayHasKey( 'start', $range );
		$this->assertArrayHasKey( 'end', $range );

		// 192.168.1.0 debería estar en el rango.
		$this->assertTrue( WPS_Ip_Utils::ip_in_range( '192.168.1.0', $range['start'], $range['end'] ) );
		$this->assertTrue( WPS_Ip_Utils::ip_in_range( '192.168.1.255', $range['start'], $range['end'] ) );
		$this->assertFalse( WPS_Ip_Utils::ip_in_range( '192.168.2.0', $range['start'], $range['end'] ) );
	}

	public function test_cidr_to_range_invalid(): void {
		$this->assertNull( WPS_Ip_Utils::cidr_to_range( 'invalid' ) );
	}

	/*──────────────────────────────────────────────
	 * strip_port
	 *──────────────────────────────────────────────*/

	public function test_strip_port_ipv4_with_port(): void {
		$this->assertEquals( '69.171.230.40', WPS_Ip_Utils::strip_port( '69.171.230.40:53776' ) );
		$this->assertEquals( '173.252.70.9', WPS_Ip_Utils::strip_port( '173.252.70.9:40020' ) );
		$this->assertEquals( '69.171.234.17', WPS_Ip_Utils::strip_port( '69.171.234.17:54572' ) );
		$this->assertEquals( '1.2.3.4', WPS_Ip_Utils::strip_port( '1.2.3.4:80' ) );
	}

	public function test_strip_port_plain_ipv4_unchanged(): void {
		$this->assertEquals( '1.2.3.4', WPS_Ip_Utils::strip_port( '1.2.3.4' ) );
		$this->assertEquals( '203.0.113.50', WPS_Ip_Utils::strip_port( '203.0.113.50' ) );
	}

	public function test_strip_port_ipv6_with_brackets_and_port(): void {
		$this->assertEquals( '2001:db8::1', WPS_Ip_Utils::strip_port( '[2001:db8::1]:80' ) );
		$this->assertEquals( '::1', WPS_Ip_Utils::strip_port( '[::1]:443' ) );
	}

	public function test_strip_port_plain_ipv6_unchanged(): void {
		$this->assertEquals( '2001:db8::1', WPS_Ip_Utils::strip_port( '2001:db8::1' ) );
		$this->assertEquals( '::1', WPS_Ip_Utils::strip_port( '::1' ) );
	}

	public function test_strip_port_trims_whitespace(): void {
		$this->assertEquals( '1.2.3.4', WPS_Ip_Utils::strip_port( '  1.2.3.4:8080  ' ) );
	}

	/*──────────────────────────────────────────────
	 * sanitize_ip
	 *──────────────────────────────────────────────*/

	public function test_sanitize_ip_with_port(): void {
		$this->assertEquals( '69.171.230.40', WPS_Ip_Utils::sanitize_ip( '69.171.230.40:53776' ) );
		$this->assertEquals( '173.252.70.9', WPS_Ip_Utils::sanitize_ip( '173.252.70.9:40020' ) );
		$this->assertEquals( '69.171.234.17', WPS_Ip_Utils::sanitize_ip( '69.171.234.17:54572' ) );
	}

	public function test_sanitize_ip_without_port(): void {
		$this->assertEquals( '1.2.3.4', WPS_Ip_Utils::sanitize_ip( '1.2.3.4' ) );
		$this->assertEquals( '2001:db8::1', WPS_Ip_Utils::sanitize_ip( '2001:db8::1' ) );
	}

	public function test_sanitize_ip_invalid_returns_null(): void {
		$this->assertNull( WPS_Ip_Utils::sanitize_ip( 'not-an-ip' ) );
		$this->assertNull( WPS_Ip_Utils::sanitize_ip( '' ) );
		$this->assertNull( WPS_Ip_Utils::sanitize_ip( '999.999.999.999:80' ) );
	}

	public function test_sanitize_ip_ipv6_bracket_port(): void {
		$this->assertEquals( '2001:db8::1', WPS_Ip_Utils::sanitize_ip( '[2001:db8::1]:443' ) );
	}

	/*──────────────────────────────────────────────
	 * Network
	 *──────────────────────────────────────────────*/

	public function test_get_network(): void {
		$network = WPS_Ip_Utils::get_network( '192.168.1.100' );
		$this->assertNotNull( $network );
		$this->assertStringContainsString( '/24', $network );
	}

	public function test_get_network_ipv6(): void {
		$network = WPS_Ip_Utils::get_network( '2001:db8::1' );
		$this->assertNotNull( $network );
		$this->assertStringContainsString( '/48', $network );
	}

	/*──────────────────────────────────────────────
	 * Familias de IP
	 *──────────────────────────────────────────────*/

	public function test_ipv6_never_matches_an_ipv4_cidr(): void {
		$this->assertFalse( WPS_Ip_Utils::ip_in_cidr( '::1', '127.0.0.0/8' ) );
		$this->assertFalse( WPS_Ip_Utils::ip_in_cidr( '::5', '0.0.0.0/8' ) );
	}

	public function test_ipv4_never_matches_an_ipv6_cidr(): void {
		$this->assertFalse( WPS_Ip_Utils::ip_in_cidr( '10.0.0.1', '::/8' ) );
	}

	/*──────────────────────────────────────────────
	 * IP del propio servidor
	 *──────────────────────────────────────────────*/

	public function test_loopback_is_the_server(): void {
		$this->assertTrue( WPS_Ip_Utils::is_server_ip( '127.0.0.1' ) );
		$this->assertTrue( WPS_Ip_Utils::is_server_ip( '127.0.1.1' ) );
		$this->assertTrue( WPS_Ip_Utils::is_server_ip( '::1' ) );
	}

	public function test_server_addr_is_the_server(): void {
		$_SERVER['SERVER_ADDR'] = '203.0.113.10';
		try {
			$this->assertTrue( WPS_Ip_Utils::is_server_ip( '203.0.113.10' ) );
			$this->assertFalse( WPS_Ip_Utils::is_server_ip( '203.0.113.11' ) );
		} finally {
			unset( $_SERVER['SERVER_ADDR'] );
		}
	}

	public function test_visitor_ip_is_not_the_server(): void {
		$this->assertFalse( WPS_Ip_Utils::is_server_ip( '45.33.32.156' ) );
		$this->assertFalse( WPS_Ip_Utils::is_server_ip( 'not-an-ip' ) );
	}
}
