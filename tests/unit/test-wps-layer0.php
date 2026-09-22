<?php
/**
 * Tests de la Capa 0: el archivo de datos y su lectura en el prepend.
 *
 * La Capa 0 corre antes de WordPress y sin base de datos, así que todo lo que
 * necesita saber (vencimientos, whitelist por rango) tiene que estar en el
 * archivo generado.
 */
class Test_WPS_Layer0 extends \PHPUnit\Framework\TestCase {

	public static function setUpBeforeClass(): void {
		// Sin REMOTE_ADDR el prepend no hace nada al cargarse.
		unset( $_SERVER['REMOTE_ADDR'] );
		require_once WPS_INCLUDES_DIR . 'firewall/wps-firewall-prepend.php';
	}

	/*──────────────────────────────────────────────
	 * Generación del archivo
	 *──────────────────────────────────────────────*/

	public function test_temporary_block_carries_its_expiry(): void {
		$data = WPS_Activator::build_blocked_ips_data(
			array( array( 'ip_address' => '45.33.32.156', 'cidr' => null, 'expires_at' => '2026-09-22 12:15:00' ) ),
			array(),
			0
		);

		$this->assertSame( strtotime( '2026-09-22 12:15:00 UTC' ), $data['ips']['45.33.32.156'] );
	}

	public function test_permanent_block_has_no_expiry(): void {
		$data = WPS_Activator::build_blocked_ips_data(
			array( array( 'ip_address' => '45.33.32.156', 'cidr' => null, 'expires_at' => null ) ),
			array(),
			0
		);

		$this->assertSame( 0, $data['ips']['45.33.32.156'] );
	}

	public function test_longest_block_wins_when_an_ip_has_several(): void {
		$data = WPS_Activator::build_blocked_ips_data(
			array(
				array( 'ip_address' => '45.33.32.156', 'cidr' => null, 'expires_at' => '2026-09-22 12:15:00' ),
				array( 'ip_address' => '45.33.32.156', 'cidr' => null, 'expires_at' => null ),
				array( 'ip_address' => '45.33.32.157', 'cidr' => null, 'expires_at' => '2026-09-22 12:15:00' ),
				array( 'ip_address' => '45.33.32.157', 'cidr' => null, 'expires_at' => '2026-09-22 18:00:00' ),
			),
			array(),
			0
		);

		$this->assertSame( 0, $data['ips']['45.33.32.156'] );
		$this->assertSame( strtotime( '2026-09-22 18:00:00 UTC' ), $data['ips']['45.33.32.157'] );
	}

	public function test_cidr_blocks_and_whitelist_ranges_are_exported(): void {
		$data = WPS_Activator::build_blocked_ips_data(
			array( array( 'ip_address' => null, 'cidr' => '198.51.100.0/24', 'expires_at' => null ) ),
			array(
				array( 'ip_address' => '203.0.113.7', 'cidr' => null ),
				array( 'ip_address' => null, 'cidr' => '192.0.2.0/24' ),
			),
			0
		);

		$this->assertSame( array( '198.51.100.0/24' => 0 ), $data['cidrs'] );
		$this->assertArrayHasKey( '203.0.113.7', $data['whitelist'] );
		$this->assertSame( array( '192.0.2.0/24' ), $data['whitelist_cidrs'] );
	}

	/*──────────────────────────────────────────────
	 * Lectura en el prepend
	 *──────────────────────────────────────────────*/

	public function test_expired_block_no_longer_applies(): void {
		$data = array( 'ips' => array( '45.33.32.156' => time() - 60 ) );

		$this->assertFalse( $this->prepend( 'is_blocked', '45.33.32.156', $data ) );
	}

	public function test_active_temporary_block_applies(): void {
		$data = array( 'ips' => array( '45.33.32.156' => time() + 600 ) );

		$this->assertTrue( $this->prepend( 'is_blocked', '45.33.32.156', $data ) );
	}

	public function test_previous_file_format_still_blocks(): void {
		// Formato hasta 0.3.0: valor 1 por IP y lista plana de CIDRs.
		$data = array(
			'ips'   => array( '45.33.32.156' => 1 ),
			'cidrs' => array( '198.51.100.0/24' ),
		);

		$this->assertTrue( $this->prepend( 'is_blocked', '45.33.32.156', $data ) );
		$this->assertTrue( $this->prepend( 'is_blocked', '198.51.100.20', $data ) );
		$this->assertFalse( $this->prepend( 'is_blocked', '203.0.113.1', $data ) );
	}

	public function test_expired_cidr_block_no_longer_applies(): void {
		$data = array( 'cidrs' => array( '198.51.100.0/24' => time() - 60 ) );

		$this->assertFalse( $this->prepend( 'is_blocked', '198.51.100.20', $data ) );
	}

	public function test_whitelisted_range_is_honored(): void {
		$data = array( 'whitelist_cidrs' => array( '192.0.2.0/24' ) );

		$this->assertTrue( $this->prepend( 'is_whitelisted', '192.0.2.44', $data ) );
		$this->assertFalse( $this->prepend( 'is_whitelisted', '192.0.3.44', $data ) );
	}

	private function prepend( string $method, string $ip, array $data ): bool {
		$ref = new \ReflectionMethod( 'WPS_Firewall_Prepend', $method );
		$ref->setAccessible( true );
		return $ref->invoke( null, $ip, $data );
	}
}
