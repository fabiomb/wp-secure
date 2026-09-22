<?php
/**
 * Tests de la agrupación de clientes IPv6 por prefijo.
 *
 * Un cliente IPv6 recibe normalmente un /64 entero y puede usar una dirección
 * distinta en cada petición. Si el rate limiting, el conteo de logins y los
 * bloqueos automáticos trabajan con la dirección exacta, rotar alcanza para
 * esquivarlos todos.
 */
class Test_WPS_Ipv6_Client extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']->reset_queries();
		unset( $_SERVER['SERVER_ADDR'] );
	}

	/*──────────────────────────────────────────────
	 * Clave de cliente
	 *──────────────────────────────────────────────*/

	public function test_ipv4_key_is_the_ip(): void {
		$this->assertSame( '45.33.32.156', WPS_Ip_Utils::client_key( '45.33.32.156' ) );
	}

	public function test_addresses_in_the_same_64_share_a_key(): void {
		$a = WPS_Ip_Utils::client_key( '2001:db8:1:2:aaaa:bbbb:cccc:dddd' );
		$b = WPS_Ip_Utils::client_key( '2001:db8:1:2::1' );

		$this->assertSame( '2001:db8:1:2::/64', $a );
		$this->assertSame( $a, $b );
	}

	public function test_different_64_networks_have_different_keys(): void {
		$this->assertNotSame(
			WPS_Ip_Utils::client_key( '2001:db8:1:2::1' ),
			WPS_Ip_Utils::client_key( '2001:db8:1:3::1' )
		);
	}

	public function test_prefix_128_keeps_the_exact_address(): void {
		$this->assertSame( '2001:db8:1:2::1', WPS_Ip_Utils::client_key( '2001:db8:1:2::1', 128 ) );
	}

	public function test_custom_prefix_is_applied(): void {
		$this->assertSame( '2001:db8:1::/56', WPS_Ip_Utils::client_key( '2001:db8:1:2::1', 56 ) );
	}

	public function test_out_of_range_prefix_falls_back_to_default(): void {
		// Un 0 de un formulario vacío no puede terminar bloqueando un /48.
		$this->assertSame( 64, WPS_Ip_Utils::clamp_ipv6_prefix( 0 ) );
		$this->assertSame( 64, WPS_Ip_Utils::clamp_ipv6_prefix( 32 ) );
		$this->assertSame( 64, WPS_Ip_Utils::clamp_ipv6_prefix( 129 ) );
		$this->assertSame( 48, WPS_Ip_Utils::clamp_ipv6_prefix( 48 ) );
	}

	/*──────────────────────────────────────────────
	 * Bloqueo automático
	 *──────────────────────────────────────────────*/

	public function test_automatic_block_of_ipv6_blocks_the_network(): void {
		WPS_Blocker::get_instance()->block_offender( '2001:db8:1:2::1', 'auto_sqli', 'test', 15 );

		$row = $this->last_block_insert();
		$this->assertNotNull( $row );
		$this->assertSame( '2001:db8:1:2::/64', $row['cidr'] );
		$this->assertArrayNotHasKey( 'ip_address', $row );
	}

	public function test_automatic_block_of_ipv4_blocks_the_ip(): void {
		WPS_Blocker::get_instance()->block_offender( '45.33.32.156', 'auto_sqli', 'test', 15 );

		$row = $this->last_block_insert();
		$this->assertSame( '45.33.32.156', $row['ip_address'] );
		$this->assertArrayNotHasKey( 'cidr', $row );
	}

	public function test_network_that_contains_the_server_is_not_blocked_whole(): void {
		// La Capa 0 no exime al servidor: bloquear su /64 le cortaría wp-cron.
		$_SERVER['SERVER_ADDR'] = '2001:db8:1:2::10';

		WPS_Blocker::get_instance()->block_offender( '2001:db8:1:2::99', 'auto_rate', 'test', 15 );

		$row = $this->last_block_insert();
		$this->assertSame( '2001:db8:1:2::99', $row['ip_address'] );
		$this->assertArrayNotHasKey( 'cidr', $row );
	}

	public function test_automatic_block_never_targets_the_server(): void {
		$this->assertFalse( WPS_Blocker::get_instance()->block_offender( '::1', 'auto_rate', 'test', 15 ) );
		$this->assertNull( $this->last_block_insert() );
	}

	/*──────────────────────────────────────────────
	 * Rate limiting
	 *──────────────────────────────────────────────*/

	public function test_rate_limit_counts_the_whole_64_together(): void {
		$prop = new \ReflectionProperty( 'WPS_Rate_Limiter', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );

		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, array( 'rate_total_per_min' => 240 ) );
		$limiter = WPS_Rate_Limiter::get_instance( $loader );

		$GLOBALS['wpdb']->reset_queries();
		$limiter->record_hit( '2001:db8:1:2::1', 'total' );
		$limiter->record_hit( '2001:db8:1:2::2', 'total' );

		$keys = array_column( $GLOBALS['wpdb']->prepared_args, 0 );
		$this->assertSame( array( '2001:db8:1:2::/64', '2001:db8:1:2::/64' ), $keys );
	}

	private function last_block_insert(): ?array {
		$rows = array_filter( $GLOBALS['wpdb']->inserts, function ( $insert ) {
			return 'wp_wps_blocked_ips' === $insert[0];
		} );

		return $rows ? end( $rows )[1] : null;
	}
}
