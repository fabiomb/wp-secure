<?php
/**
 * Tests de los comandos WP-CLI (`wp wps …`).
 */
class Test_WPS_Cli extends \PHPUnit\Framework\TestCase {

	/** @var WPS_CLI */
	private $cli;

	public static function setUpBeforeClass(): void {
		require_once dirname( __DIR__ ) . '/fixtures/wp-cli-stub.php';
	}

	protected function setUp(): void {
		WP_CLI::$log                   = array();
		$GLOBALS['wps_test_options']   = array();
		$GLOBALS['wps_test_mails']     = array();
		$GLOBALS['wps_test_cli_items'] = null;
		$GLOBALS['wpdb']->reset_queries();
		$this->cli = new WPS_CLI();
	}

	/*──────────────────────────────────────────────
	 * block / unblock
	 *──────────────────────────────────────────────*/

	public function test_block_an_ip_manually(): void {
		$this->cli->block( array( '203.0.113.7' ), array( 'minutes' => '60' ) );

		$row = $this->last_insert( 'wp_wps_blocked_ips' );
		$this->assertSame( '203.0.113.7', $row['ip_address'] );
		$this->assertSame( 'manual', $row['block_type'] );
		$this->assertSame( 'success', WP_CLI::last()[0] );
	}

	public function test_block_a_cidr(): void {
		$this->cli->block( array( '198.51.100.0/24' ), array() );

		$this->assertSame( '198.51.100.0/24', $this->last_insert( 'wp_wps_blocked_ips' )['cidr'] );
	}

	public function test_block_rejects_garbage(): void {
		$this->expectException( \RuntimeException::class );

		$this->cli->block( array( 'no-es-ip' ), array() );
	}

	public function test_unblock_also_lifts_network_blocks_that_contain_the_ip(): void {
		$this->cli->unblock( array( '2001:db8:1:2::99' ), array() );

		$query = end( $GLOBALS['wpdb']->queries );
		$this->assertStringContainsString( 'ip_range_start <=', $query, 'En IPv6 el bloqueo automático es del /64: desbloquear sólo la dirección no alcanza.' );
		$this->assertSame( 'warning', WP_CLI::last()[0], 'Sin bloqueos activos se avisa, no es un error.' );
	}

	/*──────────────────────────────────────────────
	 * whitelist
	 *──────────────────────────────────────────────*/

	public function test_whitelist_add_and_remove(): void {
		$this->cli->whitelist( array( 'add', '203.0.113.7' ), array( 'label' => 'Oficina' ) );

		$row = $this->last_insert( 'wp_wps_whitelist' );
		$this->assertSame( '203.0.113.7', $row['ip_address'] );
		$this->assertSame( 'Oficina', $row['label'] );
		$this->assertSame( 'global', $row['whitelist_type'] );

		$this->cli->whitelist( array( 'remove', '203.0.113.7' ), array() );
		$this->assertStringContainsString( 'DELETE FROM', end( $GLOBALS['wpdb']->queries ) );
	}

	public function test_whitelist_list_uses_the_requested_format(): void {
		$this->cli->whitelist( array( 'list' ), array( 'format' => 'json' ) );

		$this->assertSame( 'json', $GLOBALS['wps_test_cli_items']['format'] );
		$this->assertSame( array( 'id', 'target', 'type', 'label' ), $GLOBALS['wps_test_cli_items']['fields'] );
	}

	public function test_unknown_whitelist_action_is_an_error(): void {
		$this->expectException( \RuntimeException::class );

		$this->cli->whitelist( array( 'borrar-todo' ), array() );
	}

	/*──────────────────────────────────────────────
	 * unsafe-mode / status
	 *──────────────────────────────────────────────*/

	public function test_unsafe_mode_can_be_turned_on_and_off(): void {
		$this->cli->unsafe_mode( array( 'on' ), array() );
		$this->assertTrue( $GLOBALS['wps_test_options']['wps_unsafe_mode'] );
		$this->assertTrue( WPS_Blocker::blocking_disabled() );

		$this->cli->unsafe_mode( array( 'off' ), array() );
		$this->assertFalse( $GLOBALS['wps_test_options']['wps_unsafe_mode'] );
	}

	public function test_unsafe_mode_rejects_other_values(): void {
		$this->expectException( \RuntimeException::class );

		$this->cli->unsafe_mode( array( 'quizas' ), array() );
	}

	public function test_status_reports_the_firewall_state(): void {
		$this->cli->status( array(), array() );

		$items = array_column( $GLOBALS['wps_test_cli_items']['items'], 'value', 'item' );
		$this->assertArrayHasKey( 'Versión', $items );
		$this->assertSame( 'inactivo', $items['Modo Inseguro'] );
	}

	private function last_insert( string $table ): ?array {
		$rows = array_filter( $GLOBALS['wpdb']->inserts, function ( $insert ) use ( $table ) {
			return $table === $insert[0];
		} );
		return $rows ? end( $rows )[1] : null;
	}
}
