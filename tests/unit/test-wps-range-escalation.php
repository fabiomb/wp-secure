<?php
/**
 * Tests de la escalada de bloqueos de IP a rango.
 */
class Test_WPS_Range_Escalation extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $server;

	protected function setUp(): void {
		$this->server = $_SERVER;
		unset( $_SERVER['SERVER_ADDR'], $_SERVER['LOCAL_ADDR'] );
		$GLOBALS['wpdb']->reset_queries();
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
	}

	/*──────────────────────────────────────────────
	 * Conteo
	 *──────────────────────────────────────────────*/

	public function test_ranges(): void {
		$this->assertSame( '203.0.113.0/24', WPS_Range_Escalation::range_for( '203.0.113.77' ) );
		$this->assertSame( '2001:db8:1::/48', WPS_Range_Escalation::range_for( '2001:db8:1:2::5' ) );
		$this->assertNull( WPS_Range_Escalation::range_for( 'no-ip' ) );
	}

	public function test_offenders_are_distinct_clients_inside_the_range(): void {
		$rows = array(
			array( 'ip_address' => '203.0.113.1', 'cidr' => null ),
			array( 'ip_address' => '203.0.113.1', 'cidr' => null ), // Misma IP, otro bloqueo.
			array( 'ip_address' => '203.0.113.2', 'cidr' => null ),
			array( 'ip_address' => '203.0.114.3', 'cidr' => null ), // Otro /24.
		);

		$this->assertSame( 2, WPS_Range_Escalation::count_offenders( $rows, '203.0.113.0/24' ) );
	}

	public function test_ipv6_offenders_are_networks(): void {
		$rows = array(
			array( 'ip_address' => null, 'cidr' => '2001:db8:1:1::/64' ),
			array( 'ip_address' => null, 'cidr' => '2001:db8:1:2::/64' ),
			array( 'ip_address' => null, 'cidr' => '2001:db8:2:1::/64' ),
		);

		$this->assertSame( 2, WPS_Range_Escalation::count_offenders( $rows, '2001:db8:1::/48' ) );
	}

	public function test_overlaps(): void {
		$this->assertTrue( WPS_Range_Escalation::overlaps( '203.0.113.9', '203.0.113.0/24' ) );
		$this->assertTrue( WPS_Range_Escalation::overlaps( '203.0.0.0/16', '203.0.113.0/24' ), 'Un rango más amplio también.' );
		$this->assertTrue( WPS_Range_Escalation::overlaps( '203.0.113.128/25', '203.0.113.0/24' ) );
		$this->assertFalse( WPS_Range_Escalation::overlaps( '203.0.114.9', '203.0.113.0/24' ) );
		$this->assertTrue( WPS_Range_Escalation::overlaps( '2001:db8:1:5::/64', '2001:db8:1::/48' ) );
	}

	/*──────────────────────────────────────────────
	 * Escalada
	 *──────────────────────────────────────────────*/

	public function test_range_is_blocked_at_the_threshold(): void {
		$escalation = $this->escalation( array( 'rows' => $this->ipv4_rows( 3 ) ) );

		$this->assertNotNull( $escalation->maybe_escalate( '203.0.113.3' ) );

		$insert = $this->range_insert();
		$this->assertSame( '203.0.113.0/24', $insert['cidr'] );
		$this->assertSame( 'auto_range', $insert['block_type'] );
		$this->assertNotEmpty( $insert['expires_at'], 'Temporal, no permanente.' );
	}

	public function test_below_the_threshold_nothing_happens(): void {
		$this->assertNull( $this->escalation( array( 'rows' => $this->ipv4_rows( 2 ) ) )->maybe_escalate( '203.0.113.2' ) );
		$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
	}

	public function test_threshold_is_configurable(): void {
		$escalation = $this->escalation( array( 'rows' => $this->ipv4_rows( 3 ) ), array( 'range_escalation_threshold' => 5 ) );

		$this->assertNull( $escalation->maybe_escalate( '203.0.113.3' ) );
	}

	public function test_disabled_escalation(): void {
		$escalation = $this->escalation( array( 'rows' => $this->ipv4_rows( 10 ) ), array( 'range_escalation_enabled' => false ) );

		$this->assertNull( $escalation->maybe_escalate( '203.0.113.3' ) );
	}

	public function test_already_blocked_range_is_not_blocked_again(): void {
		$this->assertNull( $this->escalation( array( 'rows' => $this->ipv4_rows( 5 ), 'blocked' => true ) )->maybe_escalate( '203.0.113.3' ) );
	}

	public function test_range_with_a_whitelisted_ip_is_never_blocked(): void {
		$escalation = $this->escalation( array( 'rows' => $this->ipv4_rows( 5 ), 'whitelist' => array( '203.0.113.200' ) ) );

		$this->assertNull( $escalation->maybe_escalate( '203.0.113.3' ) );
		$this->assertSame( 'whitelist', $escalation->protection( '203.0.113.0/24' ) );
	}

	public function test_range_where_a_user_logged_in_is_never_blocked(): void {
		$escalation = $this->escalation( array( 'rows' => $this->ipv4_rows( 5 ), 'known' => array( '203.0.113.50' ) ) );

		$this->assertNull( $escalation->maybe_escalate( '203.0.113.3' ), 'El administrador no puede quedar afuera.' );
	}

	public function test_range_containing_the_server_is_never_blocked(): void {
		$_SERVER['SERVER_ADDR'] = '203.0.113.10';

		$this->assertSame( 'server', $this->escalation( array() )->protection( '203.0.113.0/24' ) );
	}

	public function test_ipv6_with_a_48_client_prefix_does_not_escalate(): void {
		$rows       = array(
			array( 'ip_address' => null, 'cidr' => '2001:db8:1::/48' ),
			array( 'ip_address' => null, 'cidr' => '2001:db8:1::/48' ),
			array( 'ip_address' => null, 'cidr' => '2001:db8:1::/48' ),
		);
		$escalation = $this->escalation( array( 'rows' => $rows ), array( 'ipv6_block_prefix' => 48 ) );

		$this->assertNull( $escalation->maybe_escalate( '2001:db8:1:2::5' ) );
	}

	public function test_new_automatic_block_checks_its_range(): void {
		$this->loader( array() );
		WPS_Blocker::get_instance()->block_offender( '203.0.113.9', 'auto_sqli', 'prueba', 15 );

		$checked = array_filter( $GLOBALS['wpdb']->queries, function ( $sql ) {
			return false !== strpos( (string) $sql, 'DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)' );
		} );
		$this->assertCount( 1, $checked );
	}

	public function test_recent_rows_query_excludes_manual_unblocks_and_range_blocks(): void {
		$escalation = new WPS_Range_Escalation( $this->loader( array() ), WPS_Blocker::get_instance() );
		$method     = new \ReflectionMethod( $escalation, 'recent_rows' );
		$method->setAccessible( true );
		$method->invoke( $escalation, '203.0.113.0/24', 60 );

		$sql = end( $GLOBALS['wpdb']->queries );
		$this->assertStringContainsString( "is_active = 1 OR ( expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP() )", $sql );
		$this->assertSame( array( 'auto_range', 60, '203.0.113.%', WPS_Range_Escalation::MAX_ROWS ), $GLOBALS['wpdb']->prepared_args[0] );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function ipv4_rows( int $count ): array {
		$rows = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$rows[] = array( 'ip_address' => "203.0.113.{$i}", 'cidr' => null );
		}
		return $rows;
	}

	private function range_insert(): array {
		$this->assertCount( 1, $GLOBALS['wpdb']->inserts );
		return $GLOBALS['wpdb']->inserts[0][1];
	}

	private function loader( array $settings ): WPS_Loader {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );
		return $loader;
	}

	private function escalation( array $data, array $settings = array() ): WPS_Range_Escalation {
		$data += array( 'rows' => array(), 'blocked' => false, 'whitelist' => array(), 'known' => array() );

		return new class( $this->loader( $settings ), WPS_Blocker::get_instance(), $data ) extends WPS_Range_Escalation {
			private $data;

			public function __construct( WPS_Loader $loader, WPS_Blocker $blocker, array $data ) {
				parent::__construct( $loader, $blocker );
				$this->data = $data;
			}
			protected function recent_rows( string $range, int $window_minutes ): array {
				return $this->data['rows'];
			}
			protected function range_blocked( string $range ): bool {
				return $this->data['blocked'];
			}
			protected function whitelist_entries(): array {
				return $this->data['whitelist'];
			}
			protected function known_login_networks(): array {
				return $this->data['known'];
			}
		};
	}
}
