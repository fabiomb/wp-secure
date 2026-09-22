<?php
/**
 * Tests unitarios para WPS_Blocker.
 */
class Test_WPS_Blocker extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']->reset_queries();
	}

	public function test_detectors_never_block_the_server_itself(): void {
		$blocker = WPS_Blocker::get_instance();

		$this->assertFalse( $blocker->block_ip( '127.0.0.1', 'auto_rate', 'test', 15 ) );
		$this->assertFalse( $blocker->block_ip( '::1', 'auto_scanner', 'test', 15 ) );
		$this->assertCount(
			0,
			$GLOBALS['wpdb']->queries,
			'Bloquear al servidor deja al sitio sin wp-cron ni loopbacks.'
		);
	}

	public function test_manual_block_of_server_ip_is_still_allowed(): void {
		WPS_Blocker::get_instance()->block_ip( '127.0.0.1', 'manual', 'test' );

		$this->assertNotEmpty( $GLOBALS['wpdb']->queries, 'El bloqueo manual sigue su curso normal.' );
	}
}
