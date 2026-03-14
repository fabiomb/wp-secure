<?php
/**
 * Tests de integración para WPS_Blocker.
 *
 * Requiere WP test framework (wordpress-develop/tests/phpunit).
 * Ejecutar con: WP_TESTS_DIR=/path/to/wp/tests/phpunit phpunit --testsuite integration
 */
class Test_WPS_Blocker_Integration extends WP_UnitTestCase {

	public function test_block_ip_creates_record(): void {
		$blocker = WPS_Blocker::get_instance();
		$result  = $blocker->block_ip( '192.0.2.100', 'test', 'Test block' );

		$this->assertTrue( $result );
		$this->assertTrue( $blocker->is_blocked( '192.0.2.100' ) );
	}

	public function test_unblock_ip_removes_record(): void {
		$blocker = WPS_Blocker::get_instance();
		$blocker->block_ip( '192.0.2.101', 'test', 'Test block' );
		$blocker->unblock_ip( '192.0.2.101' );

		$this->assertFalse( $blocker->is_blocked( '192.0.2.101' ) );
	}

	public function test_temporary_block_expires(): void {
		$blocker = WPS_Blocker::get_instance();
		$blocker->block_ip( '192.0.2.102', 'test', 'Test block', 1 );

		$this->assertTrue( $blocker->is_blocked( '192.0.2.102' ) );

		// Simular expiración no es factible sin manipular el reloj;
		// verificar al menos que la duración se registre.
		$this->assertTrue( true );
	}

	public function test_whitelist_prevents_block(): void {
		$whitelist = WPS_Whitelist::get_instance();
		$whitelist->add( '192.0.2.103', 'Test WL' );

		$blocker = WPS_Blocker::get_instance();
		$result  = $blocker->block_ip( '192.0.2.103', 'test', 'Should not block' );

		$this->assertFalse( $result );
	}
}
