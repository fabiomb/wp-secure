<?php
/**
 * Tests unitarios para WPS_Whitelist.
 *
 * is_whitelisted() se consulta una decena de veces por petición (loader, cada
 * detector, hardener, rate limiter), así que su costo en queries importa tanto
 * como que la coincidencia sea correcta.
 */
class Test_WPS_Whitelist extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$this->reset_singleton();
		$GLOBALS['wpdb']->reset_queries();
	}

	private function reset_singleton(): void {
		$prop = new \ReflectionProperty( 'WPS_Whitelist', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}

	/*──────────────────────────────────────────────
	 * Costo de acceso a base de datos
	 *──────────────────────────────────────────────*/

	public function test_repeated_checks_query_the_database_once(): void {
		$whitelist = WPS_Whitelist::get_instance();

		$whitelist->is_whitelisted( '45.33.32.156' );
		$whitelist->is_whitelisted( '45.33.32.156' );
		$whitelist->is_whitelisted( '8.8.8.8' );
		$whitelist->is_whitelisted( '8.8.8.8', 'login' );

		$this->assertCount(
			1,
			$GLOBALS['wpdb']->queries,
			'La whitelist debe cargarse una sola vez por petición y resolverse en memoria.'
		);
	}

	/*──────────────────────────────────────────────
	 * Coincidencia de entradas
	 *──────────────────────────────────────────────*/

	public function test_matches_exact_ip(): void {
		$entries = array(
			array( 'ip_address' => '45.33.32.156', 'cidr' => null, 'whitelist_type' => 'global' ),
		);

		$this->assertTrue( WPS_Whitelist::matches_entries( '45.33.32.156', 'global', $entries ) );
		$this->assertFalse( WPS_Whitelist::matches_entries( '8.8.8.8', 'global', $entries ) );
	}

	public function test_matches_cidr_range(): void {
		$entries = array(
			array( 'ip_address' => null, 'cidr' => '45.33.32.0/24', 'whitelist_type' => 'global' ),
		);

		$this->assertTrue( WPS_Whitelist::matches_entries( '45.33.32.156', 'global', $entries ) );
		$this->assertFalse( WPS_Whitelist::matches_entries( '45.33.33.1', 'global', $entries ) );
	}

	public function test_global_entry_applies_to_every_type(): void {
		$entries = array(
			array( 'ip_address' => '45.33.32.156', 'cidr' => null, 'whitelist_type' => 'global' ),
		);

		$this->assertTrue( WPS_Whitelist::matches_entries( '45.33.32.156', 'login', $entries ) );
	}

	public function test_typed_entry_does_not_apply_to_other_types(): void {
		$entries = array(
			array( 'ip_address' => '45.33.32.156', 'cidr' => null, 'whitelist_type' => 'login' ),
		);

		$this->assertTrue( WPS_Whitelist::matches_entries( '45.33.32.156', 'login', $entries ) );
		$this->assertFalse(
			WPS_Whitelist::matches_entries( '45.33.32.156', 'global', $entries ),
			'Una entrada sólo para login no debe eximir del resto del firewall.'
		);
	}

	public function test_empty_whitelist_matches_nothing(): void {
		$this->assertFalse( WPS_Whitelist::matches_entries( '45.33.32.156', 'global', array() ) );
	}

	public function test_ignores_malformed_cidr_entries(): void {
		$entries = array(
			array( 'ip_address' => null, 'cidr' => 'no-es-un-rango', 'whitelist_type' => 'global' ),
		);

		$this->assertFalse( WPS_Whitelist::matches_entries( '45.33.32.156', 'global', $entries ) );
	}
}
