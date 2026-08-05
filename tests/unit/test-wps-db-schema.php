<?php
/**
 * Tests unitarios para WPS_Db_Schema.
 */
class Test_WPS_Db_Schema extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']->reset_queries();
		WPS_Db_Schema::flush_table_cache();
	}

	public function test_table_name_uses_the_plugin_prefix(): void {
		$this->assertEquals( 'wp_wps_blocked_ips', WPS_Db_Schema::table( 'blocked_ips' ) );
	}

	/*──────────────────────────────────────────────
	 * Costo de verificar el esquema
	 *──────────────────────────────────────────────*/

	public function test_checking_tables_uses_a_single_query(): void {
		WPS_Db_Schema::tables_exist();

		$this->assertCount(
			1,
			$GLOBALS['wpdb']->queries,
			'Verificar el esquema no puede costar una query por tabla en cada petición.'
		);
	}

	public function test_repeated_checks_are_memoized(): void {
		WPS_Db_Schema::tables_exist();
		WPS_Db_Schema::tables_exist();
		WPS_Db_Schema::tables_exist();

		$this->assertCount( 1, $GLOBALS['wpdb']->queries );
	}

	public function test_flush_forces_a_new_check(): void {
		WPS_Db_Schema::tables_exist();
		WPS_Db_Schema::flush_table_cache();
		WPS_Db_Schema::tables_exist();

		$this->assertCount( 2, $GLOBALS['wpdb']->queries );
	}

	public function test_reports_missing_tables(): void {
		// El doble de $wpdb no devuelve ninguna tabla.
		$this->assertFalse( WPS_Db_Schema::tables_exist() );
	}

	public function test_declares_every_table_it_creates(): void {
		$declared = WPS_Db_Schema::table_names();

		$source = file_get_contents( dirname( __DIR__, 2 ) . '/includes/database/class-wps-db-schema.php' );
		preg_match_all( "/self::table\(\s*'([a-z_]+)'\s*\)/", $source, $matches );

		foreach ( array_unique( $matches[1] ) as $used ) {
			$this->assertContains(
				$used,
				$declared,
				"La tabla '{$used}' se usa pero no está en la lista canónica."
			);
		}
	}
}
