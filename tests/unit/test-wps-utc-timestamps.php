<?php
/**
 * Tests de regresión: las fechas se comparan en UTC.
 *
 * Todas las columnas de fecha del plugin se escriben en UTC desde PHP
 * (`gmdate()`, `current_time( 'mysql', true )`). `NOW()` devuelve la hora en
 * la zona horaria de la sesión MySQL, que WordPress no fija: con MySQL en
 * UTC-3 un bloqueo de 15 minutos duraba 3 h 15 min, y con UTC+2 vencía al
 * instante y el conteo de intentos de login daba siempre cero.
 */
class Test_WPS_Utc_Timestamps extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']->reset_queries();
	}

	public function test_block_lookup_compares_expiry_against_utc(): void {
		WPS_Blocker::get_instance()->is_blocked( '45.33.32.156' );

		$this->assertNotEmpty( $GLOBALS['wpdb']->queries );
		foreach ( $GLOBALS['wpdb']->queries as $query ) {
			$this->assertStringContainsString( 'UTC_TIMESTAMP()', $query );
			$this->assertStringNotContainsString( 'NOW()', $query );
		}
	}

	public function test_no_query_in_the_plugin_uses_session_local_time(): void {
		$offenders = array();

		$files = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( WPS_INCLUDES_DIR, \FilesystemIterator::SKIP_DOTS )
		);

		foreach ( $files as $file ) {
			if ( 'php' !== $file->getExtension() ) {
				continue;
			}

			$source = file_get_contents( $file->getPathname() );
			if ( preg_match( '/\b(?:NOW|CURDATE|CURTIME|SYSDATE)\s*\(\s*\)/i', $source ) ) {
				$offenders[] = str_replace( WPS_INCLUDES_DIR, '', $file->getPathname() );
			}
		}

		$this->assertSame(
			array(),
			$offenders,
			'Las fechas se guardan en UTC: usar UTC_TIMESTAMP() en lugar de NOW()/CURDATE().'
		);
	}
}
