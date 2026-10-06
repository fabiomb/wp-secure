<?php
/**
 * Tests de la exportación e importación de configuración.
 *
 * El archivo exportado suele terminar en correos, tickets o repositorios: no
 * puede llevar secretos. El importado viene de afuera: no puede dejar ajustes
 * desconocidos, fuera de rango ni con opciones inexistentes.
 */
class Test_WPS_Config_Export extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wpdb']->reset_queries();
		$this->set_settings( array(
			'ipinfo_api_key'      => 'token-secreto',
			'maxmind_license_key' => 'licencia-secreta',
			'rate_pages_per_min'  => 60,
		) );
	}

	protected function tearDown(): void {
		$this->set_settings( array() );
	}

	/*──────────────────────────────────────────────
	 * Exportación
	 *──────────────────────────────────────────────*/

	public function test_export_does_not_include_secrets(): void {
		$export = WPS_Admin_Export::build_config_export();

		$this->assertArrayNotHasKey( 'ipinfo_api_key', $export['settings'] );
		$this->assertStringNotContainsString( 'token-secreto', json_encode( $export ) );
	}

	public function test_export_does_not_include_maxmind_license_key(): void {
		$export = WPS_Admin_Export::build_config_export();

		$this->assertArrayNotHasKey( 'maxmind_license_key', $export['settings'] );
		$this->assertStringNotContainsString( 'licencia-secreta', json_encode( $export ) );
		$this->assertArrayHasKey( 'geo_provider', $export['settings'] );
	}

	public function test_export_includes_panel_settings(): void {
		$export = WPS_Admin_Export::build_config_export();

		$this->assertSame( 60, $export['settings']['rate_pages_per_min'] );
		$this->assertArrayHasKey( 'ipv6_block_prefix', $export['settings'] );
	}

	/*──────────────────────────────────────────────
	 * Importación
	 *──────────────────────────────────────────────*/

	public function test_valid_settings_are_imported(): void {
		$result = $this->import( array( 'rate_pages_per_min' => 120, 'block_response_code' => '503' ) );

		$this->assertSame( 2, $result['imported_settings'] );
		$this->assertSame( array(), $result['skipped_settings'] );
		$this->assertSame( 120, WPS_Loader::get_instance()->get_setting( 'rate_pages_per_min' ) );
	}

	/**
	 * @dataProvider invalid_settings
	 */
	public function test_invalid_or_unknown_settings_are_skipped( string $key, $value ): void {
		$result = $this->import( array( $key => $value ) );

		$this->assertSame( 0, $result['imported_settings'] );
		$this->assertSame( array( $key ), $result['skipped_settings'] );
	}

	public function invalid_settings(): array {
		return array(
			'clave desconocida'       => array( 'no_existe', 'x' ),
			'numero fuera de rango'   => array( 'rate_pages_per_min', 1 ),
			'numero no numerico'      => array( 'rate_pages_per_min', 'mucho' ),
			'numero negativo'         => array( 'rate_block_minutes', -5 ),
			'opcion inexistente'      => array( 'block_response_code', '200' ),
			'checkbox invalido'       => array( 'xmlrpc_block_all', 'quizas' ),
			'array en campo de texto' => array( 'block_custom_message', array( 'x' ) ),
			'secreto'                 => array( 'ipinfo_api_key', 'token-ajeno' ),
			'secreto de MaxMind'      => array( 'maxmind_license_key', 'licencia-ajena' ),
			'proveedor inexistente'   => array( 'geo_provider', 'otro' ),
			'interno'                 => array( 'db_version', '9.9.9' ),
		);
	}

	public function test_skipped_keys_are_reported(): void {
		$result = $this->import( array( 'no_existe' => 1 ) );

		$this->assertStringContainsString( 'no_existe', $result['message'] );
	}

	private function import( array $settings ): array {
		return WPS_Admin_Export::import_config( array(
			'plugin'   => 'wp-secure',
			'settings' => $settings,
		) );
	}

	private function set_settings( array $settings ): void {
		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), $settings );
	}
}
