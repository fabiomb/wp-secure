<?php
/**
 * Tests de la selección de proveedor de geolocalización.
 *
 * La geolocalización es opcional y hay un solo proveedor activo: sin
 * proveedor no se consulta nada, y un proveedor nunca cae en el otro.
 */
class Test_WPS_Geo_Providers extends \PHPUnit\Framework\TestCase {

	/** @var string Directorio de datos temporal del manager. */
	private $data_dir;

	protected function setUp(): void {
		$GLOBALS['wps_test_transients']    = array();
		$GLOBALS['wps_test_http_calls']    = 0;
		$GLOBALS['wps_test_http_urls']     = array();
		$GLOBALS['wps_test_http_args']     = array();
		$GLOBALS['wps_test_http_response'] = null;

		$this->data_dir = sys_get_temp_dir() . '/wps-geo-test-' . uniqid() . '/';
		mkdir( $this->data_dir );

		$this->set_settings( array() );
	}

	protected function tearDown(): void {
		foreach ( (array) glob( $this->data_dir . '*' ) as $file ) {
			@unlink( $file );
		}
		@rmdir( $this->data_dir );

		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), array() );

		$this->reset_manager();
		$GLOBALS['wps_test_transients'] = array();
	}

	/*──────────────────────────────────────────────
	 * Sin proveedor
	 *──────────────────────────────────────────────*/

	public function test_no_provider_returns_empty_result_without_queries(): void {
		$this->set_settings( array(
			'geo_provider'   => 'none',
			'ipinfo_api_key' => 'token',
			'ipinfo_mode'    => 'api',
		) );
		$this->touch( 'country_asn.mmdb' );

		$result = $this->manager()->lookup( '45.33.32.156' );

		$this->assertNull( $result['country'] );
		$this->assertNull( $result['asn'] );
		$this->assertNull( $result['source'] );
		$this->assertSame( 0, $GLOBALS['wps_test_http_calls'] );
		$this->assertFalse( $this->manager()->is_configured() );
	}

	public function test_unknown_provider_value_counts_as_none(): void {
		$this->set_settings( array( 'geo_provider' => 'otro', 'ipinfo_api_key' => 'token' ) );

		$this->assertSame( 'none', $this->manager()->get_provider() );
		$this->assertFalse( $this->manager()->is_configured() );
	}

	/*──────────────────────────────────────────────
	 * Sin cruce entre proveedores
	 *──────────────────────────────────────────────*/

	public function test_maxmind_without_credentials_never_falls_back_to_ipinfo(): void {
		$this->set_settings( array(
			'geo_provider'   => 'maxmind',
			'maxmind_mode'   => 'api',
			'ipinfo_api_key' => 'token',
		) );
		$this->touch( 'country_asn.mmdb' );

		$result = $this->manager()->lookup( '45.33.32.156' );

		$this->assertNull( $result['country'] );
		$this->assertSame( 0, $GLOBALS['wps_test_http_calls'], 'No se consulta la API de ipinfo.io con MaxMind activo.' );
		$this->assertFalse( $this->manager()->is_configured() );
	}

	public function test_ipinfo_without_credentials_never_falls_back_to_maxmind(): void {
		$this->set_settings( array(
			'geo_provider'        => 'ipinfo',
			'ipinfo_mode'         => 'api',
			'maxmind_account_id'  => '123',
			'maxmind_license_key' => 'clave',
		) );
		$this->touch( WPS_Ipdb_Maxmind::COUNTRY_FILENAME );
		$this->touch( WPS_Ipdb_Maxmind::ASN_FILENAME );

		$this->manager()->lookup( '45.33.32.156' );

		$this->assertSame( 0, $GLOBALS['wps_test_http_calls'] );
		$this->assertFalse( $this->manager()->is_configured() );
	}

	public function test_maxmind_api_queries_geolite_with_basic_auth(): void {
		$this->set_settings( array(
			'geo_provider'        => 'maxmind',
			'maxmind_mode'        => 'api',
			'maxmind_account_id'  => '123',
			'maxmind_license_key' => 'clave',
			'ipinfo_api_key'      => 'token',
		) );
		$GLOBALS['wps_test_http_response'] = array(
			'code' => 200,
			'body' => json_encode( array(
				'country' => array( 'iso_code' => 'AR', 'names' => array( 'en' => 'Argentina' ) ),
				'traits'  => array( 'autonomous_system_number' => 7303, 'autonomous_system_organization' => 'Telecom Argentina S.A.' ),
			) ),
		);

		$result = $this->manager()->lookup( '45.33.32.156' );

		$this->assertSame( 'AR', $result['country'] );
		$this->assertSame( 7303, $result['asn'] );
		$this->assertSame( 'api', $result['source'] );
		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'] );
		$this->assertStringStartsWith( 'https://geolite.info/geoip/v2.1/city/', $GLOBALS['wps_test_http_urls'][0] );
		$this->assertSame(
			'Basic ' . base64_encode( '123:clave' ),
			$GLOBALS['wps_test_http_args'][0]['headers']['Authorization']
		);
	}

	public function test_maxmind_api_result_is_cached(): void {
		$this->given_maxmind_api();
		$GLOBALS['wps_test_http_response'] = array( 'code' => 200, 'body' => '{"country":{"iso_code":"AR"}}' );

		$this->manager()->lookup( '45.33.32.156' );
		$this->reset_memory_cache();
		$this->manager()->lookup( '45.33.32.156' );

		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'] );
	}

	public function test_maxmind_quota_pauses_only_maxmind(): void {
		$this->given_maxmind_api();
		$GLOBALS['wps_test_http_response'] = array( 'code' => 429, 'body' => '' );

		$this->manager()->lookup( '45.33.32.156' );
		$this->manager()->lookup( '45.33.32.157' );

		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'] );
		$this->assertNotFalse( get_transient( WPS_Ipdb_Manager::MAXMIND_BACKOFF_KEY ) );
		$this->assertFalse( get_transient( WPS_Ipdb_Manager::API_BACKOFF_KEY ), 'La pausa de MaxMind no suspende ipinfo.io.' );
	}

	public function test_maxmind_rejected_credentials_pause_the_service(): void {
		$this->given_maxmind_api();
		$GLOBALS['wps_test_http_response'] = array( 'code' => 401, 'body' => '' );

		$this->manager()->lookup( '45.33.32.156' );
		$this->manager()->lookup( '45.33.32.157' );

		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'] );
	}

	public function test_maxmind_failure_for_one_ip_is_remembered(): void {
		$this->given_maxmind_api();
		$GLOBALS['wps_test_http_response'] = array( 'code' => 404, 'body' => '' );

		$this->manager()->lookup( '45.33.32.156' );
		$this->reset_memory_cache();
		$this->manager()->lookup( '45.33.32.156' );
		$this->manager()->lookup( '45.33.32.157' );

		$this->assertSame( 2, $GLOBALS['wps_test_http_calls'] );
	}

	/*──────────────────────────────────────────────
	 * Archivos locales por proveedor
	 *──────────────────────────────────────────────*/

	public function test_local_files_belong_to_their_provider(): void {
		$this->touch( 'country_asn.mmdb' );

		$this->assertTrue( $this->manager()->is_local_available( 'ipinfo' ) );
		$this->assertFalse( $this->manager()->is_local_available( 'maxmind' ), 'Una base de ipinfo.io no se lee con el mapeo de MaxMind.' );

		$this->touch( WPS_Ipdb_Maxmind::ASN_FILENAME );

		$this->assertTrue( $this->manager()->is_local_available( 'maxmind' ) );
		$this->assertFalse( $this->manager()->is_local_complete( 'maxmind' ) );
		$this->assertSame( $this->data_dir . 'country_asn.mmdb', $this->manager()->get_mmdb_path( 'ipinfo' ) );
		$this->assertSame( $this->data_dir . WPS_Ipdb_Maxmind::ASN_FILENAME, $this->manager()->get_mmdb_path( 'maxmind' ) );
	}

	public function test_no_provider_has_no_local_files(): void {
		$this->touch( 'country_asn.mmdb' );
		$this->touch( WPS_Ipdb_Maxmind::COUNTRY_FILENAME );

		$this->assertFalse( $this->manager()->is_local_available( 'none' ) );
	}

	/*──────────────────────────────────────────────
	 * is_configured()
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider configured_matrix
	 */
	public function test_is_configured( array $settings, array $files, bool $expected ): void {
		$this->set_settings( $settings );
		foreach ( $files as $file ) {
			$this->touch( $file );
		}

		$this->assertSame( $expected, $this->manager()->is_configured() );
	}

	public function configured_matrix(): array {
		$mm_creds = array( 'maxmind_account_id' => '123', 'maxmind_license_key' => 'clave' );

		return array(
			'ninguno'                         => array( array( 'geo_provider' => 'none' ), array(), false ),
			'ninguno con todo configurado'    => array( array( 'geo_provider' => 'none', 'ipinfo_api_key' => 't' ) + $mm_creds, array( 'country_asn.mmdb' ), false ),
			'ipinfo api con token'            => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_mode' => 'api', 'ipinfo_api_key' => 't' ), array(), true ),
			'ipinfo api sin token'            => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_mode' => 'api' ), array(), false ),
			'ipinfo token en blanco'          => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_api_key' => '   ' ), array(), false ),
			'ipinfo local con base'           => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_mode' => 'local' ), array( 'country_asn.mmdb' ), true ),
			'ipinfo local sin base ni token'  => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_mode' => 'local' ), array(), false ),
			'ipinfo con base de maxmind'      => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_mode' => 'local' ), array( WPS_Ipdb_Maxmind::COUNTRY_FILENAME ), false ),
			'maxmind api con credenciales'    => array( array( 'geo_provider' => 'maxmind', 'maxmind_mode' => 'api' ) + $mm_creds, array(), true ),
			'maxmind sin license key'         => array( array( 'geo_provider' => 'maxmind', 'maxmind_mode' => 'api', 'maxmind_account_id' => '123' ), array(), false ),
			'maxmind local con base'          => array( array( 'geo_provider' => 'maxmind', 'maxmind_mode' => 'local' ), array( WPS_Ipdb_Maxmind::COUNTRY_FILENAME ), true ),
			'maxmind local sin nada'          => array( array( 'geo_provider' => 'maxmind', 'maxmind_mode' => 'local' ), array(), false ),
			'maxmind con base de ipinfo'      => array( array( 'geo_provider' => 'maxmind', 'maxmind_mode' => 'local', 'ipinfo_api_key' => 't' ), array( 'country_asn.mmdb' ), false ),
		);
	}

	/*──────────────────────────────────────────────
	 * Migración
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider legacy_matrix
	 */
	public function test_legacy_provider_decision( string $api_key, bool $has_mmdb, string $expected ): void {
		$this->assertSame( $expected, WPS_Ipdb_Manager::legacy_provider( $api_key, $has_mmdb ) );
	}

	public function legacy_matrix(): array {
		return array(
			'instalación nueva'     => array( '', false, 'none' ),
			'con token de ipinfo'   => array( 'token', false, 'ipinfo' ),
			'con base descargada'   => array( '', true, 'ipinfo' ),
			'token en blanco'       => array( '  ', false, 'none' ),
		);
	}

	public function test_unset_provider_is_deduced_from_previous_ipinfo_setup(): void {
		$this->set_settings( array( 'ipinfo_api_key' => 'token' ) );
		$this->assertSame( 'ipinfo', $this->manager()->get_provider() );

		$this->reset_manager();
		$this->set_settings( array() );
		$this->assertSame( 'none', $this->manager()->get_provider() );
	}

	public function test_initial_provider_detects_downloaded_ipinfo_database(): void {
		$this->touch( 'country_asn.mmdb' );
		$this->manager();
		$GLOBALS['wpdb']->reset_queries();

		$this->assertSame( 'ipinfo', WPS_Activator::initial_geo_provider( WPS_Db::get_instance() ) );
	}

	public function test_set_defaults_decides_provider_before_filling_defaults(): void {
		$this->manager();
		$GLOBALS['wpdb']->reset_queries();

		WPS_Activator::set_defaults();

		// Primer guardado: geo_provider con la decisión de migración ('none'
		// en una instalación nueva), antes de cualquier valor por defecto.
		$writes = array_values( array_filter( $GLOBALS['wpdb']->prepared_args, function ( $args ) {
			return 3 === count( $args );
		} ) );

		$this->assertSame( 'geo_provider', $writes[0][0] );
		$this->assertSame( 'none', $writes[0][1] );
		$this->assertContains( 'maxmind_mode', array_column( $writes, 0 ) );
	}

	public function test_set_defaults_keeps_ipinfo_for_existing_installs(): void {
		$this->touch( 'country_asn.mmdb' );
		$this->manager();
		$GLOBALS['wpdb']->reset_queries();

		WPS_Activator::set_defaults();

		$writes = array_values( array_filter( $GLOBALS['wpdb']->prepared_args, function ( $args ) {
			return 3 === count( $args );
		} ) );

		$this->assertSame( array( 'geo_provider', 'ipinfo' ), array_slice( $writes[0], 0, 2 ) );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function given_maxmind_api(): void {
		$this->set_settings( array(
			'geo_provider'        => 'maxmind',
			'maxmind_mode'        => 'api',
			'maxmind_account_id'  => '123',
			'maxmind_license_key' => 'clave',
		) );
	}

	private function manager(): WPS_Ipdb_Manager {
		$manager  = WPS_Ipdb_Manager::get_instance();
		$data_dir = new \ReflectionProperty( 'WPS_Ipdb_Manager', 'data_dir' );
		$data_dir->setAccessible( true );
		$data_dir->setValue( $manager, $this->data_dir );
		return $manager;
	}

	private function reset_manager(): void {
		$instance = new \ReflectionProperty( 'WPS_Ipdb_Manager', 'instance' );
		$instance->setAccessible( true );
		$instance->setValue( null, null );
	}

	private function reset_memory_cache(): void {
		$cache = new \ReflectionProperty( 'WPS_Ipdb_Manager', 'cache' );
		$cache->setAccessible( true );
		$cache->setValue( $this->manager(), array() );
	}

	private function set_settings( array $settings ): void {
		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), $settings );
		$this->reset_manager();
	}

	private function touch( string $filename ): void {
		file_put_contents( $this->data_dir . $filename, 'x' );
	}
}
