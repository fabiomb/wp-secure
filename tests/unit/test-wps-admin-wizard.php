<?php
/**
 * Tests del wizard de configuración inicial.
 */
class Test_WPS_Admin_Wizard extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $server_backup;

	/** @var string */
	private $data_dir;

	protected function setUp(): void {
		$this->server_backup = $_SERVER;
		$_GET  = array();
		$_POST = array();
		$GLOBALS['wpdb']->reset_queries();

		$this->data_dir = sys_get_temp_dir() . '/wps-wizard-test-' . uniqid() . '/';
		mkdir( $this->data_dir );

		$this->set_settings( array() );
	}

	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$_GET    = array();
		$_POST   = array();

		foreach ( (array) glob( $this->data_dir . '*' ) as $file ) {
			@unlink( $file );
		}
		@rmdir( $this->data_dir );

		$this->set_settings( array() );
		$this->reset_singleton( 'WPS_Request' );
		$this->reset_singleton( 'WPS_Whitelist' );
		$this->reset_singleton( 'WPS_Ipdb_Manager' );
	}

	/*──────────────────────────────────────────────
	 * Paso pedido
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider steps
	 */
	public function test_step_is_clamped( $requested, int $expected ): void {
		if ( null !== $requested ) {
			$_GET['step'] = $requested;
		}

		$this->assertSame( $expected, $this->wizard()->current_step() );
	}

	public function steps(): array {
		return array(
			'sin paso'       => array( null, 1 ),
			'cero'           => array( '0', 1 ),
			'intermedio'     => array( '3', 3 ),
			'último'         => array( '4', 4 ),
			'fuera de rango' => array( '9', WPS_Admin_Wizard::TOTAL_STEPS ),
			'no numérico'    => array( 'abc', 1 ),
		);
	}

	/*──────────────────────────────────────────────
	 * Paso 1: IP con el modo de proxy recién guardado
	 *──────────────────────────────────────────────*/

	public function test_whitelisted_ip_uses_the_proxy_mode_saved_in_the_same_submit(): void {
		// Petición por Cloudflare con el modo 'cloudflare' vigente: WPS_Request
		// resuelve y guarda la IP del header.
		$_SERVER['REMOTE_ADDR']           = '173.245.48.1';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';
		$this->set_settings( array( 'proxy_mode' => 'cloudflare' ) );
		WPS_Proxy_Config::get_instance()->set_loader( WPS_Loader::get_instance() );
		$this->reset_singleton( 'WPS_Request' );
		$this->assertSame( '203.0.113.9', WPS_Request::get_instance()->ip() );

		// El administrador indica que no hay proxy y pide agregar su IP.
		$_POST = array(
			'proxy_mode'           => 'none',
			'whitelist_current_ip' => '1',
		);
		$this->save_step( 1 );

		$this->assertSame( 'none', WPS_Loader::get_instance()->get_setting( 'proxy_mode' ) );
		$this->assertSame( array( '173.245.48.1' ), $this->whitelisted_ips() );
	}

	public function test_resolved_ip_follows_new_proxy_mode(): void {
		$_SERVER['REMOTE_ADDR']           = '173.245.48.1';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '203.0.113.9';
		$this->set_settings( array( 'proxy_mode' => 'none' ) );

		$wizard = $this->wizard();
		$this->assertSame( '173.245.48.1', $wizard->resolve_current_ip() );

		WPS_Loader::get_instance()->set_setting( 'proxy_mode', 'cloudflare' );
		$this->assertSame( '203.0.113.9', $wizard->resolve_current_ip() );
	}

	public function test_invalid_proxy_mode_falls_back_to_auto(): void {
		$_POST = array( 'proxy_mode' => 'inventado' );

		$this->save_step( 1 );

		$this->assertSame( 'auto', WPS_Loader::get_instance()->get_setting( 'proxy_mode' ) );
		$this->assertSame( array(), $this->whitelisted_ips() );
	}

	/*──────────────────────────────────────────────
	 * Paso 4: geolocalización
	 *──────────────────────────────────────────────*/

	public function test_provider_is_saved_even_without_credentials(): void {
		$_POST = array(
			'geo_provider'        => 'maxmind',
			'maxmind_account_id'  => '',
			'maxmind_license_key' => '',
			'maxmind_mode'        => 'local',
		);

		$this->save_step( 4 );

		$this->assertSame( 'maxmind', WPS_Loader::get_instance()->get_setting( 'geo_provider' ) );
		$this->assertSame( 'local', WPS_Loader::get_instance()->get_setting( 'maxmind_mode' ) );
	}

	public function test_unknown_provider_is_saved_as_none(): void {
		$_POST = array( 'geo_provider' => 'otro', 'ipinfo_mode' => 'raro', 'maxmind_mode' => 'raro' );

		$this->save_step( 4 );

		$loader = WPS_Loader::get_instance();
		$this->assertSame( 'none', $loader->get_setting( 'geo_provider' ) );
		$this->assertSame( 'api', $loader->get_setting( 'ipinfo_mode' ) );
		$this->assertSame( 'local', $loader->get_setting( 'maxmind_mode' ) );
	}

	/**
	 * @dataProvider finish_cases
	 */
	public function test_finish_url( array $settings, array $files, string $expected ): void {
		$this->set_settings( $settings );
		foreach ( $files as $file ) {
			file_put_contents( $this->data_dir . $file, 'x' );
		}

		$this->assertSame( 'https://example.com/wp-admin/' . $expected, $this->wizard()->finish_url() );
	}

	public function finish_cases(): array {
		$mm = array( 'geo_provider' => 'maxmind', 'maxmind_account_id' => '1', 'maxmind_license_key' => 'k' );

		return array(
			'sin geolocalización'          => array( array( 'geo_provider' => 'none' ), array(), 'admin.php?page=wp-secure&wizard=done' ),
			'local sin descargar'          => array( $mm + array( 'maxmind_mode' => 'local' ), array(), 'admin.php?page=wp-secure-ipdb&wizard=done&wps_geo=download' ),
			'local a medio descargar'      => array( $mm + array( 'maxmind_mode' => 'local' ), array( WPS_Ipdb_Maxmind::COUNTRY_FILENAME ), 'admin.php?page=wp-secure-ipdb&wizard=done&wps_geo=download' ),
			'local ya descargada'          => array( $mm + array( 'maxmind_mode' => 'local' ), array( WPS_Ipdb_Maxmind::COUNTRY_FILENAME, WPS_Ipdb_Maxmind::ASN_FILENAME ), 'admin.php?page=wp-secure&wizard=done' ),
			'local sin credenciales'       => array( array( 'geo_provider' => 'maxmind', 'maxmind_mode' => 'local' ), array(), 'admin.php?page=wp-secure-ipdb&wizard=done&wps_geo=incomplete' ),
			'api con token'                => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_mode' => 'api', 'ipinfo_api_key' => 't' ), array(), 'admin.php?page=wp-secure&wizard=done' ),
			'api sin token'                => array( array( 'geo_provider' => 'ipinfo', 'ipinfo_mode' => 'api' ), array(), 'admin.php?page=wp-secure&wizard=done&wps_geo=incomplete' ),
			'base de ipinfo no sirve a mm' => array( $mm + array( 'maxmind_mode' => 'local' ), array( 'country_asn.mmdb' ), 'admin.php?page=wp-secure-ipdb&wizard=done&wps_geo=download' ),
		);
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function wizard(): WPS_Admin_Wizard {
		$manager  = WPS_Ipdb_Manager::get_instance();
		$data_dir = new \ReflectionProperty( 'WPS_Ipdb_Manager', 'data_dir' );
		$data_dir->setAccessible( true );
		$data_dir->setValue( $manager, $this->data_dir );

		return new WPS_Admin_Wizard( WPS_Loader::get_instance() );
	}

	private function save_step( int $step ): void {
		$method = new \ReflectionMethod( 'WPS_Admin_Wizard', 'save_step' );
		$method->setAccessible( true );
		$method->invoke( $this->wizard(), $step );
	}

	/**
	 * IPs insertadas en la tabla de whitelist.
	 */
	private function whitelisted_ips(): array {
		$ips = array();
		foreach ( $GLOBALS['wpdb']->inserts as $insert ) {
			if ( false !== strpos( $insert[0], 'whitelist' ) && ! empty( $insert[1]['ip_address'] ) ) {
				$ips[] = $insert[1]['ip_address'];
			}
		}
		return $ips;
	}

	private function set_settings( array $settings ): void {
		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), $settings );
		$this->reset_singleton( 'WPS_Ipdb_Manager' );
	}

	private function reset_singleton( string $class ): void {
		$instance = new \ReflectionProperty( $class, 'instance' );
		$instance->setAccessible( true );
		$instance->setValue( null, null );
	}
}
