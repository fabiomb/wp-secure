<?php
/**
 * Tests de la consulta a la API de geolocalización.
 *
 * La consulta corre dentro de la petición del visitante. Si el servicio falla,
 * no puede costar un timeout por cada petición del sitio.
 */
class Test_WPS_Ipdb_Api extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wps_test_transients']   = array();
		$GLOBALS['wps_test_http_calls']   = 0;
		$GLOBALS['wps_test_http_response'] = null;

		// Loader con token de API configurado.
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, array( 'ipinfo_api_key' => 'token', 'ipinfo_mode' => 'api' ) );

		// Manager nuevo en cada test (sin cache en memoria).
		$instance = new \ReflectionProperty( 'WPS_Ipdb_Manager', 'instance' );
		$instance->setAccessible( true );
		$instance->setValue( null, null );
	}

	protected function tearDown(): void {
		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), array() );
		$GLOBALS['wps_test_transients'] = array();
	}

	public function test_successful_lookup_is_cached(): void {
		$GLOBALS['wps_test_http_response'] = array(
			'code' => 200,
			'body' => '{"country":"AR","org":"AS7303 Telecom Argentina S.A."}',
		);

		$first = $this->lookup( '45.33.32.156' );
		$this->reset_memory_cache();
		$this->lookup( '45.33.32.156' );

		$this->assertSame( 'AR', $first['country'] );
		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'] );
	}

	public function test_service_outage_pauses_the_api_for_every_ip(): void {
		$GLOBALS['wps_test_http_response'] = array( 'error' => 'cURL error 28: timeout' );

		$this->lookup( '45.33.32.156' );
		$this->lookup( '45.33.32.157' );
		$this->lookup( '45.33.32.158' );

		$this->assertSame(
			1,
			$GLOBALS['wps_test_http_calls'],
			'Con el servicio caído, cada IP nueva pagaba el timeout completo.'
		);
	}

	public function test_quota_exhausted_pauses_the_api(): void {
		$GLOBALS['wps_test_http_response'] = array( 'code' => 429, 'body' => '' );

		$this->lookup( '45.33.32.156' );
		$this->lookup( '45.33.32.157' );

		$this->assertSame( 1, $GLOBALS['wps_test_http_calls'] );
	}

	public function test_failure_for_one_ip_is_remembered_without_pausing_others(): void {
		$GLOBALS['wps_test_http_response'] = array( 'code' => 404, 'body' => '' );

		$this->lookup( '45.33.32.156' );
		$this->reset_memory_cache();
		$this->lookup( '45.33.32.156' );
		$this->lookup( '45.33.32.157' );

		$this->assertSame( 2, $GLOBALS['wps_test_http_calls'], 'La IP que falló no se reconsulta; otra IP sí se consulta.' );
	}

	private function lookup( string $ip ): array {
		return WPS_Ipdb_Manager::get_instance()->lookup( $ip );
	}

	private function reset_memory_cache(): void {
		$cache = new \ReflectionProperty( 'WPS_Ipdb_Manager', 'cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Ipdb_Manager::get_instance(), array() );
	}
}
