<?php
/**
 * Tests unitarios para WPS_Request.
 */
class Test_WPS_Request extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $server_backup;

	protected function setUp(): void {
		$this->server_backup = $_SERVER;
	}

	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$this->reset_singleton();
	}

	/**
	 * Vaciar el singleton para que el siguiente get_instance() relea $_SERVER.
	 */
	private function reset_singleton(): void {
		$prop = new \ReflectionProperty( 'WPS_Request', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}

	private function fresh_request(): WPS_Request {
		$this->reset_singleton();
		return WPS_Request::get_instance();
	}

	/**
	 * Dejar sólo los headers indicados en el entorno de la petición.
	 */
	private function given_request( string $remote_addr, array $headers = array() ): void {
		foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_SUCURI_CLIENTIP' ) as $key ) {
			unset( $_SERVER[ $key ] );
		}

		$_SERVER['REMOTE_ADDR']    = $remote_addr;
		$_SERVER['REQUEST_URI']    = '/';
		$_SERVER['REQUEST_METHOD'] = 'GET';

		foreach ( $headers as $key => $value ) {
			$_SERVER[ $key ] = $value;
		}
	}

	/*──────────────────────────────────────────────
	 * Resolución de IP
	 *──────────────────────────────────────────────*/

	public function test_ignores_forwarded_headers_when_remote_addr_is_empty(): void {
		// Algunos setups FastCGI dejan REMOTE_ADDR vacío. Eso no habilita
		// a confiar en headers que controla el cliente.
		$this->given_request( '', array( 'HTTP_CF_CONNECTING_IP' => '1.2.3.4' ) );

		$this->assertNotEquals( '1.2.3.4', $this->fresh_request()->ip() );
	}

	public function test_ignores_forwarded_headers_when_remote_addr_is_malformed(): void {
		$this->given_request( 'unknown', array( 'HTTP_X_FORWARDED_FOR' => '1.2.3.4' ) );

		$this->assertNotEquals( '1.2.3.4', $this->fresh_request()->ip() );
	}

	public function test_ignores_spoofed_headers_from_direct_connection(): void {
		$this->given_request( '45.33.32.156', array(
			'HTTP_CF_CONNECTING_IP' => '1.2.3.4',
			'HTTP_X_FORWARDED_FOR'  => '1.2.3.4',
		) );

		$this->assertEquals( '45.33.32.156', $this->fresh_request()->ip() );
	}

	/*──────────────────────────────────────────────
	 * Clasificación de visitante
	 *──────────────────────────────────────────────*/

	public function test_classifies_rest_route_query_as_restapi(): void {
		$this->given_request( '45.33.32.156' );
		$_SERVER['REQUEST_URI'] = '/index.php?rest_route=/wp/v2/posts';

		$this->assertEquals( 'restapi', $this->fresh_request()->visitor_type() );
	}

	public function test_classifies_wp_json_path_as_restapi(): void {
		$this->given_request( '45.33.32.156' );
		$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';

		$this->assertEquals( 'restapi', $this->fresh_request()->visitor_type() );
	}

	public function test_classifies_plain_permalink_as_page(): void {
		$this->given_request( '45.33.32.156' );
		$_SERVER['REQUEST_URI'] = '/2026/mi-articulo/';

		$this->assertEquals( 'page', $this->fresh_request()->visitor_type() );
	}

	/*──────────────────────────────────────────────
	 * Usuarios de confianza
	 *──────────────────────────────────────────────*/

	public function test_administrator_is_a_trusted_user(): void {
		$GLOBALS['wps_test_caps'] = array( 'manage_options' => true, 'edit_posts' => true );

		$this->assertTrue( WPS_Request::is_trusted_user() );

		unset( $GLOBALS['wps_test_caps'] );
	}

	public function test_author_is_a_trusted_user(): void {
		// Quien publica contenido pega código y ejemplos como parte de su
		// trabajo; bloquearle la IP rompe el sitio para quien lo edita.
		$GLOBALS['wps_test_caps'] = array( 'edit_posts' => true );

		$this->assertTrue( WPS_Request::is_trusted_user() );

		unset( $GLOBALS['wps_test_caps'] );
	}

	public function test_subscriber_is_not_a_trusted_user(): void {
		$GLOBALS['wps_test_caps'] = array( 'read' => true );

		$this->assertFalse( WPS_Request::is_trusted_user() );

		unset( $GLOBALS['wps_test_caps'] );
	}

	public function test_anonymous_visitor_is_not_a_trusted_user(): void {
		unset( $GLOBALS['wps_test_caps'] );

		$this->assertFalse( WPS_Request::is_trusted_user() );
	}
}
