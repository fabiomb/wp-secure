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

	/**
	 * @dataProvider missing_asset_paths
	 */
	public function test_classifies_typical_missing_assets_as_static( string $uri ): void {
		$this->given_request( '45.33.32.156' );
		$_SERVER['REQUEST_URI'] = $uri;

		$this->assertEquals( 'static', $this->fresh_request()->visitor_type() );
	}

	public function missing_asset_paths(): array {
		return array(
			'imagen migrada'     => array( '/wp-content/uploads/2019/03/foto.jpg' ),
			'icono de ios'       => array( '/apple-touch-icon-precomposed.png' ),
			'favicon'            => array( '/favicon.ico' ),
			'css con version'    => array( '/wp-content/themes/viejo/style.css?ver=1.2' ),
			'source map'         => array( '/wp-includes/js/jquery/jquery.min.js.map' ),
		);
	}

	/**
	 * @dataProvider path_info_bypasses
	 */
	public function test_php_script_with_static_suffix_is_not_static( string $uri, string $expected_type ): void {
		$this->given_request( '45.33.32.156' );
		$_SERVER['REQUEST_URI'] = $uri;

		$this->assertEquals(
			$expected_type,
			$this->fresh_request()->visitor_type(),
			'Una ruta que ejecuta PHP no puede eximirse de los detectores por terminar en una extensión estática.'
		);
	}

	public function path_info_bypasses(): array {
		return array(
			'admin-ajax con css'     => array( '/wp-admin/admin-ajax.php/x.css?action=a&id=1', 'ajax' ),
			'mayusculas'             => array( '/wp-admin/admin-ajax.PHP/x.CSS?action=a', 'ajax' ),
			'barra codificada'       => array( '/wp-admin/admin-ajax.php%2Fx.js?action=a', 'ajax' ),
			'login con png'          => array( '/wp-login.php/logo.png', 'login' ),
			'xmlrpc con ico'         => array( '/xmlrpc.php/favicon.ico', 'xmlrpc' ),
			'index con pathinfo'     => array( '/index.php/2026/articulo.css', 'page' ),
			'script de plugin'       => array( '/wp-content/plugins/x/api.php/a/b.jpg?q=1', 'page' ),
		);
	}

	public function test_static_path_detection(): void {
		$this->assertTrue( WPS_Request::is_static_path( '/wp-content/themes/t/style.css' ) );
		$this->assertTrue( WPS_Request::is_static_path( '/uploads/foto.JPG' ) );
		$this->assertTrue( WPS_Request::is_static_path( '/archivo.php.css' ), 'Un archivo llamado x.php.css no ejecuta PHP.' );
		$this->assertFalse( WPS_Request::is_static_path( '/wp-admin/admin-ajax.php/x.css' ) );
		$this->assertFalse( WPS_Request::is_static_path( '/2026/mi-articulo/' ) );
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
