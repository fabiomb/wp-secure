<?php
/**
 * Tests de la protección contra enumeración de usuarios.
 *
 * Con `rest_block_user_enum` activo, ninguna de estas vías puede revelar
 * nombres de usuario a un visitante anónimo.
 */
class Test_WPS_User_Enumeration extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * ?author=
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider author_queries
	 */
	public function test_author_parameter_variants_are_enumeration( array $query ): void {
		$this->assertTrue(
			WPS_Restapi_Detector::is_author_enumeration( $query ),
			'WordPress acepta esta variante de ?author= y redirige al nombre de usuario.'
		);
	}

	public function author_queries(): array {
		return array(
			'numerico'         => array( array( 'author' => '1' ) ),
			'con coma'         => array( array( 'author' => '1,' ) ),
			'con espacio'      => array( array( 'author' => '1 ' ) ),
			'negativo'         => array( array( 'author' => '-1' ) ),
			'como array'       => array( array( 'author' => array( '1' ) ) ),
			'junto a otro'     => array( array( 's' => 'x', 'author' => '2' ) ),
		);
	}

	public function test_requests_without_author_are_not_enumeration(): void {
		$this->assertFalse( WPS_Restapi_Detector::is_author_enumeration( array() ) );
		$this->assertFalse( WPS_Restapi_Detector::is_author_enumeration( array( 's' => 'author' ) ) );
		$this->assertFalse( WPS_Restapi_Detector::is_author_enumeration( array( 'author' => '' ) ) );
	}

	/*──────────────────────────────────────────────
	 * REST /wp/v2/users
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider users_routes
	 */
	public function test_users_route_variants_are_detected( string $route ): void {
		$this->assertTrue( WPS_Restapi_Detector::is_users_route( $route ) );
	}

	public function users_routes(): array {
		return array(
			'listado'         => array( '/wp/v2/users' ),
			'detalle'         => array( '/wp/v2/users/1' ),
			'mayusculas'      => array( '/wp/v2/USERS' ),
			'mezcla'          => array( '/WP/V2/Users/1' ),
			'barra final'     => array( '/wp/v2/users/' ),
			'barras dobles'   => array( '//wp/v2//users' ),
		);
	}

	public function test_other_routes_are_not_users_routes(): void {
		$this->assertFalse( WPS_Restapi_Detector::is_users_route( '/wp/v2/posts' ) );
		$this->assertFalse( WPS_Restapi_Detector::is_users_route( '/wp/v2/users-extra' ) );
		$this->assertFalse( WPS_Restapi_Detector::is_users_route( '/mi-plugin/v1/users' ) );
	}

	/*──────────────────────────────────────────────
	 * Sitemap y oEmbed
	 *──────────────────────────────────────────────*/

	public function test_users_sitemap_is_removed(): void {
		$detector = $this->detector();
		$provider = new \stdClass();

		$this->assertFalse( $detector->remove_users_sitemap( $provider, 'users' ) );
		$this->assertSame( $provider, $detector->remove_users_sitemap( $provider, 'posts' ) );
	}

	public function test_oembed_author_is_removed(): void {
		$data = $this->detector()->remove_oembed_author( array(
			'title'       => 'Entrada',
			'author_name' => 'admin',
			'author_url'  => 'https://ejemplo.com/author/admin/',
		) );

		$this->assertSame( array( 'title' => 'Entrada' ), $data );
	}

	public function test_author_check_runs_before_canonical_redirect(): void {
		// redirect_canonical corre en template_redirect con prioridad 10 y
		// redirige ?author=1 a /author/{usuario}/: el bloqueo tiene que ir antes.
		$GLOBALS['wps_test_hooks'] = array();
		$this->detector()->init();

		$priorities = array();
		foreach ( $GLOBALS['wps_test_hooks'] as $hook ) {
			if ( 'template_redirect' === $hook['hook'] && is_array( $hook['callback'] )
				&& 'block_author_enumeration' === $hook['callback'][1] ) {
				$priorities[] = $hook['priority'];
			}
		}

		$this->assertCount( 1, $priorities );
		$this->assertLessThan( 10, $priorities[0] );
	}

	public function test_sitemap_and_oembed_filters_follow_the_setting(): void {
		$GLOBALS['wps_test_hooks'] = array();
		$this->detector( array( 'rest_block_user_enum' => false ) )->init();

		$hooks = array_column( $GLOBALS['wps_test_hooks'], 'hook' );
		$this->assertNotContains( 'wp_sitemaps_add_provider', $hooks );
		$this->assertNotContains( 'oembed_response_data', $hooks );
	}

	private function detector( array $settings = array() ): WPS_Restapi_Detector {
		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		return new WPS_Restapi_Detector( $loader );
	}
}
