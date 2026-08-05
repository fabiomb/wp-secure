<?php
/**
 * Tests de las condiciones sugeridas al crear una regla desde un evento.
 *
 * Una sugerencia demasiado amplia es peor que ninguna: una regla
 * "uri contiene /" con acción de bloqueo saca el sitio de servicio.
 */
class Test_WPS_Rule_Suggestions extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * Sugerencias válidas
	 *──────────────────────────────────────────────*/

	public function test_suggests_contains_on_the_request_path(): void {
		$condition = WPS_Custom_Rules::suggest_condition_from_uri( '/wp-content/plugins/revslider/readme.txt' );

		$this->assertEquals( 'uri', $condition['field'] );
		$this->assertEquals( 'contains', $condition['operator'] );
		$this->assertEquals( '/wp-content/plugins/revslider/readme.txt', $condition['value'] );
	}

	public function test_drops_the_query_string(): void {
		$condition = WPS_Custom_Rules::suggest_condition_from_uri( '/index.php?author=1&foo=bar' );

		$this->assertEquals(
			'/index.php',
			$condition['value'],
			'El query string varía en cada intento; la regla debe apuntar a la ruta.'
		);
	}

	public function test_trims_surrounding_whitespace(): void {
		$condition = WPS_Custom_Rules::suggest_condition_from_uri( '  /.env  ' );

		$this->assertEquals( '/.env', $condition['value'] );
	}

	public function test_caps_the_value_length(): void {
		$long = '/' . str_repeat( 'a', 500 );

		$condition = WPS_Custom_Rules::suggest_condition_from_uri( $long );

		$this->assertLessThanOrEqual( 255, strlen( $condition['value'] ) );
	}

	/*──────────────────────────────────────────────
	 * Sugerencias que hay que rechazar
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider dangerously_broad_uris
	 */
	public function test_refuses_to_suggest_overly_broad_rules( string $uri ): void {
		$this->assertNull(
			WPS_Custom_Rules::suggest_condition_from_uri( $uri ),
			"Una regla derivada de '{$uri}' coincidiría con casi todo el tráfico del sitio."
		);
	}

	public function dangerously_broad_uris(): array {
		return array(
			'raiz'              => array( '/' ),
			'vacio'             => array( '' ),
			'solo espacios'     => array( '   ' ),
			'solo query'        => array( '?s=algo' ),
			'demasiado corto'   => array( '/a' ),
			'barra duplicada'   => array( '//' ),
		);
	}

	/*──────────────────────────────────────────────
	 * Sugerencia desde User-Agent
	 *──────────────────────────────────────────────*/

	public function test_suggests_contains_on_a_distinctive_user_agent(): void {
		$condition = WPS_Custom_Rules::suggest_condition_from_user_agent( 'Mozilla/5.0 (compatible; SemrushBot/7~bl)' );

		$this->assertEquals( 'user_agent', $condition['field'] );
		$this->assertEquals( 'contains', $condition['operator'] );
		$this->assertEquals( 'Mozilla/5.0 (compatible; SemrushBot/7~bl)', $condition['value'] );
	}

	public function test_refuses_to_suggest_an_empty_user_agent(): void {
		$this->assertNull( WPS_Custom_Rules::suggest_condition_from_user_agent( '' ) );
		$this->assertNull( WPS_Custom_Rules::suggest_condition_from_user_agent( '   ' ) );
	}

	/*──────────────────────────────────────────────
	 * Patrones ya cubiertos por una regla existente
	 *──────────────────────────────────────────────*/

	private function rule( array $conditions, string $action = 'block_temporary' ): array {
		return array(
			'id'          => 1,
			'name'        => 'Regla de prueba',
			'action_type' => $action,
			'conditions'  => $conditions,
		);
	}

	public function test_path_is_covered_by_a_matching_uri_rule(): void {
		$rules = array(
			$this->rule( array(
				array( 'field' => 'uri', 'operator' => 'contains', 'value' => '/wp-content/plugins/revslider/' ),
			) ),
		);

		$this->assertTrue(
			WPS_Custom_Rules::path_is_covered( '/wp-content/plugins/revslider/readme.txt', $rules )
		);
	}

	public function test_path_is_not_covered_by_an_unrelated_rule(): void {
		$rules = array(
			$this->rule( array(
				array( 'field' => 'uri', 'operator' => 'contains', 'value' => '/xmlrpc.php' ),
			) ),
		);

		$this->assertFalse(
			WPS_Custom_Rules::path_is_covered( '/wp-content/plugins/revslider/readme.txt', $rules )
		);
	}

	public function test_path_is_not_covered_when_there_are_no_rules(): void {
		$this->assertFalse( WPS_Custom_Rules::path_is_covered( '/.env', array() ) );
	}

	public function test_exempt_rules_do_not_count_as_coverage(): void {
		$rules = array(
			$this->rule(
				array( array( 'field' => 'uri', 'operator' => 'contains', 'value' => '/.env' ) ),
				'exempt'
			),
		);

		$this->assertFalse(
			WPS_Custom_Rules::path_is_covered( '/.env', $rules ),
			'Una regla de exención no bloquea el patrón, así que no lo cubre.'
		);
	}

	public function test_rules_on_other_fields_do_not_count_as_coverage(): void {
		$rules = array(
			$this->rule( array(
				array( 'field' => 'user_agent', 'operator' => 'contains', 'value' => 'curl' ),
			) ),
		);

		$this->assertFalse( WPS_Custom_Rules::path_is_covered( '/.env', $rules ) );
	}
}
