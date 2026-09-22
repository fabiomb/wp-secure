<?php
/**
 * Tests de los ajustes de endurecimiento de la 0.3.1: security headers,
 * detección de XML-RPC y acción `whitelist` de reglas personalizadas.
 */
class Test_WPS_Hardening_031 extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * Security headers
	 *──────────────────────────────────────────────*/

	public function test_all_headers_are_sent_when_none_exist(): void {
		$headers = WPS_Security_Hardener::headers_to_send( array() );

		$this->assertSame( 'SAMEORIGIN', $headers['X-Frame-Options'] );
		$this->assertSame( 'nosniff', $headers['X-Content-Type-Options'] );
	}

	public function test_headers_set_by_others_are_not_overridden(): void {
		$headers = WPS_Security_Hardener::headers_to_send( array(
			'x-frame-options: ALLOW-FROM https://partner.example',
			'Content-Type: text/html',
		) );

		$this->assertArrayNotHasKey( 'X-Frame-Options', $headers );
		$this->assertArrayHasKey( 'Referrer-Policy', $headers );
	}

	public function test_legacy_xss_filter_is_disabled(): void {
		$headers = WPS_Security_Hardener::headers_to_send( array() );

		$this->assertSame( '0', $headers['X-XSS-Protection'] );
	}

	/*──────────────────────────────────────────────
	 * XML-RPC
	 *──────────────────────────────────────────────*/

	public function test_xmlrpc_endpoint_is_detected(): void {
		$this->assertTrue( WPS_Xmlrpc_Detector::is_xmlrpc_path( '/xmlrpc.php' ) );
		$this->assertTrue( WPS_Xmlrpc_Detector::is_xmlrpc_path( '/blog/xmlrpc.php?rsd' ) );
		$this->assertTrue( WPS_Xmlrpc_Detector::is_xmlrpc_path( '/XMLRPC.PHP' ) );
	}

	public function test_xmlrpc_mentioned_in_query_is_not_an_xmlrpc_request(): void {
		$this->assertFalse( WPS_Xmlrpc_Detector::is_xmlrpc_path( '/?s=xmlrpc.php' ) );
		$this->assertFalse( WPS_Xmlrpc_Detector::is_xmlrpc_path( '/como-desactivar-xmlrpc-php/' ) );
	}

	/*──────────────────────────────────────────────
	 * Acción whitelist de reglas personalizadas
	 *──────────────────────────────────────────────*/

	public function test_whitelist_rule_by_ip_is_allowed(): void {
		$this->assertTrue( WPS_Custom_Rules::whitelist_conditions_allowed( array(
			array( 'field' => 'ip', 'operator' => 'equals', 'value' => '203.0.113.7' ),
		) ) );
		$this->assertTrue( WPS_Custom_Rules::whitelist_conditions_allowed( array(
			array( 'field' => 'ip', 'operator' => 'cidr', 'value' => '203.0.113.0/24' ),
		) ) );
	}

	/**
	 * @dataProvider attacker_controlled_conditions
	 */
	public function test_whitelist_rule_on_visitor_controlled_fields_is_rejected( array $condition ): void {
		$this->assertFalse(
			WPS_Custom_Rules::whitelist_conditions_allowed( array( $condition ) ),
			'Un visitante podría incluirse a sí mismo en la whitelist.'
		);
	}

	public function attacker_controlled_conditions(): array {
		return array(
			'user agent'   => array( array( 'field' => 'user_agent', 'operator' => 'contains', 'value' => 'MiApp' ) ),
			'header'       => array( array( 'field' => 'header:x-token', 'operator' => 'equals', 'value' => 'secreto' ) ),
			'uri'          => array( array( 'field' => 'uri', 'operator' => 'starts_with', 'value' => '/webhook' ) ),
			'pais'         => array( array( 'field' => 'country', 'operator' => 'equals', 'value' => 'AR' ) ),
			'ip negada'    => array( array( 'field' => 'ip', 'operator' => 'not_equals', 'value' => '203.0.113.7' ) ),
			'ip por regex' => array( array( 'field' => 'ip', 'operator' => 'regex', 'value' => '.*' ) ),
		);
	}

	public function test_mixed_conditions_are_rejected(): void {
		$this->assertFalse( WPS_Custom_Rules::whitelist_conditions_allowed( array(
			array( 'field' => 'ip', 'operator' => 'cidr', 'value' => '203.0.113.0/24' ),
			array( 'field' => 'user_agent', 'operator' => 'contains', 'value' => 'x', 'logic' => 'OR' ),
		) ) );
	}
}
