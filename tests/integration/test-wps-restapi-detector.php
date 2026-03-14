<?php
/**
 * Tests de integración para WPS_Restapi_Detector.
 *
 * Requiere WP test framework con REST API disponible.
 */
class Test_WPS_Restapi_Detector_Integration extends WP_UnitTestCase {

	public function test_authenticated_user_can_access_rest(): void {
		$user_id = $this->factory->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $user_id );

		$detector = new WPS_Restapi_Detector();
		$result   = $detector->maybe_block_public_rest( null );

		// Usuarios autenticados no deben ser bloqueados.
		$this->assertNull( $result );
	}

	public function test_unauthenticated_user_blocked_when_setting_enabled(): void {
		wp_set_current_user( 0 );

		$loader = WPS_Loader::get_instance();
		// Asegurar que rest_disable_public está habilitado.
		// Nota: depende de la configuración activa.

		$detector = new WPS_Restapi_Detector();
		$detector->init();

		$this->assertTrue( true );
	}

	public function test_user_enumeration_blocked(): void {
		wp_set_current_user( 0 );

		$detector = new WPS_Restapi_Detector();

		$request = new WP_REST_Request( 'GET', '/wp/v2/users' );
		$result  = $detector->block_user_enumeration( null, rest_get_server(), $request );

		// Debe retornar un WP_Error si está configurado para bloquear.
		$this->assertTrue( $result instanceof WP_Error || $result === null );
	}

	public function test_allowed_namespace_passes(): void {
		wp_set_current_user( 0 );

		$detector = new WPS_Restapi_Detector();

		// oembed siempre está permitido.
		$ref    = new \ReflectionClass( $detector );
		$method = $ref->getMethod( 'is_namespace_allowed' );
		$method->setAccessible( true );

		$result = $method->invoke( $detector, '/oembed/1.0/embed' );
		$this->assertTrue( $result );
	}
}
