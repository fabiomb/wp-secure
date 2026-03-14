<?php
/**
 * Tests unitarios para WPS_Rules_Engine (puntuación de riesgo).
 */
class Test_WPS_Rules_Engine extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * Verificar que la clase existe y tiene los métodos esperados
	 *──────────────────────────────────────────────*/

	public function test_class_exists(): void {
		$this->assertTrue( class_exists( 'WPS_Rules_Engine' ) );
	}

	public function test_has_evaluate_method(): void {
		$ref = new \ReflectionClass( 'WPS_Rules_Engine' );
		$this->assertTrue( $ref->hasMethod( 'evaluate' ) );
	}

	public function test_has_evaluate_and_act_method(): void {
		$ref = new \ReflectionClass( 'WPS_Rules_Engine' );
		$this->assertTrue( $ref->hasMethod( 'evaluate_and_act' ) );
	}

	/*──────────────────────────────────────────────
	 * Constantes de umbral
	 *──────────────────────────────────────────────*/

	public function test_threshold_constants(): void {
		$ref = new \ReflectionClass( 'WPS_Rules_Engine' );
		$constants = $ref->getConstants();

		// Verificar que existen umbrales definidos.
		$this->assertNotEmpty( $constants );
	}
}
