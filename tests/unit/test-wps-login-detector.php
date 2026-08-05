<?php
/**
 * Tests unitarios para WPS_Login_Detector.
 */
class Test_WPS_Login_Detector extends \PHPUnit\Framework\TestCase {

	/**
	 * Construir el detector con settings predefinidos, sin tocar la base de datos.
	 */
	private function detector_with( array $settings = array() ): WPS_Login_Detector {
		$loader     = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache_prop = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache_prop->setAccessible( true );
		$cache_prop->setValue( $loader, $settings );

		return new WPS_Login_Detector( $loader );
	}

	/*──────────────────────────────────────────────
	 * Umbral de intentos con usuario inexistente
	 *──────────────────────────────────────────────*/

	public function test_does_not_block_on_first_unknown_user_attempt(): void {
		$detector = $this->detector_with();

		$this->assertFalse(
			$detector->should_block_unknown_user( 1 ),
			'Un solo tipeo mal del nombre de usuario no puede bloquear la IP.'
		);
	}

	public function test_blocks_once_the_default_threshold_is_reached(): void {
		$detector = $this->detector_with();

		$this->assertTrue( $detector->should_block_unknown_user( 3 ) );
	}

	public function test_respects_the_configured_threshold(): void {
		$detector = $this->detector_with( array( 'login_unknown_user_threshold' => 5 ) );

		$this->assertFalse( $detector->should_block_unknown_user( 4 ) );
		$this->assertTrue( $detector->should_block_unknown_user( 5 ) );
	}

	public function test_threshold_of_zero_disables_unknown_user_blocking(): void {
		$detector = $this->detector_with( array( 'login_unknown_user_threshold' => 0 ) );

		$this->assertFalse( $detector->should_block_unknown_user( 50 ) );
	}

	/*──────────────────────────────────────────────
	 * Divulgación de existencia de cuentas
	 *──────────────────────────────────────────────*/

	public function test_denied_message_does_not_disclose_account_existence(): void {
		$message = strtolower( WPS_Login_Detector::denied_message() );

		foreach ( array( 'inexistente', 'no existe', 'usuario incorrecto', 'unknown user' ) as $leak ) {
			$this->assertStringNotContainsString(
				$leak,
				$message,
				'El mensaje de error revela si la cuenta existe y habilita enumerar usuarios.'
			);
		}
	}

	public function test_denied_message_is_not_empty(): void {
		$this->assertNotEmpty( WPS_Login_Detector::denied_message() );
	}
}
