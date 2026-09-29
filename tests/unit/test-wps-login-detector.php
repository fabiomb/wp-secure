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

	/*──────────────────────────────────────────────
	 * Un intento, una fila
	 *──────────────────────────────────────────────*/

	public function test_unknown_user_attempt_is_recorded_once(): void {
		$GLOBALS['wps_test_users'] = array();
		$GLOBALS['wpdb']->reset_queries();
		$detector = $this->detector_with();

		// WordPress llama a authenticate y, al fallar, dispara wp_login_failed.
		$detector->check_before_auth( null, 'usuario-inexistente', 'x' );
		$detector->on_login_failed( 'usuario-inexistente' );

		$this->assertCount(
			1,
			$this->login_attempt_inserts(),
			'Cada intento contado dos veces bloquea la IP con la mitad de los errores configurados.'
		);
	}

	public function test_each_attempt_counts_separately(): void {
		$GLOBALS['wps_test_users'] = array();
		$GLOBALS['wpdb']->reset_queries();
		$detector = $this->detector_with();

		for ( $i = 0; $i < 2; $i++ ) {
			$detector->check_before_auth( null, 'usuario-inexistente', 'x' );
			$detector->on_login_failed( 'usuario-inexistente' );
		}

		$this->assertCount( 2, $this->login_attempt_inserts() );
	}

	public function test_failed_login_of_existing_user_is_recorded(): void {
		$GLOBALS['wps_test_users'] = array( 'admin' => (object) array( 'ID' => 1 ) );
		$GLOBALS['wpdb']->reset_queries();
		$detector = $this->detector_with();

		$detector->check_before_auth( null, 'admin', 'mala' );
		$detector->on_login_failed( 'admin' );

		$inserts = $this->login_attempt_inserts();
		$this->assertCount( 1, $inserts );
		$this->assertSame( 1, $inserts[0]['user_exists'] );
		$GLOBALS['wps_test_users'] = array();
	}

	/*──────────────────────────────────────────────
	 * Application passwords
	 *──────────────────────────────────────────────*/

	public function test_failed_application_password_counts_as_failed_login(): void {
		$GLOBALS['wps_test_users'] = array( 'admin' => (object) array( 'ID' => 1 ) );
		$_SERVER['PHP_AUTH_USER']  = 'admin';
		$GLOBALS['wpdb']->reset_queries();

		$this->detector_with()->on_application_password_failed( new WP_Error( 'incorrect_password' ) );

		$inserts = $this->login_attempt_inserts();
		$this->assertCount( 1, $inserts, 'La fuerza bruta contra /wp-json/ con Basic auth no se contaba.' );
		$this->assertSame( 'admin', $inserts[0]['username'] );
		$this->assertSame( 0, $inserts[0]['success'] );
		$this->assertTrue( $this->failed_count_was_checked(), 'El fallo tiene que evaluarse contra el máximo de intentos.' );

		unset( $_SERVER['PHP_AUTH_USER'] );
		$GLOBALS['wps_test_users'] = array();
	}

	public function test_application_password_with_unknown_user_is_counted(): void {
		$_SERVER['PHP_AUTH_USER'] = 'no-existe';
		$GLOBALS['wpdb']->reset_queries();

		$this->detector_with()->on_application_password_failed( new WP_Error( 'invalid_username' ) );

		$this->assertCount( 1, $this->login_attempt_inserts() );
		unset( $_SERVER['PHP_AUTH_USER'] );
	}

	public function test_disabled_application_passwords_are_not_an_attack(): void {
		$_SERVER['PHP_AUTH_USER'] = 'admin';
		$GLOBALS['wpdb']->reset_queries();
		$detector = $this->detector_with();

		$detector->on_application_password_failed( new WP_Error( 'application_passwords_disabled' ) );
		$detector->on_application_password_failed( new WP_Error( 'application_passwords_disabled_for_user' ) );

		$this->assertCount( 0, $this->login_attempt_inserts() );
		unset( $_SERVER['PHP_AUTH_USER'] );
	}

	private function failed_count_was_checked(): bool {
		foreach ( $GLOBALS['wpdb']->queries as $query ) {
			if ( false !== strpos( (string) $query, 'success = 0' ) && false === strpos( (string) $query, 'user_exists = 0' ) ) {
				return true;
			}
		}
		return false;
	}

	private function login_attempt_inserts(): array {
		$rows = array();
		foreach ( $GLOBALS['wpdb']->inserts as $insert ) {
			if ( 'wp_wps_login_attempts' === $insert[0] ) {
				$rows[] = $insert[1];
			}
		}
		return $rows;
	}
}
