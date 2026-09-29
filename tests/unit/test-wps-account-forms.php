<?php
/**
 * Tests de login, recuperación de contraseña y registro: mensajes que no
 * revelan cuentas y límites por cliente.
 */
class Test_WPS_Account_Forms extends \PHPUnit\Framework\TestCase {

	private $server_backup;

	protected function setUp(): void {
		$this->server_backup         = $_SERVER;
		$GLOBALS['wps_test_options'] = array();
		$GLOBALS['wpdb']->reset_queries();
		$_SERVER['REQUEST_URI']      = '/wp-login.php?action=lostpassword';
		$_SERVER['REQUEST_METHOD']   = 'POST';
		$_SERVER['REMOTE_ADDR']      = '45.33.32.156';
		$this->reset_singletons();
	}

	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$this->reset_singletons();
	}

	/*──────────────────────────────────────────────
	 * Errores de login
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider revealing_codes
	 */
	public function test_login_errors_that_reveal_accounts_become_uniform( string $code ): void {
		$errors = $this->detector()->uniform_login_errors( new WP_Error( $code, 'The username admin is not registered…' ) );

		$this->assertSame( array( 'wps_login_failed' ), $errors->get_error_codes() );
		$this->assertSame( array( WPS_Login_Detector::denied_message() ), $errors->get_error_messages( 'wps_login_failed' ) );
	}

	public function revealing_codes(): array {
		return array(
			'usuario inexistente'    => array( 'invalid_username' ),
			'email inexistente'      => array( 'invalid_email' ),
			'contraseña incorrecta'  => array( 'incorrect_password' ),
		);
	}

	public function test_other_login_errors_are_kept(): void {
		$errors = new WP_Error( 'empty_password', 'Falta la contraseña.' );

		$this->assertSame( $errors, $this->detector()->uniform_login_errors( $errors ) );
	}

	/*──────────────────────────────────────────────
	 * Recuperación de contraseña
	 *──────────────────────────────────────────────*/

	public function test_missing_account_gets_the_same_response_as_an_existing_one(): void {
		$detector = $this->detector();

		$detector->on_lost_password( new WP_Error(), false );

		$this->assertTrue( $detector->redirected, 'Una cuenta inexistente tiene que verse igual que una que existe.' );
	}

	public function test_existing_account_follows_the_normal_flow(): void {
		$detector = $this->detector();

		$detector->on_lost_password( new WP_Error(), (object) array( 'ID' => 1 ) );

		$this->assertFalse( $detector->redirected );
	}

	public function test_empty_field_is_still_reported(): void {
		$this->assertFalse( $this->detector()->should_hide_missing_account( new WP_Error( 'empty_username', 'Vacío' ) ) );
		$this->assertTrue( $this->detector()->should_hide_missing_account( new WP_Error( 'invalid_email', 'No existe' ) ) );
	}

	public function test_missing_account_is_reported_when_protection_is_off(): void {
		$detector = $this->detector( array( 'rest_block_user_enum' => false ) );

		$detector->on_lost_password( new WP_Error(), false );

		$this->assertFalse( $detector->redirected );
	}

	public function test_lost_password_limit_rejects_without_blocking(): void {
		$GLOBALS['wpdb']->insert_id = 6; // Sexto pedido en la hora (límite 5).
		$errors = new WP_Error();

		$this->detector()->on_lost_password( $errors, (object) array( 'ID' => 1 ) );

		$this->assertContains( 'wps_rate_limited', $errors->get_error_codes() );
		$this->assertCount( 0, $this->block_inserts(), 'Quien olvidó su contraseña no puede quedar bloqueado del sitio.' );
	}

	/*──────────────────────────────────────────────
	 * Registro
	 *──────────────────────────────────────────────*/

	public function test_registration_limit_rejects_without_blocking(): void {
		$GLOBALS['wpdb']->insert_id = 4; // Cuarto registro en la hora (límite 3).

		$errors = $this->detector()->limit_registration( new WP_Error(), 'nuevo', 'nuevo@example.com' );

		$this->assertContains( 'wps_rate_limited', $errors->get_error_codes() );
		$this->assertCount( 0, $this->block_inserts() );
	}

	public function test_registration_within_limit_passes(): void {
		$errors = $this->detector()->limit_registration( new WP_Error(), 'nuevo', 'nuevo@example.com' );

		$this->assertFalse( $errors->has_errors() );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function detector( array $settings = array() ): WPS_Login_Detector {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		return new class( $loader ) extends WPS_Login_Detector {
			public $redirected = false;
			protected function redirect_as_sent(): void {
				$this->redirected = true;
			}
		};
	}

	private function block_inserts(): array {
		return array_filter( $GLOBALS['wpdb']->inserts, function ( $insert ) {
			return 'wp_wps_blocked_ips' === $insert[0];
		} );
	}

	private function reset_singletons(): void {
		foreach ( array( 'WPS_Request', 'WPS_Rate_Limiter' ) as $class ) {
			$prop = new \ReflectionProperty( $class, 'instance' );
			$prop->setAccessible( true );
			$prop->setValue( null, null );
		}
		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), array() );
	}
}
