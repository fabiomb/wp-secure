<?php
/**
 * Tests del campo trampa y el tiempo mínimo en formularios.
 */
class Test_WPS_Form_Guard extends \PHPUnit\Framework\TestCase {

	private $server_backup;
	private $post_backup;

	protected function setUp(): void {
		$this->server_backup         = $_SERVER;
		$this->post_backup           = $_POST;
		$GLOBALS['wps_test_options'] = array();
		$GLOBALS['wps_test_caps']    = array();
	}

	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$_POST   = $this->post_backup;
		$this->reset_request();
	}

	/*──────────────────────────────────────────────
	 * Evaluación de envíos
	 *──────────────────────────────────────────────*/

	public function test_human_submission_passes(): void {
		$post = $this->form_loaded_at( time() - 10 );

		$this->assertSame( WPS_Form_Guard::OK, WPS_Form_Guard::assess( $post, 3, time() ) );
	}

	public function test_filled_trap_field_is_a_bot(): void {
		$post = array_merge( $this->form_loaded_at( time() - 10 ), array( WPS_Form_Guard::HONEYPOT_FIELD => 'http://spam.tld' ) );

		$this->assertSame( WPS_Form_Guard::HONEYPOT, WPS_Form_Guard::assess( $post, 3, time() ) );
	}

	public function test_submission_faster_than_minimum_is_a_bot(): void {
		$post = $this->form_loaded_at( time() - 1 );

		$this->assertSame( WPS_Form_Guard::TOO_FAST, WPS_Form_Guard::assess( $post, 3, time() ) );
	}

	public function test_zero_minimum_disables_the_time_check(): void {
		$post = $this->form_loaded_at( time() );

		$this->assertSame( WPS_Form_Guard::OK, WPS_Form_Guard::assess( $post, 0, time() ) );
	}

	public function test_missing_or_forged_token_counts_as_missing(): void {
		$old = time() - 60;

		$this->assertSame( WPS_Form_Guard::MISSING, WPS_Form_Guard::assess( array(), 3, time() ) );
		$this->assertSame( WPS_Form_Guard::MISSING, WPS_Form_Guard::assess( array( WPS_Form_Guard::TIME_FIELD => $old . '.' . str_repeat( 'a', 20 ) ), 3, time() ), 'Una firma inventada no prueba que se cargó el formulario.' );
		$this->assertSame( WPS_Form_Guard::MISSING, WPS_Form_Guard::assess( array( WPS_Form_Guard::TIME_FIELD => 'basura' ), 3, time() ) );
	}

	public function test_rendered_fields_carry_a_valid_token(): void {
		$html = WPS_Form_Guard::fields_html( time() - 10 );

		preg_match( '/name="' . WPS_Form_Guard::TIME_FIELD . '" value="([^"]+)"/', $html, $m );
		$this->assertSame( WPS_Form_Guard::OK, WPS_Form_Guard::assess( array( WPS_Form_Guard::TIME_FIELD => $m[1] ), 3, time() ) );
		$this->assertStringContainsString( 'name="' . WPS_Form_Guard::HONEYPOT_FIELD . '"', $html );
		$this->assertStringContainsString( 'aria-hidden="true"', $html );
	}

	/*──────────────────────────────────────────────
	 * Login
	 *──────────────────────────────────────────────*/

	public function test_bot_login_on_wp_login_is_rejected(): void {
		$this->post_to( '/wp-login.php', array_merge( $this->form_loaded_at( time() - 10 ), array( WPS_Form_Guard::HONEYPOT_FIELD => 'x' ) ) );

		$this->assertInstanceOf( WP_Error::class, $this->guard()->check_login( null, 'admin', 'clave' ) );
	}

	public function test_login_without_plugin_fields_is_allowed(): void {
		// Formularios de login de temas o plugins que no usan los hooks estándar.
		$this->post_to( '/wp-login.php', array( 'log' => 'admin' ) );

		$this->assertNull( $this->guard()->check_login( null, 'admin', 'clave' ) );
	}

	public function test_login_outside_wp_login_is_not_checked(): void {
		$this->post_to( '/mi-cuenta/', array( WPS_Form_Guard::HONEYPOT_FIELD => 'x' ) );

		$this->assertNull( $this->guard()->check_login( null, 'cliente', 'clave' ) );
	}

	public function test_login_is_not_rejected_while_blocking_is_suspended(): void {
		$GLOBALS['wps_test_options'] = array( 'wps_unsafe_mode' => true );
		$this->post_to( '/wp-login.php', array( WPS_Form_Guard::HONEYPOT_FIELD => 'x' ) );

		$this->assertNull( $this->guard()->check_login( null, 'admin', 'clave' ) );
	}

	/*──────────────────────────────────────────────
	 * Comentarios
	 *──────────────────────────────────────────────*/

	public function test_comment_without_plugin_fields_goes_to_spam(): void {
		$this->post_to( '/wp-comments-post.php', array( 'comment' => 'Hola' ) );
		$guard = $this->guard();

		$data = $guard->check_comment( array( 'comment_content' => 'Hola' ) );

		$this->assertSame( array( 'comment_content' => 'Hola' ), $data, 'No se pierde: va a moderación como spam.' );
		$this->assertSame( 'spam', $guard->maybe_mark_spam( 0 ) );
	}

	public function test_human_comment_is_untouched(): void {
		$this->post_to( '/wp-comments-post.php', $this->form_loaded_at( time() - 20 ) );
		$guard = $this->guard();

		$guard->check_comment( array( 'comment_content' => 'Hola' ) );

		$this->assertSame( 0, $guard->maybe_mark_spam( 0 ) );
	}

	public function test_pingbacks_are_not_checked(): void {
		$this->post_to( '/xmlrpc.php', array() );
		$guard = $this->guard();

		$guard->check_comment( array( 'comment_type' => 'pingback' ) );

		$this->assertSame( 1, $guard->maybe_mark_spam( 1 ) );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function form_loaded_at( int $time ): array {
		return array(
			WPS_Form_Guard::HONEYPOT_FIELD => '',
			WPS_Form_Guard::TIME_FIELD     => WPS_Form_Guard::create_token( $time ),
		);
	}

	private function post_to( string $uri, array $post ): void {
		$_SERVER['REQUEST_URI']    = $uri;
		$_SERVER['REQUEST_METHOD'] = 'POST';
		$_SERVER['REMOTE_ADDR']    = '45.33.32.156';
		$_POST                     = $post;
		$this->reset_request();
	}

	private function guard(): WPS_Form_Guard {
		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, array() );
		return new WPS_Form_Guard( $loader );
	}

	private function reset_request(): void {
		$prop = new \ReflectionProperty( 'WPS_Request', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}
}
