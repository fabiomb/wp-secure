<?php
/**
 * Tests del chequeo de endurecimiento.
 *
 * El entorno (constantes, versión de PHP, permisos, usuarios) se reemplaza en
 * una subclase para verificar cada estado sin depender del equipo de prueba.
 */
class Test_WPS_Hardening_Check extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wps_test_transients'] = array();
		$GLOBALS['wps_test_user_caps']  = array();
	}

	/*──────────────────────────────────────────────
	 * wp-config.php y errores
	 *──────────────────────────────────────────────*/

	public function test_file_editor(): void {
		$this->assertSame( 'warn', $this->check()->check_file_edit()['status'] );
		$this->assertSame( 'pass', $this->check( array( 'constants' => array( 'DISALLOW_FILE_EDIT' => true ) ) )->check_file_edit()['status'] );
		$this->assertSame( 'pass', $this->check( array( 'constants' => array( 'DISALLOW_FILE_MODS' => true ) ) )->check_file_edit()['status'] );
	}

	public function test_displayed_errors_fail_even_without_wp_debug(): void {
		// Con WP_DEBUG apagado, WordPress no toca display_errors: vale php.ini.
		$this->assertSame( 'fail', $this->check( array( 'errors_displayed' => true ) )->check_debug_display()['status'] );
	}

	public function test_wp_debug_without_display_is_a_warning(): void {
		$this->assertSame( 'warn', $this->check( array( 'constants' => array( 'WP_DEBUG' => true ) ) )->check_debug_display()['status'] );
		$this->assertSame( 'pass', $this->check()->check_debug_display()['status'] );
	}

	public function test_wp_config_permissions(): void {
		$this->assertSame( 'info', $this->check( array( 'perms' => null ) )->check_wp_config_permissions()['status'], 'Windows.' );
		$this->assertSame( 'fail', $this->check( array( 'perms' => 0100666 ) )->check_wp_config_permissions()['status'] );
		$this->assertSame( 'warn', $this->check( array( 'perms' => 0100644 ) )->check_wp_config_permissions()['status'] );
		$this->assertSame( 'pass', $this->check( array( 'perms' => 0100640 ) )->check_wp_config_permissions()['status'] );
		$this->assertSame( 'pass', $this->check( array( 'perms' => 0100400 ) )->check_wp_config_permissions()['status'] );
		$this->assertSame( 'info', $this->check( array( 'wp_config' => '' ) )->check_wp_config_permissions()['status'] );
	}

	public function test_permissions_message_shows_octal_mode(): void {
		$this->assertStringContainsString( '0644', $this->check( array( 'perms' => 0100644 ) )->check_wp_config_permissions()['message'] );
	}

	/*──────────────────────────────────────────────
	 * PHP
	 *──────────────────────────────────────────────*/

	public function test_php_version_support_window(): void {
		$now = strtotime( '2026-09-29 12:00:00 UTC' );

		$this->assertSame( 'fail', $this->check( array( 'php' => '8.1.30', 'now' => $now ) )->check_php_version()['status'], 'Sin parches desde 2025-12-31.' );
		$this->assertSame( 'warn', $this->check( array( 'php' => '8.2.12', 'now' => $now ) )->check_php_version()['status'], 'Termina en menos de seis meses.' );
		$this->assertSame( 'pass', $this->check( array( 'php' => '8.3.10', 'now' => $now ) )->check_php_version()['status'] );
		$this->assertSame( 'pass', $this->check( array( 'php' => '9.0.0', 'now' => $now ) )->check_php_version()['status'], 'Versión posterior a la tabla.' );
	}

	public function test_php_verdict_changes_with_time(): void {
		$check = array( 'php' => '8.3.10' );

		$this->assertSame( 'warn', $this->check( $check + array( 'now' => strtotime( '2027-09-01 UTC' ) ) )->check_php_version()['status'] );
		$this->assertSame( 'fail', $this->check( $check + array( 'now' => strtotime( '2028-01-01 UTC' ) ) )->check_php_version()['status'] );
	}

	/*──────────────────────────────────────────────
	 * Usuarios, HTTPS, uploads, prefijo
	 *──────────────────────────────────────────────*/

	public function test_admin_user(): void {
		$this->assertSame( 'pass', $this->check()->check_admin_user()['status'] );

		$admin = (object) array( 'ID' => 7 );
		$this->assertSame( 'info', $this->check( array( 'admin' => $admin ) )->check_admin_user()['status'], 'Existe pero no administra.' );

		$GLOBALS['wps_test_user_caps'][7]['manage_options'] = true;
		$this->assertSame( 'warn', $this->check( array( 'admin' => $admin ) )->check_admin_user()['status'] );
	}

	public function test_https(): void {
		$this->assertSame( 'pass', $this->check( array( 'home' => 'https://example.com/' ) )->check_https()['status'] );
		$this->assertSame( 'warn', $this->check( array( 'home' => 'http://example.com/' ) )->check_https()['status'] );
	}

	public function test_uploads_php_follows_the_setting(): void {
		$this->assertSame( 'warn', $this->check( array(), array( 'uploads_block_php' => false ) )->check_uploads_php()['status'] );
		$this->assertSame( 'pass', $this->check( array(), array( 'uploads_block_php' => true ) )->check_uploads_php()['status'] );
	}

	public function test_default_table_prefix_is_informative_only(): void {
		$this->assertSame( 'info', $this->check( array( 'prefix' => 'wp_' ) )->check_db_prefix()['status'] );
		$this->assertSame( 'pass', $this->check( array( 'prefix' => 'x7k_' ) )->check_db_prefix()['status'] );
	}

	/*──────────────────────────────────────────────
	 * Pasada completa
	 *──────────────────────────────────────────────*/

	public function test_http_checks_are_cached(): void {
		$cached = array(
			'directory_listing' => array( 'id' => 'directory_listing', 'status' => 'fail', 'label' => '', 'message' => '', 'fix' => '' ),
			'debug_log'         => array( 'id' => 'debug_log', 'status' => 'pass', 'label' => '', 'message' => '', 'fix' => '' ),
		);
		$GLOBALS['wps_test_transients'][ WPS_Hardening_Check::HTTP_CACHE ] = $cached;

		$results = $this->check()->run();
		$ids     = array_column( $results, 'status', 'id' );

		$this->assertCount( 10, $results );
		$this->assertSame( 'fail', $ids['directory_listing'], 'Sin peticiones nuevas: se usa lo guardado.' );
		$this->assertSame( 1, WPS_Hardening_Check::counts( $results )['fail'] );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function check( array $env = array(), array $settings = array() ): WPS_Hardening_Check {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		$env += array(
			'constants'        => array(),
			'errors_displayed' => false,
			'php'              => '8.3.10',
			'now'              => strtotime( '2026-09-29 UTC' ),
			'prefix'           => 'wps_',
			'admin'            => false,
			'home'             => 'https://example.com/',
			'wp_config'        => '/var/www/wp-config.php',
			'perms'            => 0100640,
		);

		return new class( $loader, $env ) extends WPS_Hardening_Check {
			private $env;

			public function __construct( WPS_Loader $loader, array $env ) {
				parent::__construct( $loader );
				$this->env = $env;
			}
			protected function constant( string $name ) {
				return $this->env['constants'][ $name ] ?? null;
			}
			protected function errors_displayed(): bool {
				return $this->env['errors_displayed'];
			}
			protected function php_version(): string {
				return $this->env['php'];
			}
			protected function timestamp(): int {
				return $this->env['now'];
			}
			protected function db_prefix(): string {
				return $this->env['prefix'];
			}
			protected function user_by_login( string $login ) {
				return $this->env['admin'];
			}
			protected function home_url(): string {
				return $this->env['home'];
			}
			protected function wp_config_path(): string {
				return $this->env['wp_config'];
			}
			protected function file_permissions( string $file ): ?int {
				return $this->env['perms'];
			}
			protected function http_get( string $url ): ?array {
				throw new \LogicException( 'Sin peticiones HTTP en los tests.' );
			}
		};
	}
}
