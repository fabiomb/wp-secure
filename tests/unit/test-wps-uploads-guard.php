<?php
/**
 * Tests de PHP en la carpeta de subidas: búsqueda, avisos y reglas.
 *
 * Los contenidos de prueba son inocuos a propósito: un archivo de test con
 * la firma de un webshell lo bloquea el antivirus del equipo de desarrollo.
 */
class Test_WPS_Uploads_Guard extends \PHPUnit\Framework\TestCase {

	/** @var string */
	private $dir;

	/** @var WPS_Uploads_Guard */
	private $guard;

	public static function setUpBeforeClass(): void {
		unset( $_SERVER['REMOTE_ADDR'] );
		require_once WPS_INCLUDES_DIR . 'firewall/wps-firewall-prepend.php';
	}

	protected function setUp(): void {
		$this->dir = str_replace( '\\', '/', sys_get_temp_dir() ) . '/wps-uploads-' . uniqid();
		mkdir( $this->dir . '/2026/09', 0777, true );
		file_put_contents( $this->dir . '/2026/09/foto.jpg', 'imagen' );

		$GLOBALS['wps_test_options'] = array();
		$GLOBALS['wps_test_mails']   = array();

		$this->guard = new WPS_Uploads_Guard( $this->loader() );
		$this->guard->set_dir( $this->dir );
	}

	protected function tearDown(): void {
		$files = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $this->dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $files as $file ) {
			$file->isDir() ? rmdir( $file->getPathname() ) : unlink( $file->getPathname() );
		}
		rmdir( $this->dir );
		$GLOBALS['wps_test_options'] = array();
	}

	/*──────────────────────────────────────────────
	 * Búsqueda
	 *──────────────────────────────────────────────*/

	public function test_media_only_is_clean(): void {
		$this->assertSame( array(), WPS_Uploads_Guard::find( $this->dir ) );
	}

	public function test_php_and_double_extensions_are_found(): void {
		$this->put( '2026/09/archivo.php', '<?php echo "hola";' );
		$this->put( '2026/09/imagen.php.jpg', '<?php echo "hola";' );
		$this->put( '2026/09/viejo.PHTML', '<?php echo "hola";' );
		$this->put( '2026/09/fotos.photo.jpg', 'imagen' );

		$found = WPS_Uploads_Guard::find( $this->dir );

		$this->assertSame(
			array( $this->dir . '/2026/09/archivo.php', $this->dir . '/2026/09/imagen.php.jpg', $this->dir . '/2026/09/viejo.PHTML' ),
			array_keys( $found )
		);
		$this->assertSame( 'php', $found[ $this->dir . '/2026/09/archivo.php' ]['reason'] );
	}

	public function test_silence_is_golden_index_is_ignored(): void {
		$this->put( 'plugin-x/index.php', "<?php\n// Silence is golden.\n" );
		$this->put( 'plugin-y/index.php', "<?php /** Nada. */ ?>\n<p>vacío</p>" );

		$this->assertSame( array(), WPS_Uploads_Guard::find( $this->dir ) );
	}

	public function test_code_after_a_closing_tag_in_a_comment_is_not_inert(): void {
		// Un comentario de línea termina en la etiqueta de cierre: lo que sigue se ejecuta.
		$this->assertFalse( WPS_Uploads_Guard::is_inert_php( '<?php // nada ?><?php echo "hola";' ) );
		$this->assertTrue( WPS_Uploads_Guard::is_inert_php( "<?php\n// Silence is golden.\n" ) );
	}

	public function test_config_that_enables_php_is_found(): void {
		$this->put( '2026/.htaccess', "AddHandler application/x-httpd-php .jpg\n" );
		$this->put( '2026/09/.user.ini', "auto_prepend_file = foto.jpg\n" );

		$found = WPS_Uploads_Guard::find( $this->dir );

		$this->assertSame( 'config', $found[ $this->dir . '/2026/.htaccess' ]['reason'] );
		$this->assertSame( 'config', $found[ $this->dir . '/2026/09/.user.ini' ]['reason'] );
	}

	public function test_protective_htaccess_of_other_plugins_is_not_reported(): void {
		$this->put( 'woo/.htaccess', "deny from all\n" );
		$this->put( 'wf/.htaccess', "<IfModule mod_php7.c>\nphp_flag engine 0\n</IfModule>\nAddHandler cgi-script .php .phtml\nOptions -ExecCGI\n" );
		$this->put( 'webp/.htaccess', "AddType image/webp .webp\n" );
		$this->put( '.htaccess', WPS_Uploads_Guard::RULES );

		$this->assertSame( array(), WPS_Uploads_Guard::find( $this->dir ) );
	}

	/*──────────────────────────────────────────────
	 * Escaneo, avisos y revisión
	 *──────────────────────────────────────────────*/

	public function test_files_present_at_the_first_scan_are_reported(): void {
		$this->put( '2026/09/archivo.php', '<?php echo "hola";' );

		$this->assertCount( 1, $this->guard->scan(), 'No hay referencia que los acepte en silencio.' );
		$this->assertCount( 1, $GLOBALS['wps_test_mails'] );
		$this->assertStringContainsString( 'archivo.php', $GLOBALS['wps_test_mails'][0]['message'] );
	}

	public function test_known_files_are_reported_once_but_stay_pending(): void {
		$this->put( '2026/09/archivo.php', '<?php echo "hola";' );
		$this->guard->scan();

		$this->assertSame( array(), $this->guard->scan() );
		$this->assertCount( 1, $GLOBALS['wps_test_mails'] );
		$this->assertCount( 1, $this->guard->pending() );
	}

	public function test_reviewed_files_are_reported_again_if_they_change(): void {
		$this->put( '2026/09/archivo.php', '<?php echo "hola";' );
		$this->guard->scan();

		$this->assertSame( 1, $this->guard->review() );
		$this->assertSame( array(), $this->guard->pending() );
		$this->assertSame( array(), $this->guard->scan() );

		$this->put( '2026/09/archivo.php', '<?php echo "chau";' );

		$this->assertCount( 1, $this->guard->scan() );
		$this->assertCount( 1, $this->guard->pending() );
	}

	public function test_removed_files_leave_the_list(): void {
		$this->put( '2026/09/archivo.php', '<?php echo "hola";' );
		$this->guard->scan();
		$this->guard->review();

		unlink( $this->dir . '/2026/09/archivo.php' );
		$this->guard->scan();

		$state = $this->guard->state();
		$this->assertSame( array(), $state['files'] );
		$this->assertSame( array(), $state['reviewed'] );
	}

	/*──────────────────────────────────────────────
	 * Reglas de .htaccess
	 *──────────────────────────────────────────────*/

	public function test_rules_are_written_and_removed(): void {
		$this->assertTrue( WPS_Uploads_Guard::sync_rules( true, $this->dir ) );
		$this->assertTrue( WPS_Uploads_Guard::has_rules( $this->dir ) );

		$this->assertTrue( WPS_Uploads_Guard::sync_rules( false, $this->dir ) );
		$this->assertFileDoesNotExist( $this->dir . '/.htaccess', 'Sólo tenía las reglas propias.' );
	}

	public function test_rules_of_other_plugins_are_kept(): void {
		$other = "# BEGIN Otro plugin\nOptions -Indexes\n# END Otro plugin\n";

		$with = WPS_Uploads_Guard::with_rules( $other, true );
		$this->assertStringStartsWith( '# BEGIN WP Seguro', $with );
		$this->assertStringContainsString( $other, $with );

		$this->assertSame( $with, WPS_Uploads_Guard::with_rules( $with, true ), 'Idempotente.' );
		$this->assertSame( $other, WPS_Uploads_Guard::with_rules( $with, false ) );
	}

	public function test_rules_keep_windows_line_endings(): void {
		$with = WPS_Uploads_Guard::with_rules( "Options -Indexes\r\n", true );

		$this->assertStringNotContainsString( "\n", str_replace( "\r\n", '', $with ) );
	}

	/*──────────────────────────────────────────────
	 * Capa 0
	 *──────────────────────────────────────────────*/

	public function test_layer0_data_carries_the_denied_dirs(): void {
		$this->assertArrayNotHasKey( 'deny_php_dirs', WPS_Activator::build_blocked_ips_data( array(), array(), 0 ) );

		$data = WPS_Activator::build_blocked_ips_data( array(), array(), 0, array( $this->dir ) );
		$this->assertSame( array( $this->dir ), $data['deny_php_dirs'] );
	}

	public function test_layer0_denies_scripts_inside_uploads_only(): void {
		$this->put( '2026/09/archivo.php', '<?php echo "hola";' );
		$data = array( 'deny_php_dirs' => array( $this->dir ) );

		$this->assertTrue( $this->denied( $this->dir . '/2026/09/archivo.php', $data ) );
		$this->assertTrue( $this->denied( $this->dir . '/2026/../2026/09/archivo.php', $data ), 'Se resuelve la ruta real.' );
		$this->assertFalse( $this->denied( dirname( $this->dir ) . '/index.php', $data ) );
		$this->assertFalse( $this->denied( $this->dir . '-otro/archivo.php', $data ), 'Un prefijo de nombre no alcanza.' );
		$this->assertFalse( $this->denied( $this->dir . '/2026/09/archivo.php', array() ) );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function put( string $relative, string $content ): void {
		$path = $this->dir . '/' . $relative;
		if ( ! is_dir( dirname( $path ) ) ) {
			mkdir( dirname( $path ), 0777, true );
		}
		file_put_contents( $path, $content );
	}

	private function denied( string $script, array $data ): bool {
		$ref = new \ReflectionMethod( 'WPS_Firewall_Prepend', 'is_denied_script' );
		$ref->setAccessible( true );
		return $ref->invoke( null, $script, $data );
	}

	private function loader(): WPS_Loader {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, array( 'notify_file_changes' => true, 'notify_email' => 'alertas@example.com' ) );

		$notifier = new \ReflectionProperty( 'WPS_Admin_Notifier', 'instance' );
		$notifier->setAccessible( true );
		$notifier->setValue( null, null );

		return $loader;
	}
}
