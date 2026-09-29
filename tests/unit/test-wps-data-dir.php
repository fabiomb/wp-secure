<?php
/**
 * Tests de la protección de wp-content/wps-data/ y del log de la Capa 0.
 *
 * En nginx el .htaccess no rige: el log no puede ser legible por web aunque
 * alguien lo pida directamente.
 */
class Test_WPS_Data_Dir extends \PHPUnit\Framework\TestCase {

	/** @var string */
	private $dir;

	private $server_backup;

	public static function setUpBeforeClass(): void {
		unset( $_SERVER['REMOTE_ADDR'] );
		require_once WPS_INCLUDES_DIR . 'firewall/wps-firewall-prepend.php';
	}

	protected function setUp(): void {
		$this->server_backup = $_SERVER;
		$this->dir           = sys_get_temp_dir() . '/wps-data-' . uniqid() . '/';
		mkdir( $this->dir );
	}

	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		foreach ( (array) scandir( $this->dir ) as $name ) {
			if ( is_file( $this->dir . $name ) ) {
				unlink( $this->dir . $name );
			}
		}
		rmdir( $this->dir );
	}

	/*──────────────────────────────────────────────
	 * Directorio
	 *──────────────────────────────────────────────*/

	public function test_htaccess_denies_access_on_apache_22_and_24(): void {
		WPS_Activator::protect_data_dir( $this->dir );

		$htaccess = file_get_contents( $this->dir . '.htaccess' );
		$this->assertStringContainsString( 'Require all denied', $htaccess );
		$this->assertStringContainsString( 'Deny from all', $htaccess );
		$this->assertFileExists( $this->dir . 'index.php' );
	}

	public function test_old_htaccess_is_rewritten(): void {
		file_put_contents( $this->dir . '.htaccess', "Order deny,allow\nDeny from all\n" );

		WPS_Activator::protect_data_dir( $this->dir );

		$this->assertSame( WPS_Activator::DATA_DIR_HTACCESS, file_get_contents( $this->dir . '.htaccess' ) );
	}

	public function test_old_plain_text_log_is_removed(): void {
		file_put_contents( $this->dir . 'wps-firewall.log', "[2026-01-01] BLOCKED 45.33.32.156 GET /\n" );

		WPS_Activator::protect_data_dir( $this->dir );

		$this->assertFileDoesNotExist( $this->dir . 'wps-firewall.log' );
	}

	/*──────────────────────────────────────────────
	 * Log de la Capa 0
	 *──────────────────────────────────────────────*/

	public function test_log_is_a_php_file_that_shows_nothing_when_requested(): void {
		$this->log_request( 'GET', '/wp-login.php' );

		$log = $this->dir . WPS_Firewall_Prepend::LOG_FILE;
		$this->assertStringStartsWith( WPS_Firewall_Prepend::LOG_GUARD, file_get_contents( $log ) );
		$this->assertSame( '', $this->run_php( $log ), 'Pedido por web, el log no puede mostrar IPs ni URIs.' );
	}

	public function test_visitor_input_cannot_add_php_or_fake_entries(): void {
		$this->log_request( "GET", "/x?<?php system('id'); ?>\n[2026-01-01 00:00:00] BLOCKED 1.2.3.4 GET /falso" );

		$content = file_get_contents( $this->dir . WPS_Firewall_Prepend::LOG_FILE );
		$body    = substr( $content, strlen( WPS_Firewall_Prepend::LOG_GUARD ) );

		$this->assertStringNotContainsString( '<?php', $body );
		$this->assertStringNotContainsString( '?>', $body );
		$this->assertSame( 1, substr_count( $body, "\n" ), 'Un salto de línea en la URI no puede crear otra entrada.' );
	}

	public function test_log_rotates_when_it_grows_too_large(): void {
		$log = $this->dir . WPS_Firewall_Prepend::LOG_FILE;
		file_put_contents( $log, WPS_Firewall_Prepend::LOG_GUARD . str_repeat( 'x', WPS_Firewall_Prepend::LOG_MAX_BYTES + 1 ) );

		$this->log_request( 'GET', '/' );

		$this->assertFileExists( $this->dir . WPS_Firewall_Prepend::LOG_ROTATED );
		$this->assertLessThan( 200, filesize( $log ) );
		$this->assertStringStartsWith( WPS_Firewall_Prepend::LOG_GUARD, file_get_contents( $log ) );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function log_request( string $method, string $uri ): void {
		$_SERVER['REQUEST_METHOD'] = $method;
		$_SERVER['REQUEST_URI']    = $uri;

		$data_file = new \ReflectionProperty( 'WPS_Firewall_Prepend', 'data_file' );
		$data_file->setAccessible( true );
		$data_file->setValue( null, $this->dir . 'wps-blocked-ips.php' );

		$log = new \ReflectionMethod( 'WPS_Firewall_Prepend', 'log_block' );
		$log->setAccessible( true );
		$log->invoke( null, '45.33.32.156' );
	}

	private function run_php( string $file ): string {
		return (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $file ) . ' 2>&1' );
	}
}
