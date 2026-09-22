<?php
/**
 * Tests del cargador estable de la Capa 0.
 *
 * `auto_prepend_file` apunta al cargador. Si el firewall del plugin falta
 * (actualización en curso, plugin eliminado o renombrado), el cargador no
 * puede fallar: un error ahí tumba cada petición del sitio.
 */
class Test_WPS_Prepend_Loader extends \PHPUnit\Framework\TestCase {

	/** @var string */
	private $dir;

	protected function setUp(): void {
		$this->dir = sys_get_temp_dir() . '/wps-loader-' . uniqid();
		mkdir( $this->dir );
	}

	protected function tearDown(): void {
		foreach ( (array) glob( $this->dir . '/*' ) as $file ) {
			unlink( $file );
		}
		rmdir( $this->dir );
	}

	public function test_loader_is_silent_when_the_plugin_is_missing(): void {
		$loader = $this->write_loader( $this->dir . '/no-existe/wps-firewall-prepend.php' );

		$output = $this->run_php( $loader );

		$this->assertSame( '', $output, 'El cargador no puede emitir errores si falta el plugin.' );
	}

	public function test_loader_includes_the_firewall_when_present(): void {
		$firewall = $this->dir . '/wps-firewall-prepend.php';
		file_put_contents( $firewall, "<?php echo 'firewall-cargado';" );

		$loader = $this->write_loader( $firewall );

		$this->assertSame( 'firewall-cargado', $this->run_php( $loader ) );
	}

	public function test_loader_does_not_leak_variables_into_the_request(): void {
		$loader = $this->write_loader( $this->dir . '/no-existe.php' );
		$probe  = $this->dir . '/probe.php';
		file_put_contents( $probe, '<?php require ' . var_export( $loader, true ) . '; echo isset( $prepend ) ? "leak" : "ok";' );

		$this->assertSame( 'ok', $this->run_php( $probe ) );
	}

	private function write_loader( string $firewall_path ): string {
		$loader = $this->dir . '/wps-firewall-loader.php';
		file_put_contents( $loader, WPS_Activator::build_prepend_loader( $firewall_path ) );
		return $loader;
	}

	/**
	 * Ejecutar un archivo PHP en un proceso aparte y devolver su salida.
	 */
	private function run_php( string $file ): string {
		$cmd = escapeshellarg( PHP_BINARY ) . ' -d display_errors=1 -d error_reporting=-1 ' . escapeshellarg( $file ) . ' 2>&1';
		return trim( (string) shell_exec( $cmd ) );
	}
}
