<?php
/**
 * Tests del contrato de carga de dependencias del MU-Plugin (Capa 1).
 *
 * El MU-Plugin corre antes de que el autoloader del plugin esté registrado,
 * así que carga sus clases a mano. Si esa lista queda incompleta, las clases
 * faltantes simplemente no existen y el código cae a rutas de respaldo
 * inseguras en vez de fallar de forma visible.
 */
class Test_WPS_Firewall_MuPlugin extends \PHPUnit\Framework\TestCase {

	/** @var string */
	private $source;

	protected function setUp(): void {
		$this->source = file_get_contents(
			dirname( __DIR__, 2 ) . '/includes/firewall/wps-firewall-muplugin.php'
		);
	}

	/**
	 * Orden en que el MU-Plugin hace require de las clases del plugin.
	 *
	 * @return string[]
	 */
	private function loaded_classes(): array {
		preg_match_all( '/[\'"]([a-z\/]*class-wps-[a-z-]+\.php)[\'"]/', $this->source, $matches );
		return $matches[1];
	}

	public function test_loads_proxy_config(): void {
		$this->assertContains(
			'core/class-wps-proxy-config.php',
			$this->loaded_classes(),
			'Sin WPS_Proxy_Config, WPS_Request resuelve la IP confiando en headers sin verificar el proxy.'
		);
	}

	public function test_loads_proxy_config_before_request(): void {
		$classes = $this->loaded_classes();

		$proxy_position   = array_search( 'core/class-wps-proxy-config.php', $classes, true );
		$request_position = array_search( 'core/class-wps-request.php', $classes, true );

		$this->assertNotFalse( $request_position, 'El MU-Plugin debe cargar WPS_Request.' );
		$this->assertNotFalse( $proxy_position, 'El MU-Plugin debe cargar WPS_Proxy_Config.' );
		$this->assertLessThan(
			$request_position,
			$proxy_position,
			'WPS_Request resuelve la IP en su constructor, así que WPS_Proxy_Config debe estar disponible antes.'
		);
	}

	public function test_declares_current_plugin_version(): void {
		preg_match( '/^\s*\*\s*Version:\s*(.+)$/mi', $this->source, $header );
		preg_match( '/define\(\s*[\'"]WPS_VERSION[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]/', $this->source, $fallback );

		$this->assertNotEmpty( $header, 'El MU-Plugin debe declarar una versión en su header.' );
		$this->assertNotEmpty( $fallback, 'El MU-Plugin debe definir WPS_VERSION como respaldo.' );
		$this->assertEquals(
			trim( $header[1] ),
			$fallback[1],
			'La versión de respaldo quedó desincronizada del header del MU-Plugin.'
		);
	}
}
