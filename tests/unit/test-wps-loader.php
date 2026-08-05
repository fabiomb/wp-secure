<?php
/**
 * Tests unitarios para WPS_Loader.
 */
class Test_WPS_Loader extends \PHPUnit\Framework\TestCase {

	private function loader_with( array $settings = array() ): WPS_Loader {
		$loader     = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache_prop = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache_prop->setAccessible( true );
		$cache_prop->setValue( $loader, $settings );

		return $loader;
	}

	/*──────────────────────────────────────────────
	 * Exclusión de estáticos del log de tráfico
	 *──────────────────────────────────────────────*/

	public function test_excludes_static_assets_from_traffic_log_by_default(): void {
		$loader = $this->loader_with( array( 'exclude_static_from_log' => true ) );

		$this->assertFalse( $loader->should_log_traffic( 'static' ) );
	}

	public function test_logs_regular_pages(): void {
		$loader = $this->loader_with( array( 'exclude_static_from_log' => true ) );

		$this->assertTrue( $loader->should_log_traffic( 'page' ) );
		$this->assertTrue( $loader->should_log_traffic( 'login' ) );
		$this->assertTrue( $loader->should_log_traffic( 'restapi' ) );
	}

	public function test_logs_static_assets_when_the_setting_is_off(): void {
		$loader = $this->loader_with( array( 'exclude_static_from_log' => false ) );

		$this->assertTrue(
			$loader->should_log_traffic( 'static' ),
			'Si el ajuste está desactivado, los estáticos deben registrarse.'
		);
	}

	/*──────────────────────────────────────────────
	 * Capas del firewall
	 *──────────────────────────────────────────────*/

	public function test_layer1_is_enabled_by_default(): void {
		$loader = $this->loader_with( array() );

		$this->assertTrue( $loader->is_layer_enabled( 1 ) );
	}

	public function test_layer1_can_be_turned_off(): void {
		$loader = $this->loader_with( array( 'firewall_layer1_enabled' => false ) );

		$this->assertFalse(
			$loader->is_layer_enabled( 1 ),
			'El interruptor de Capa 1 en Configuración debe apagar realmente la capa.'
		);
	}

	public function test_layer0_is_disabled_by_default(): void {
		$loader = $this->loader_with( array() );

		$this->assertFalse( $loader->is_layer_enabled( 0 ) );
	}
}
