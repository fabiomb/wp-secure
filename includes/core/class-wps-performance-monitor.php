<?php
defined( 'ABSPATH' ) || exit;

/**
 * Monitor de rendimiento.
 *
 * Mide tiempos de ejecución de componentes del plugin y proporciona
 * métricas opcionales en el admin bar cuando el modo debug está activado.
 */
class WPS_Performance_Monitor {

	/** @var WPS_Performance_Monitor|null */
	private static $instance = null;

	/** @var array Timers activos ['label' => start_time]. */
	private $timers = array();

	/** @var array Resultados ['label' => elapsed_ms]. */
	private $results = array();

	/** @var bool */
	private $debug_enabled = false;

	private function __construct() {}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Inicializar con configuración.
	 */
	public function init( WPS_Loader $loader ): void {
		$this->debug_enabled = (bool) $loader->get_setting( 'performance_debug', false );

		if ( $this->debug_enabled && is_admin() ) {
			add_action( 'admin_bar_menu', array( $this, 'add_admin_bar_info' ), 999 );
			add_action( 'shutdown', array( $this, 'log_performance' ), 9999 );
		}
	}

	/**
	 * Iniciar un timer.
	 */
	public function start( string $label ): void {
		$this->timers[ $label ] = microtime( true );
	}

	/**
	 * Detener un timer y registrar el resultado.
	 *
	 * @return float Milisegundos transcurridos.
	 */
	public function stop( string $label ): float {
		if ( ! isset( $this->timers[ $label ] ) ) {
			return 0.0;
		}

		$elapsed = ( microtime( true ) - $this->timers[ $label ] ) * 1000;
		$this->results[ $label ] = round( $elapsed, 2 );

		unset( $this->timers[ $label ] );

		return $this->results[ $label ];
	}

	/**
	 * Obtener todos los resultados de medición.
	 */
	public function get_results(): array {
		return $this->results;
	}

	/**
	 * Obtener uso de memoria.
	 */
	public function get_memory_usage(): array {
		return array(
			'current_mb' => round( memory_get_usage() / 1048576, 2 ),
			'peak_mb'    => round( memory_get_peak_usage() / 1048576, 2 ),
		);
	}

	/**
	 * Obtener overhead total del plugin.
	 */
	public function get_total_overhead_ms(): float {
		$total = 0.0;
		foreach ( $this->results as $ms ) {
			$total += $ms;
		}
		return round( $total, 2 );
	}

	/**
	 * Agregar info al admin bar.
	 *
	 * @param \WP_Admin_Bar $wp_admin_bar
	 */
	public function add_admin_bar_info( $wp_admin_bar ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$request  = WPS_Request::get_instance();
		$total_ms = $request->elapsed_ms();
		$overhead = $this->get_total_overhead_ms();
		$memory   = $this->get_memory_usage();

		$wp_admin_bar->add_node( array(
			'id'    => 'wps-performance',
			'title' => sprintf( 'WPS: %.1fms | Peak: %.1fMB', $overhead, $memory['peak_mb'] ),
			'meta'  => array( 'class' => 'wps-adminbar-perf' ),
		) );

		$wp_admin_bar->add_node( array(
			'id'     => 'wps-perf-total',
			'parent' => 'wps-performance',
			'title'  => sprintf( __( 'Tiempo total página: %dms', 'wp-secure' ), $total_ms ),
		) );

		$wp_admin_bar->add_node( array(
			'id'     => 'wps-perf-overhead',
			'parent' => 'wps-performance',
			'title'  => sprintf( __( 'Overhead WPS: %.1fms', 'wp-secure' ), $overhead ),
		) );

		foreach ( $this->results as $label => $ms ) {
			$wp_admin_bar->add_node( array(
				'id'     => 'wps-perf-' . sanitize_key( $label ),
				'parent' => 'wps-performance',
				'title'  => sprintf( '%s: %.2fms', $label, $ms ),
			) );
		}

		$wp_admin_bar->add_node( array(
			'id'     => 'wps-perf-memory',
			'parent' => 'wps-performance',
			'title'  => sprintf( __( 'Memoria: %.1fMB (pico: %.1fMB)', 'wp-secure' ), $memory['current_mb'], $memory['peak_mb'] ),
		) );
	}

	/**
	 * Log de rendimiento en shutdown (solo modo debug).
	 */
	public function log_performance(): void {
		if ( ! $this->debug_enabled ) {
			return;
		}

		$overhead = $this->get_total_overhead_ms();
		$memory   = $this->get_memory_usage();

		// Solo logear si hay datos significativos.
		if ( $overhead > 0 ) {
			error_log( sprintf(
				'[WP Seguro Perf] Overhead: %.2fms | Memory: %.1fMB | Details: %s',
				$overhead,
				$memory['peak_mb'],
				wp_json_encode( $this->results )
			) );
		}
	}
}
