<?php
defined( 'ABSPATH' ) || exit;

/**
 * Rate Limiter — Control de tasa de peticiones.
 *
 * Utiliza la tabla wps_rate_limits para contabilizar las peticiones
 * por IP en ventanas de tiempo. Bloquea automáticamente cuando se
 * exceden los límites configurados.
 *
 * Tipos de rate limit:
 * - pages:  peticiones que cargan WordPress (páginas, admin, REST)
 * - total:  todas las peticiones incluyendo estáticos
 * - 404:    peticiones que resultan en error 404
 * - login:  intentos de login (se registra desde login-detector)
 */
class WPS_Rate_Limiter {

	/** @var WPS_Rate_Limiter|null */
	private static $instance = null;

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Logger */
	private $logger;

	/** @var WPS_Blocker */
	private $blocker;

	/** @var string Tabla de rate limits. */
	private $table;

	/** @var array<string, bool> Hits ya contados en esta petición, por "ip|tipo". */
	private $recorded = array();

	/**
	 * Defaults de los límites.
	 *
	 * @var array
	 */
	private static $defaults = array(
		'rate_pages_per_min'    => 60,
		'rate_total_per_min'    => 240,
		'rate_404_per_min'      => 10,
		'rate_login_per_hour'   => 5,
		'rate_xmlrpc_per_hour'  => 0,
		'rate_block_minutes'    => 15,
	);

	private function __construct( WPS_Loader $loader ) {
		$this->loader  = $loader;
		$this->logger  = WPS_Logger::get_instance();
		$this->blocker = WPS_Blocker::get_instance();
		$this->table   = WPS_Db_Schema::table( 'rate_limits' );
	}

	/**
	 * @param WPS_Loader|null $loader Requerido en la primera llamada.
	 */
	public static function get_instance( WPS_Loader $loader = null ): self {
		if ( null === self::$instance ) {
			self::$instance = new self( $loader );
		}
		return self::$instance;
	}

	/**
	 * Registrar un hit para un tipo determinado.
	 * Retorna true si la IP sigue dentro de los límites, false si fue bloqueada.
	 *
	 * Cada tipo se cuenta una sola vez por petición. El MU-plugin (Capa 1) y
	 * el loader (Capa 2) registran los mismos hits en fases distintas, para
	 * cubrir tanto a visitantes anónimos como a usuarios logueados; sin esta
	 * guarda cada visita sumaba dos y los límites efectivos eran la mitad de
	 * los configurados.
	 */
	public function record_hit( string $ip, string $type ): bool {
		$key = $ip . '|' . $type;
		if ( isset( $this->recorded[ $key ] ) ) {
			return true;
		}
		$this->recorded[ $key ] = true;

		// El propio servidor (cron, loopbacks, precargadores de caché) no se
		// limita: bloquearlo deja al sitio sin tareas programadas.
		if ( WPS_Ip_Utils::is_server_ip( $ip ) ) {
			return true;
		}

		$limit = $this->get_limit( $type );

		// 0 = deshabilitado.
		if ( 0 === $limit ) {
			return true;
		}

		$window_seconds = $this->get_window_seconds( $type );
		$window_start   = $this->get_window_start( $window_seconds );

		// En IPv6 se cuenta por red: rotar de dirección dentro del /64 no
		// reinicia el contador.
		$count = $this->increment( $this->blocker->client_key( $ip ), $type, $window_start );

		if ( $count > $limit ) {
			$this->handle_exceeded( $ip, $type, $count, $limit );
			return false;
		}

		return true;
	}

	/**
	 * Obtener el conteo actual para un tipo.
	 */
	public function get_count( string $ip, string $type ): int {
		global $wpdb;

		$window_seconds = $this->get_window_seconds( $type );
		$window_start   = $this->get_window_start( $window_seconds );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count = $wpdb->get_var( $wpdb->prepare(
			"SELECT request_count FROM {$this->table} WHERE ip_address = %s AND limit_type = %s AND window_start = %s",
			$this->blocker->client_key( $ip ),
			$type,
			$window_start
		) );

		return $count ? (int) $count : 0;
	}

	/**
	 * Incrementar el contador de peticiones.
	 *
	 * Usa INSERT ... ON DUPLICATE KEY UPDATE para atomicidad, y recupera el
	 * nuevo valor en la misma consulta con LAST_INSERT_ID(expr): esto corre dos
	 * veces por visita (total y pages), así que ahorrar el SELECT de vuelta
	 * elimina dos consultas por petición.
	 *
	 * @return int El nuevo conteo.
	 */
	private function increment( string $ip, string $type, string $window_start ): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$affected = $wpdb->query( $wpdb->prepare(
			"INSERT INTO {$this->table} (ip_address, limit_type, window_start, request_count)
			VALUES (%s, %s, %s, 1)
			ON DUPLICATE KEY UPDATE request_count = LAST_INSERT_ID(request_count + 1)",
			$ip,
			$type,
			$window_start
		) );

		// MySQL devuelve 1 cuando insertó una fila nueva y 2 cuando actualizó
		// una existente. En el primer caso el contador arranca en 1; en el
		// segundo, LAST_INSERT_ID() trae el valor ya incrementado.
		if ( 1 === (int) $affected ) {
			return 1;
		}

		$count = (int) $wpdb->insert_id;

		return $count > 0 ? $count : 1;
	}

	/**
	 * Obtener el límite configurado para un tipo.
	 */
	private function get_limit( string $type ): int {
		$setting_map = array(
			'pages'  => 'rate_pages_per_min',
			'total'  => 'rate_total_per_min',
			'404'    => 'rate_404_per_min',
			'login'  => 'rate_login_per_hour',
			'xmlrpc' => 'rate_xmlrpc_per_hour',
		);

		$key     = $setting_map[ $type ] ?? 'rate_total_per_min';
		$default = self::$defaults[ $key ] ?? 60;

		return (int) $this->loader->get_setting( $key, $default );
	}

	/**
	 * Obtener la duración de la ventana de tiempo en segundos.
	 */
	private function get_window_seconds( string $type ): int {
		// Login y xmlrpc usan ventana de 1 hora, el resto 1 minuto.
		if ( in_array( $type, array( 'login', 'xmlrpc' ), true ) ) {
			return 3600;
		}
		return 60;
	}

	/**
	 * Calcular el inicio de la ventana de tiempo actual.
	 */
	private function get_window_start( int $window_seconds ): string {
		$now   = time();
		$start = $now - ( $now % $window_seconds );
		return gmdate( 'Y-m-d H:i:s', $start );
	}

	/**
	 * Manejar la situación de exceder el rate limit.
	 */
	private function handle_exceeded( string $ip, string $type, int $count, int $limit ): void {
		$minutes = (int) $this->loader->get_setting( 'rate_block_minutes', self::$defaults['rate_block_minutes'] );

		$this->logger->event_immediate( WPS_Event_Types::RATE_LIMITED, array(
			'ip_address' => $ip,
			'details'    => array(
				'type'  => $type,
				'count' => $count,
				'limit' => $limit,
			),
		) );

		$this->blocker->block_offender(
			$ip,
			'auto_rate',
			sprintf( 'Rate limit excedido: %s (%d/%d)', $type, $count, $limit ),
			$minutes
		);

		$this->blocker->send_block_response( 'Demasiadas peticiones. Inténtelo más tarde.' );
	}
}
