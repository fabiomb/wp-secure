<?php
defined( 'ABSPATH' ) || exit;

/**
 * Reporte guiado del modo sombra del motor de riesgo.
 *
 * El modo sombra registra, para cada petición con puntaje suficiente, el
 * puntaje, los factores que lo sumaron y la acción que habría tomado. Este
 * reporte los agrega para responder las preguntas que hacen falta antes de
 * pasar a modo activo:
 *
 * - ¿A cuántos clientes habría bloqueado y con qué factores?
 * - ¿Cuántos de ellos ya bloqueó otra regla (atacantes confirmados) y
 *   cuántos serían bloqueos nuevos, que hay que revisar?
 * - ¿Qué pasaría con otro umbral? Se simula sobre los puntajes registrados.
 */
class WPS_Risk_Report {

	/** Umbrales que se simulan. */
	const CANDIDATES = array( 51, 61, 71, 81, 91, 101, 121, 151, 201 );

	/** Eventos que se analizan como máximo (los más recientes). */
	const MAX_EVENTS = 5000;

	/** Clientes nuevos que se listan. */
	const MAX_LISTED = 25;

	/** Días de datos antes de sugerir un umbral con confianza. */
	const MIN_DAYS = 3;

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Armar el reporte de los últimos días.
	 */
	public function build( int $days ): array {
		$engine = WPS_Rules_Engine::get_instance( $this->loader );
		$events = $this->events( $days );

		$report = self::aggregate( $events, $this->confirmed_targets( $days ), $engine->get_thresholds()['temp_block'] );

		$report['days']       = $days;
		$report['counts']     = $this->counts( $days );
		$report['requests']   = $this->requests( $days );
		$report['truncated']  = count( $events ) >= self::MAX_EVENTS;
		$report['mode']       = $engine->mode();
		$report['thresholds'] = $engine->get_thresholds();
		$report['weights']    = $engine->get_score_table();

		return $report;
	}

	/**
	 * Agregar los eventos del motor.
	 *
	 * @param array[]  $events    Filas con ip_address, details (JSON) y created_at.
	 * @param string[] $confirmed IPs y redes bloqueadas por otras reglas.
	 * @param int      $threshold Umbral de bloqueo actual.
	 */
	public static function aggregate( array $events, array $confirmed, int $threshold ): array {
		$clients = array();
		$totals  = array();
		$first   = null;

		foreach ( $events as $event ) {
			$details = json_decode( (string) ( $event['details'] ?? '' ), true );
			$ip      = (string) ( $event['ip_address'] ?? '' );
			if ( ! is_array( $details ) || '' === $ip || ! isset( $details['score'] ) ) {
				continue;
			}

			$score   = (int) $details['score'];
			$factors = self::factor_names( (string) ( $details['factors'] ?? '' ) );

			if ( ! isset( $clients[ $ip ] ) ) {
				$clients[ $ip ] = array(
					'ip'        => $ip,
					'max_score' => 0,
					'events'    => 0,
					'factors'   => array(),
					'confirmed' => self::is_confirmed( $ip, $confirmed ),
					'last'      => '',
				);
			}

			$client                = &$clients[ $ip ];
			$client['max_score']   = max( $client['max_score'], $score );
			$client['events']++;
			$client['last']        = max( $client['last'], (string) ( $event['created_at'] ?? '' ) );
			foreach ( $factors as $factor ) {
				$client['factors'][ $factor ] = ( $client['factors'][ $factor ] ?? 0 ) + 1;

				if ( ! isset( $totals[ $factor ] ) ) {
					$totals[ $factor ] = array( 'factor' => $factor, 'events' => 0, 'clients' => array() );
				}
				$totals[ $factor ]['events']++;
				$totals[ $factor ]['clients'][ $ip ] = true;
			}
			unset( $client );

			$created = (string) ( $event['created_at'] ?? '' );
			if ( '' !== $created && ( null === $first || $created < $first ) ) {
				$first = $created;
			}
		}

		// Simulación de umbrales: clientes cuyo peor puntaje lo alcanza.
		$candidates = self::CANDIDATES;
		if ( ! in_array( $threshold, $candidates, true ) ) {
			$candidates[] = $threshold;
			sort( $candidates );
		}

		$simulation = array();
		foreach ( $candidates as $candidate ) {
			$blocked   = array_filter( $clients, function ( $c ) use ( $candidate ) {
				return $c['max_score'] >= $candidate;
			} );
			$confirmed_count = count( array_filter( $blocked, function ( $c ) {
				return $c['confirmed'];
			} ) );

			$simulation[] = array(
				'threshold' => $candidate,
				'clients'   => count( $blocked ),
				'confirmed' => $confirmed_count,
				'new'       => count( $blocked ) - $confirmed_count,
				'current'   => $candidate === $threshold,
			);
		}

		// Factores de los clientes que se bloquearían con el umbral actual,
		// separados según si otra regla ya los bloqueó.
		$would_block = array_filter( $clients, function ( $c ) use ( $threshold ) {
			return $c['max_score'] >= $threshold;
		} );

		$factors = array();
		foreach ( $would_block as $client ) {
			foreach ( array_map( 'strval', array_keys( $client['factors'] ) ) as $factor ) {
				if ( ! isset( $factors[ $factor ] ) ) {
					$factors[ $factor ] = array( 'factor' => $factor, 'clients' => 0, 'new_clients' => 0 );
				}
				$factors[ $factor ]['clients']++;
				if ( ! $client['confirmed'] ) {
					$factors[ $factor ]['new_clients']++;
				}
			}
		}
		uasort( $factors, function ( $a, $b ) {
			return array( $b['new_clients'], $b['clients'] ) <=> array( $a['new_clients'], $a['clients'] );
		} );

		$new_clients = array_values( array_filter( $would_block, function ( $c ) {
			return ! $c['confirmed'];
		} ) );
		usort( $new_clients, function ( $a, $b ) {
			return $b['max_score'] <=> $a['max_score'];
		} );

		return array(
			'clients'      => count( $clients ),
			'would_block'  => count( $would_block ),
			'simulation'   => $simulation,
			'factors'      => array_values( $factors ),
			'new_clients'  => array_slice( $new_clients, 0, self::MAX_LISTED ),
			'suggested'    => self::suggest( $simulation ),
			'first_event'  => $first,
			'measured'     => self::factor_totals( $totals ),
		);
	}

	/**
	 * Qué está midiendo el motor: cada factor con sus eventos y clientes,
	 * de todas las peticiones registradas (también las de riesgo bajo).
	 *
	 * @param array<string, array> $totals Factor => events, clients (set).
	 * @return array[] factor, events, clients; más frecuentes primero.
	 */
	private static function factor_totals( array $totals ): array {
		$rows = array();
		foreach ( $totals as $total ) {
			$rows[] = array(
				'factor'  => (string) $total['factor'],
				'events'  => $total['events'],
				'clients' => count( $total['clients'] ),
			);
		}
		usort( $rows, function ( $a, $b ) {
			return $b['events'] <=> $a['events'];
		} );
		return $rows;
	}

	/**
	 * Umbral sugerido: el más bajo con el que el motor sólo habría bloqueado
	 * clientes que otra regla ya bloqueó. Null si no hay datos para decidir.
	 */
	public static function suggest( array $simulation ): ?int {
		foreach ( $simulation as $row ) {
			if ( $row['clients'] > 0 && 0 === $row['new'] ) {
				return (int) $row['threshold'];
			}
		}
		return null;
	}

	/**
	 * `login_fail:3, 404:4, risky_country:CN` → login_fail, 404, risky_country.
	 *
	 * @return string[]
	 */
	public static function factor_names( string $factors ): array {
		$names = array();
		foreach ( explode( ',', $factors ) as $factor ) {
			$name = trim( (string) strtok( trim( $factor ), ':' ) );
			if ( '' !== $name ) {
				$names[ $name ] = true;
			}
		}
		// Una clave numérica («404») vuelve como entero.
		return array_map( 'strval', array_keys( $names ) );
	}

	private static function is_confirmed( string $ip, array $confirmed ): bool {
		foreach ( $confirmed as $target ) {
			if ( $target === $ip || ( false !== strpos( $target, '/' ) && WPS_Ip_Utils::ip_in_cidr( $ip, $target ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Etiqueta de un factor.
	 */
	public static function factor_label( string $factor ): string {
		$labels = array(
			'empty_ua'          => __( 'User-Agent vacío', 'wp-secure' ),
			'tool_ua'           => __( 'User-Agent de herramienta (curl, python…)', 'wp-secure' ),
			'suspicious_path'   => __( 'Ruta sospechosa', 'wp-secure' ),
			'xmlrpc_access'     => __( 'Acceso a xmlrpc.php', 'wp-secure' ),
			'sqli_pattern'      => __( 'Patrón de SQLi', 'wp-secure' ),
			'xss_pattern'       => __( 'Patrón de XSS', 'wp-secure' ),
			'traversal_pattern' => __( 'Path traversal', 'wp-secure' ),
			'login_fail'        => __( 'Logins fallidos', 'wp-secure' ),
			'404'               => __( 'Errores 404', 'wp-secure' ),
			'risky_country'     => __( 'País de alto riesgo', 'wp-secure' ),
			'high_rate'         => __( 'Tasa de peticiones alta', 'wp-secure' ),
			'nonexistent_user'  => __( 'Usuario inexistente', 'wp-secure' ),
		);
		return $labels[ $factor ] ?? $factor;
	}

	/*──────────────────────────────────────────────
	 * Datos
	 *──────────────────────────────────────────────*/

	/**
	 * Eventos del motor (desde 31 puntos). Los de riesgo bajo no cambian
	 * ninguna simulación de bloqueo, pero muestran qué está midiendo.
	 */
	protected function events( int $days ): array {
		$table = WPS_Db_Schema::table( 'security_events' );

		return WPS_Db::get_instance()->get_results(
			"SELECT ip_address, details, created_at FROM {$table}
			 WHERE event_type IN (%s, %s, %s) AND created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)
			 ORDER BY id DESC LIMIT %d",
			WPS_Event_Types::RISK_LOW,
			WPS_Event_Types::RISK_MEDIUM,
			WPS_Event_Types::RISK_HIGH,
			$days,
			self::MAX_EVENTS
		);
	}

	/**
	 * Peticiones del período según el log de tráfico (con su peso de
	 * muestreo), o null si el log está desactivado. Es la referencia para
	 * saber si el motor midió: sin eventos y con miles de peticiones, ninguna
	 * llegó a 31 puntos.
	 */
	protected function requests( int $days ): ?int {
		if ( WPS_Traffic_Sampler::MODE_OFF === WPS_Traffic_Sampler::mode( $this->loader ) ) {
			return null;
		}

		$table = WPS_Db_Schema::table( 'traffic_log' );
		return (int) WPS_Db::get_instance()->get_var(
			"SELECT COALESCE(SUM(sample_weight), 0) FROM {$table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
			$days
		);
	}

	/**
	 * @return array<string, int> Tipo de evento de riesgo => cantidad.
	 */
	protected function counts( int $days ): array {
		$table = WPS_Db_Schema::table( 'security_events' );
		$rows  = WPS_Db::get_instance()->get_results(
			"SELECT event_type, COUNT(*) AS total FROM {$table}
			 WHERE event_type IN (%s, %s, %s) AND created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)
			 GROUP BY event_type",
			WPS_Event_Types::RISK_LOW,
			WPS_Event_Types::RISK_MEDIUM,
			WPS_Event_Types::RISK_HIGH,
			$days
		);

		$counts = array( WPS_Event_Types::RISK_LOW => 0, WPS_Event_Types::RISK_MEDIUM => 0, WPS_Event_Types::RISK_HIGH => 0 );
		foreach ( $rows as $row ) {
			$counts[ $row['event_type'] ] = (int) $row['total'];
		}
		return $counts;
	}

	/**
	 * IPs y redes que otras reglas (detectores, rutas trampa, bloqueos
	 * manuales) bloquearon en el período: atacantes confirmados.
	 *
	 * @return string[]
	 */
	protected function confirmed_targets( int $days ): array {
		$table = WPS_Db_Schema::table( 'blocked_ips' );
		$rows  = WPS_Db::get_instance()->get_results(
			"SELECT ip_address, cidr FROM {$table}
			 WHERE block_type <> 'auto_risk' AND blocked_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)
			 LIMIT 20000",
			$days + 1
		);

		$targets = array();
		foreach ( $rows as $row ) {
			$targets[] = ! empty( $row['ip_address'] ) ? (string) $row['ip_address'] : (string) ( $row['cidr'] ?? '' );
		}
		return array_values( array_unique( array_filter( $targets ) ) );
	}
}
