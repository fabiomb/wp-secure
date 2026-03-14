<?php
defined( 'ABSPATH' ) || exit;

/**
 * Detector de inyecciones SQL.
 *
 * Analiza QUERY_STRING, POST body, URI y cookies buscando patrones
 * de inyección SQL. Excluye administradores autenticados en wp-admin
 * para minimizar falsos positivos.
 */
class WPS_Sqli_Detector {

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Logger */
	private $logger;

	/** @var WPS_Blocker */
	private $blocker;

	/**
	 * Patrones regex de inyección SQL.
	 * Cada patrón se evalúa con modificador case-insensitive.
	 *
	 * @var array
	 */
	private static $patterns = array(
		// UNION-based injection.
		'/\bUNION\s+(ALL\s+)?SELECT\b/i',
		// Boolean-based blind.
		'/\b(?:OR|AND)\s+[\d\'"]+=[\d\'"]+/i',
		'/\'\s*OR\s+\'/i',
		// Stacked queries / destructive.
		'/\b(?:DROP|ALTER|TRUNCATE)\s+(?:TABLE|DATABASE|INDEX)\b/i',
		'/\bINSERT\s+INTO\b/i',
		'/\bUPDATE\s+\S+\s+SET\b/i',
		'/\bDELETE\s+FROM\b/i',
		// Time-based blind.
		'/\b(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep)\s*\(/i',
		// File operations.
		'/\bLOAD_FILE\s*\(/i',
		'/\bINTO\s+(?:OUT|DUMP)FILE\b/i',
		// Information schema / metadata.
		'/\bINFORMATION_SCHEMA\b/i',
		'/\bSYS(?:OBJECTS|COLUMNS|TABLES)\b/i',
		// SQL comments used for injection (standalone, not inside words).
		'/(?:--|\/\*!|\/\*\*\/)\s*(?:UNION|SELECT|DROP|INSERT|UPDATE|DELETE|OR|AND)\b/i',
		// Hex-encoded injection.
		'/0x[0-9a-f]{8,}/i',
		// Common function abuse.
		'/\b(?:CHAR|CHR|CONCAT|GROUP_CONCAT|EXTRACTVALUE|UPDATEXML)\s*\(/i',
	);

	/**
	 * Patrones cortos de alto riesgo que requieren contexto adicional.
	 *
	 * @var array
	 */
	private static $strict_patterns = array(
		// Tautologies with quotes.
		'/[\'"]\s*(?:OR|AND)\s*[\'"]\s*[\'"]\s*=/i',
		// Closing quote + SQL keyword.
		'/[\'"]\s*;\s*(?:DROP|SELECT|INSERT|UPDATE|DELETE|UNION)\b/i',
	);

	public function __construct( WPS_Loader $loader ) {
		$this->loader  = $loader;
		$this->logger  = WPS_Logger::get_instance();
		$this->blocker = WPS_Blocker::get_instance();
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		add_action( 'init', array( $this, 'check_request' ), 2 );
	}

	/**
	 * Analizar la petición actual.
	 */
	public function check_request(): void {
		// No analizar admin autenticados en wp-admin (falsos positivos).
		if ( is_admin() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$request = WPS_Request::get_instance();
		$ip      = $request->ip();

		// Whitelist.
		if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
			return;
		}

		// Recursos estáticos no se analizan.
		if ( 'static' === $request->visitor_type() ) {
			return;
		}

		$matched = $this->scan_request( $request );

		if ( $matched ) {
			$this->handle_detection( $ip, $request, $matched );
		}
	}

	/**
	 * Escanear todos los inputs de la petición.
	 *
	 * @return string|null Patrón que coincidió, o null.
	 */
	private function scan_request( WPS_Request $request ): ?string {
		$inputs = $this->collect_inputs( $request );

		foreach ( $inputs as $input ) {
			if ( empty( $input ) ) {
				continue;
			}

			// Decodificar para detectar evasión por encoding.
			$decoded = $this->decode_input( $input );

			$pattern = $this->match_patterns( $decoded );
			if ( $pattern ) {
				return $pattern;
			}
		}

		return null;
	}

	/**
	 * Recopilar todos los inputs a analizar.
	 */
	private function collect_inputs( WPS_Request $request ): array {
		$inputs = array();

		// URI.
		$inputs[] = $request->uri();

		// Query string.
		$inputs[] = $request->query_string();

		// POST parameters (solo valores, no claves).
		if ( 'POST' === $request->method() && ! empty( $_POST ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			foreach ( $_POST as $value ) {
				if ( is_string( $value ) ) {
					$inputs[] = $value;
				} elseif ( is_array( $value ) ) {
					array_walk_recursive( $value, function ( $v ) use ( &$inputs ) {
						if ( is_string( $v ) ) {
							$inputs[] = $v;
						}
					} );
				}
			}
		}

		// Cookies (solo valores).
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		foreach ( $_COOKIE as $name => $value ) {
			// Skip WordPress session cookies.
			if ( 0 === strpos( $name, 'wordpress_' ) || 0 === strpos( $name, 'wp-settings-' ) ) {
				continue;
			}
			if ( is_string( $value ) ) {
				$inputs[] = $value;
			}
		}

		return $inputs;
	}

	/**
	 * Decodificar input para detectar evasión por encoding.
	 */
	private function decode_input( string $input ): string {
		// URL decode (double decode).
		$decoded = rawurldecode( rawurldecode( $input ) );

		// Remove null bytes.
		$decoded = str_replace( "\0", '', $decoded );

		// Normalize whitespace.
		$decoded = preg_replace( '/\s+/', ' ', $decoded );

		return $decoded;
	}

	/**
	 * Evaluar todos los patrones contra un input.
	 *
	 * @return string|null El patrón que coincidió.
	 */
	private function match_patterns( string $input ): ?string {
		// Skip inputs too short to be an injection.
		if ( strlen( $input ) < 5 ) {
			return null;
		}

		foreach ( self::$patterns as $pattern ) {
			if ( preg_match( $pattern, $input ) ) {
				return $pattern;
			}
		}

		foreach ( self::$strict_patterns as $pattern ) {
			if ( preg_match( $pattern, $input ) ) {
				return $pattern;
			}
		}

		return null;
	}

	/**
	 * Manejar una detección de SQLi.
	 */
	private function handle_detection( string $ip, WPS_Request $request, string $pattern ): void {
		$minutes = (int) $this->loader->get_setting( 'rate_block_minutes', 15 );

		$this->logger->event_immediate( WPS_Event_Types::SQLI_DETECTED, array(
			'ip_address'  => $ip,
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array(
				'pattern' => $pattern,
				'method'  => $request->method(),
			),
		) );

		$this->blocker->block_ip(
			$ip,
			'auto_sqli',
			'Patrón de inyección SQL detectado',
			$minutes
		);

		$this->blocker->send_block_response( 'SQL injection detectada' );
	}
}
