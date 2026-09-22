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
		'/\bUNION\s+(?:ALL\s+)?SELECT\b/i',
		// Boolean-based blind. Se exige un delimitador de cierre antes de la
		// tautología: "1' OR 1=1" es inyección, "llevás 1 y 1 = 2" es prosa.
		// "' OR '" suelto no se usa: coincide con "'sí' or 'no'". La forma
		// real "' OR '1'='1" ya la cubre este patrón.
		'/[\'")]\s*(?:OR|AND)\s+[\d\'"]+\s*=\s*[\d\'"]+/i',
		// Stacked queries. Las sentencias destructivas sólo cuentan cuando
		// aparecen después de cerrar el valor original; un texto que menciona
		// "DELETE FROM" o "drop table" no es un ataque.
		'/[\'");]\s*;\s*(?:DROP|ALTER|TRUNCATE|INSERT|UPDATE|DELETE|SELECT)\b/i',
		// Time-based blind.
		'/\b(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep)\s*\(/i',
		// File operations.
		'/\bLOAD_FILE\s*\(/i',
		'/\bINTO\s+(?:OUT|DUMP)FILE\b/i',
		// Metadata. Se exige la referencia a la tabla, no la palabra suelta.
		'/\bINFORMATION_SCHEMA\s*\./i',
		'/\bSYS(?:OBJECTS|COLUMNS|TABLES)\b/i',
		// Comentarios SQL usados para partir palabras clave (/**/UNION,
		// /*!SELECT*/). El guion doble no cuenta: en prosa es un separador
		// habitual ("I tried it -- and it worked"), y el comentario final de
		// una inyección real ya lo cubren las tautologías y stacked queries.
		'/(?:\/\*!|\/\*\*\/)\s*(?:UNION|SELECT|DROP|INSERT|UPDATE|DELETE|OR|AND)\b/i',
		// Hex-encoded injection – must appear in a SQL context to avoid false
		// positives on legitimate hex values (e.g. WooCommerce cart hashes,
		// session tokens). Matches only when a SQL keyword or operator
		// immediately precedes or follows the hex literal.
		'/(?:\b(?:SELECT|UNION|CHAR|CONVERT|FROM|WHERE)\b|=)\s*0x[0-9a-f]{8,}/i',
		'/0x[0-9a-f]{8,}\s*(?:--|;\s*\b(?:SELECT|DROP|INSERT|UPDATE|DELETE)\b|\b(?:UNION|SELECT|FROM)\b)/i',
		// Funciones que sólo aparecen al explotar una inyección. CHAR, CONCAT y
		// GROUP_CONCAT quedan fuera a propósito: son demasiado comunes en texto
		// normal y en código que los usuarios pegan en formularios.
		'/\b(?:EXTRACTVALUE|UPDATEXML)\s*\(/i',
	);

	/**
	 * Patrones cortos de alto riesgo que requieren contexto adicional.
	 *
	 * @var array
	 */
	private static $strict_patterns = array(
		// Tautologies with quotes.
		'/[\'"]\s*(?:OR|AND)\s*[\'"]\s*[\'"]\s*=/i',
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
		// No analizar a quien edita el sitio: su propio contenido dispara los
		// mismos patrones que un ataque.
		if ( WPS_Request::is_trusted_user() ) {
			return;
		}

		$request = WPS_Request::get_instance();
		$ip      = $request->ip();

		// Whitelist.
		if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
			return;
		}

		// Eximido por regla personalizada.
		if ( WPS_Custom_Rules::is_exempt( 'sqli' ) ) {
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

			$pattern = self::detect( $input );
			if ( $pattern ) {
				return $pattern;
			}
		}

		return null;
	}

	/**
	 * Analizar un valor suelto en busca de inyección SQL.
	 *
	 * @param string $value Valor crudo tal como llegó en la petición.
	 * @return string|null Patrón que coincidió, o null si el valor es inocuo.
	 */
	public static function detect( string $value ): ?string {
		return self::match_patterns( self::decode_input( $value ) );
	}

	/**
	 * Recopilar todos los inputs a analizar.
	 */
	private function collect_inputs( WPS_Request $request ): array {
		$inputs = array();

		// URI y query string: omitir URI si es una ruta de contenido WP
		// (tags, categorías, etc.) para evitar falsos positivos con slugs.
		if ( ! $request->is_wp_content_path() ) {
			$inputs[] = $request->uri();
		}

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
	private static function decode_input( string $input ): string {
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
	private static function match_patterns( string $input ): ?string {
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
		$block_mode = $this->loader->get_setting( 'critical_block_mode', 'temporary' );
		$minutes    = 'permanent' === $block_mode
			? null
			: (int) $this->loader->get_setting( 'rate_block_minutes', 15 );

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
