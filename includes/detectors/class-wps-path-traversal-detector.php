<?php
defined( 'ABSPATH' ) || exit;

/**
 * Detector de ataques de Path Traversal.
 *
 * Detecta intentos de acceso a archivos sensibles y secuencias de
 * recorrido de directorios (../, ..%2f, etc.) en URI y parámetros.
 */
class WPS_Path_Traversal_Detector {

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Logger */
	private $logger;

	/** @var WPS_Blocker */
	private $blocker;

	/**
	 * Patrones de recorrido de directorios.
	 *
	 * @var array
	 */
	private static $traversal_patterns = array(
		// Standard traversal.
		'/(?:\.\.\/){2,}/i',
		'/(?:\.\.\\\\){2,}/i',
		// URL-encoded traversal.
		'/(?:%2e%2e[%2f%5c]){2,}/i',
		'/(?:\.\.%2f){2,}/i',
		'/(?:\.\.%5c){2,}/i',
		// Double-encoded.
		'/(?:%252e%252e%252f){2,}/i',
		// Null byte injection (legacy PHP).
		'/%00/i',
	);

	/**
	 * Archivos del sistema operativo. Son inequívocos en cualquier campo: nadie
	 * escribe "/proc/self/environ" en un comentario por accidente.
	 *
	 * @var array
	 */
	private static $system_files = array(
		'/\/etc\/(?:passwd|shadow|hosts|group)\b/i',
		'/\/proc\/self\/environ\b/i',
	);

	/**
	 * Archivos sensibles del sitio que nunca deben servirse vía web.
	 *
	 * Sólo se buscan en la ruta pedida, no en el query string ni en el cuerpo:
	 * en texto libre son menciones legítimas ("cómo editar el .htaccess",
	 * "mi wp-config.php no carga") y un buscador o un comentario en un blog
	 * técnico bastaba para bloquear al visitante.
	 *
	 * @var array
	 */
	private static $sensitive_files = array(
		'/wp-config\.php/i',
		'/\.htaccess\b/i',
		'/\.htpasswd\b/i',
		'/\.env\b/i',
		'/debug\.log\b/i',
		'/error[_-]?log\b/i',
		'/\/wp-content\/(?:debug|uploads\/wps-data)\b/i',
		'/web\.config\b/i',
		'/\.git(?:\/|ignore|modules)\b/i',
		'/\.svn\b/i',
		'/composer\.(?:json|lock)\b/i',
		'/package\.json\b/i',
		'/phpinfo\.php\b/i',
		'/adminer\.php\b/i',
		'/\.sql(?:\.gz|\.zip)?$/i',
		'/(?:backup|dump|database)[^\/]*\.(?:sql|tar|gz|zip)$/i',
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

		if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
			return;
		}

		// Eximido por regla personalizada.
		if ( WPS_Custom_Rules::is_exempt( 'traversal' ) ) {
			return;
		}

		if ( 'static' === $request->visitor_type() ) {
			return;
		}

		$matched = $this->scan_request( $request );

		if ( $matched ) {
			$this->handle_detection( $ip, $request, $matched );
		}
	}

	/**
	 * Escanear inputs.
	 *
	 * @return string|null Patrón que coincidió.
	 */
	private function scan_request( WPS_Request $request ): ?string {
		$uri          = $request->uri();
		$query_string = $request->query_string();

		// Omitir análisis de URI si es una ruta de contenido WP
		// (tags, categorías, etc.) para evitar falsos positivos.
		if ( ! $request->is_wp_content_path() ) {
			// Traversal sobre la URI completa (cruda y decodificada).
			$match = self::match_traversal( $uri );
			if ( $match ) {
				return $match;
			}

			// Archivos sensibles sólo sobre la ruta pedida.
			$path  = (string) wp_parse_url( $uri, PHP_URL_PATH );
			$match = self::detect_in_path( $path );
			if ( $match ) {
				return $match;
			}
		}

		// Query string: traversal y archivos del sistema (siempre analizar).
		if ( $query_string ) {
			$match = self::detect_in_value( $query_string );
			if ( $match ) {
				return $match;
			}
		}

		// POST parameters.
		if ( 'POST' === $request->method() && ! empty( $_POST ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			foreach ( $_POST as $value ) {
				$match = $this->check_value( $value );
				if ( $match ) {
					return $match;
				}
			}
		}

		return null;
	}

	/**
	 * Analizar la ruta pedida: traversal, archivos del sistema y archivos
	 * sensibles del sitio.
	 *
	 * @param string $path Ruta de la URL, sin query string.
	 * @return string|null Descripción del patrón que coincidió.
	 */
	public static function detect_in_path( string $path ): ?string {
		$match = self::match_traversal( $path );
		if ( $match ) {
			return $match;
		}

		$decoded = rawurldecode( rawurldecode( $path ) );

		foreach ( array_merge( self::$system_files, self::$sensitive_files ) as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return 'sensitive_file:' . $pattern;
			}
		}

		return null;
	}

	/**
	 * Analizar un valor de texto libre (query string o campo de formulario).
	 *
	 * Sólo cuentan el recorrido de directorios y los archivos del sistema; la
	 * mención de un archivo del sitio en un texto no es un ataque.
	 *
	 * @param string $value Valor crudo tal como llegó en la petición.
	 * @return string|null Descripción del patrón que coincidió.
	 */
	public static function detect_in_value( string $value ): ?string {
		$match = self::match_traversal( $value );
		if ( $match ) {
			return $match;
		}

		$decoded = rawurldecode( rawurldecode( $value ) );

		foreach ( self::$system_files as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return 'sensitive_file:' . $pattern;
			}
		}

		return null;
	}

	/**
	 * Buscar secuencias de recorrido de directorios, crudas y decodificadas.
	 */
	private static function match_traversal( string $value ): ?string {
		$decoded = rawurldecode( rawurldecode( $value ) );

		foreach ( self::$traversal_patterns as $pattern ) {
			if ( preg_match( $pattern, $value ) || preg_match( $pattern, $decoded ) ) {
				return 'traversal:' . $pattern;
			}
		}

		return null;
	}

	/**
	 * Comprobar un valor individual (recursivo para arrays).
	 *
	 * @param mixed $value Valor a comprobar.
	 * @return string|null
	 */
	private function check_value( $value ): ?string {
		if ( is_array( $value ) ) {
			foreach ( $value as $v ) {
				$match = $this->check_value( $v );
				if ( $match ) {
					return $match;
				}
			}
			return null;
		}

		if ( ! is_string( $value ) || strlen( $value ) < 3 ) {
			return null;
		}

		return self::detect_in_value( $value );
	}

	/**
	 * Manejar detección.
	 */
	private function handle_detection( string $ip, WPS_Request $request, string $match_info ): void {
		$block_mode = $this->loader->get_setting( 'critical_block_mode', 'temporary' );
		$minutes    = 'permanent' === $block_mode
			? null
			: (int) $this->loader->get_setting( 'rate_block_minutes', 15 );

		$this->logger->event_immediate( WPS_Event_Types::TRAVERSAL_DETECTED, array(
			'ip_address'  => $ip,
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array(
				'match'  => $match_info,
				'method' => $request->method(),
			),
		) );

		$this->blocker->block_ip(
			$ip,
			'auto_traversal',
			'Path traversal detectado',
			$minutes
		);

		$this->blocker->send_block_response( 'Acceso denegado' );
	}
}
