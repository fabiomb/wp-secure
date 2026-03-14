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
	 * Archivos sensibles que nunca deben ser accedidos vía web.
	 *
	 * @var array
	 */
	private static $sensitive_files = array(
		'/\/etc\/(?:passwd|shadow|hosts|group)\b/i',
		'/\/proc\/self\/environ\b/i',
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
		'/\.sql(?:\.gz|\.zip)?\b/i',
		'/(?:backup|dump|database).*\.(?:sql|tar|gz|zip)\b/i',
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
		if ( is_admin() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$request = WPS_Request::get_instance();
		$ip      = $request->ip();

		if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
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
		$decoded_uri  = rawurldecode( rawurldecode( $uri ) );
		$decoded_qs   = rawurldecode( rawurldecode( $query_string ) );

		// Traversal en URI.
		foreach ( self::$traversal_patterns as $pattern ) {
			if ( preg_match( $pattern, $uri ) || preg_match( $pattern, $decoded_uri ) ) {
				return 'traversal:' . $pattern;
			}
			if ( $query_string && ( preg_match( $pattern, $query_string ) || preg_match( $pattern, $decoded_qs ) ) ) {
				return 'traversal:' . $pattern;
			}
		}

		// Archivos sensibles en URI.
		foreach ( self::$sensitive_files as $pattern ) {
			if ( preg_match( $pattern, $decoded_uri ) ) {
				return 'sensitive_file:' . $pattern;
			}
			if ( $decoded_qs && preg_match( $pattern, $decoded_qs ) ) {
				return 'sensitive_file:' . $pattern;
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

		$decoded = rawurldecode( rawurldecode( $value ) );

		foreach ( self::$traversal_patterns as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return 'traversal:' . $pattern;
			}
		}

		foreach ( self::$sensitive_files as $pattern ) {
			if ( preg_match( $pattern, $decoded ) ) {
				return 'sensitive_file:' . $pattern;
			}
		}

		return null;
	}

	/**
	 * Manejar detección.
	 */
	private function handle_detection( string $ip, WPS_Request $request, string $match_info ): void {
		$minutes = (int) $this->loader->get_setting( 'rate_block_minutes', 15 );

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
