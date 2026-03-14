<?php
defined( 'ABSPATH' ) || exit;

/**
 * Hardening de seguridad.
 *
 * Aplica reglas de seguridad adicionales:
 * - Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
 * - Bloqueo de métodos HTTP no estándar
 * - Bloqueo de peticiones sin User-Agent
 * - Bloqueo de peticiones sin header Host
 * - Ocultamiento de versión de WordPress
 */
class WPS_Security_Hardener {

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Logger */
	private $logger;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
		$this->logger = WPS_Logger::get_instance();
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		// Security headers (prioridad alta para que se envíen antes).
		if ( $this->loader->get_setting( 'security_headers_enabled', true ) ) {
			add_action( 'send_headers', array( $this, 'add_security_headers' ) );
		}

		// Ocultar versión de WordPress.
		if ( $this->loader->get_setting( 'hide_wp_version', true ) ) {
			$this->hide_wp_version();
		}

		// Bloqueo de métodos HTTP, UA vacío y Host ausente (muy temprano).
		add_action( 'init', array( $this, 'check_request_rules' ), 1 );
	}

	/**
	 * Enviar security headers en cada respuesta.
	 */
	public function add_security_headers(): void {
		// No sobrescribir si ya están definidos por el servidor/otro plugin.
		$headers = array(
			'X-Content-Type-Options'  => 'nosniff',
			'X-Frame-Options'         => 'SAMEORIGIN',
			'Referrer-Policy'         => 'strict-origin-when-cross-origin',
			'Permissions-Policy'      => 'geolocation=(), camera=(), microphone=()',
			'X-XSS-Protection'       => '1; mode=block',
		);

		foreach ( $headers as $name => $value ) {
			if ( ! headers_sent() ) {
				header( "{$name}: {$value}" );
			}
		}
	}

	/**
	 * Verificar reglas de seguridad de la petición.
	 */
	public function check_request_rules(): void {
		// Skip para admin logueado y cron.
		if ( ( is_admin() && current_user_can( 'manage_options' ) ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$request = WPS_Request::get_instance();
		$ip      = $request->ip();

		if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
			return;
		}

		// R13: Bloquear métodos HTTP no estándar.
		if ( $this->loader->get_setting( 'block_bad_methods', true ) ) {
			$this->check_http_method( $request );
		}

		// R11: Bloquear UA vacío.
		if ( $this->loader->get_setting( 'block_empty_ua', false ) ) {
			$this->check_empty_ua( $request );
		}

		// R12: Bloquear sin header Host.
		if ( $this->loader->get_setting( 'block_no_host', true ) ) {
			$this->check_missing_host( $request );
		}
	}

	/**
	 * Bloquear métodos HTTP peligrosos.
	 *
	 * TRACE, TRACK, DEBUG, CONNECT → siempre bloqueados.
	 * DELETE, PUT, PATCH → solo permitidos en contexto REST API / AJAX.
	 */
	private function check_http_method( WPS_Request $request ): void {
		$method = $request->method();

		// Métodos siempre prohibidos.
		$always_blocked = array( 'TRACE', 'TRACK', 'DEBUG', 'CONNECT' );
		if ( in_array( $method, $always_blocked, true ) ) {
			$this->block_request( $request, WPS_Event_Types::HTTP_METHOD_BLOCKED, $method );
		}

		// Métodos condicionalmente permitidos (solo REST API / AJAX).
		$conditional = array( 'DELETE', 'PUT', 'PATCH' );
		if ( in_array( $method, $conditional, true ) ) {
			$visitor_type = $request->visitor_type();
			if ( ! in_array( $visitor_type, array( 'restapi', 'ajax' ), true ) ) {
				$this->block_request( $request, WPS_Event_Types::HTTP_METHOD_BLOCKED, $method );
			}
		}
	}

	/**
	 * Bloquear peticiones sin User-Agent.
	 */
	private function check_empty_ua( WPS_Request $request ): void {
		if ( '' === $request->user_agent() ) {
			$this->block_request( $request, WPS_Event_Types::EMPTY_UA_BLOCKED, '' );
		}
	}

	/**
	 * Bloquear peticiones sin header Host.
	 */
	private function check_missing_host( WPS_Request $request ): void {
		if ( '' === $request->host() ) {
			$this->block_request( $request, WPS_Event_Types::MISSING_HOST_BLOCKED, '' );
		}
	}

	/**
	 * Ocultar la versión de WordPress.
	 */
	private function hide_wp_version(): void {
		// Quitar meta tag <meta name="generator" content="WordPress X.Y.Z" />.
		remove_action( 'wp_head', 'wp_generator' );

		// Quitar de feeds RSS.
		add_filter( 'the_generator', '__return_empty_string' );

		// Quitar ?ver= de scripts y estilos.
		add_filter( 'style_loader_src', array( $this, 'remove_version_query' ), 15 );
		add_filter( 'script_loader_src', array( $this, 'remove_version_query' ), 15 );
	}

	/**
	 * Eliminar parámetro ?ver= de URLs de scripts/estilos.
	 */
	public function remove_version_query( string $src ): string {
		if ( strpos( $src, 'ver=' ) !== false ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}

	/**
	 * Bloquear petición con logging y respuesta 403.
	 */
	private function block_request( WPS_Request $request, string $event_type, string $value ): void {
		$this->logger->event_immediate( $event_type, array(
			'ip_address'  => $request->ip(),
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array(
				'method' => $request->method(),
				'value'  => $value,
			),
		) );

		$blocker = WPS_Blocker::get_instance();
		$blocker->send_block_response( __( 'Acceso denegado.', 'wp-secure' ) );
	}
}
