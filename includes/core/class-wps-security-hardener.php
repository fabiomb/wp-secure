<?php
defined( 'ABSPATH' ) || exit;

/**
 * Hardening de seguridad.
 *
 * Aplica reglas de seguridad adicionales:
 * - Security headers (X-Frame-Options, X-Content-Type-Options, etc.)
 * - HSTS y Content-Security-Policy (en modo reporte o aplicada)
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
		// Security headers, HSTS y CSP (sólo en el sitio público: send_headers
		// no corre en el panel ni en wp-login.php).
		add_action( 'send_headers', array( $this, 'add_security_headers' ) );

		// Reportes de violaciones de la CSP, antes de los detectores (init 2).
		$csp = new WPS_Csp( $this->loader );
		if ( 'off' !== $csp->mode() ) {
			add_action( 'init', array( $csp, 'maybe_handle_report' ), 1 );
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
		if ( headers_sent() ) {
			return;
		}

		$extra = array();

		if ( $this->loader->get_setting( 'security_headers_enabled', true ) ) {
			$extra += self::default_headers();
		}

		$hsts = self::hsts_value(
			(int) $this->loader->get_setting( 'hsts_max_age', 0 ),
			(bool) $this->loader->get_setting( 'hsts_include_subdomains', false )
		);
		if ( '' !== $hsts && is_ssl() ) {
			$extra['Strict-Transport-Security'] = $hsts;
		}

		$extra += ( new WPS_Csp( $this->loader ) )->headers();

		foreach ( self::headers_to_send( headers_list(), $extra ) as $name => $value ) {
			header( "{$name}: {$value}" );
		}
	}

	/**
	 * Valor de Strict-Transport-Security; '' si está desactivado.
	 *
	 * Sin `preload` a propósito: entrar en la lista de precarga de los
	 * navegadores es difícil de revertir y conviene hacerlo a mano.
	 */
	public static function hsts_value( int $max_age, bool $include_subdomains ): string {
		if ( $max_age <= 0 ) {
			return '';
		}
		return 'max-age=' . $max_age . ( $include_subdomains ? '; includeSubDomains' : '' );
	}

	/**
	 * Headers de seguridad básicos.
	 *
	 * @return array<string, string>
	 */
	public static function default_headers(): array {
		return array(
			'X-Content-Type-Options' => 'nosniff',
			'X-Frame-Options'        => 'SAMEORIGIN',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'Permissions-Policy'     => 'geolocation=(), camera=(), microphone=()',
			'X-XSS-Protection'       => '0',
		);
	}

	/**
	 * Headers de seguridad que faltan en la respuesta.
	 *
	 * No se pisan los que ya definió otro plugin o el tema: un
	 * `X-Frame-Options` duplicado con valores distintos hace que el navegador
	 * lo ignore, y un sitio que permite embeberse en un dominio propio quedaba
	 * roto. `X-XSS-Protection` va en `0`: el filtro que activaba `1` fue
	 * retirado de los navegadores y en los que lo conservan permite ataques de
	 * filtrado selectivo; la recomendación actual es desactivarlo.
	 *
	 * Lo mismo vale para HSTS y la CSP: si el servidor, el hosting o otro
	 * plugin ya envían una, se respeta la suya.
	 *
	 * @param string[]              $already_sent Líneas de headers ya definidas (headers_list()).
	 * @param array<string, string> $headers      Headers a enviar; por defecto, los básicos.
	 * @return array<string, string>
	 */
	public static function headers_to_send( array $already_sent, ?array $headers = null ): array {
		$headers = $headers ?? self::default_headers();

		$present = array();
		foreach ( $already_sent as $line ) {
			$present[ strtolower( trim( strstr( $line, ':', true ) ?: $line ) ) ] = true;
		}

		foreach ( array_keys( $headers ) as $name ) {
			if ( isset( $present[ strtolower( $name ) ] ) ) {
				unset( $headers[ $name ] );
			}
		}

		return $headers;
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

		if ( self::is_exempt( $ip ) ) {
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
	 * ¿La petición queda fuera de las reglas de métodos, User-Agent y Host?
	 *
	 * Como el resto de las verificaciones: la consola (WP-CLI no envía Host
	 * ni User-Agent), el propio servidor (loopbacks, precargadores de caché)
	 * y la whitelist.
	 */
	public static function is_exempt( string $ip ): bool {
		return WPS_Request::is_cli()
			|| WPS_Ip_Utils::is_server_ip( $ip )
			|| WPS_Whitelist::get_instance()->is_whitelisted( $ip );
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
