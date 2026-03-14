<?php
defined( 'ABSPATH' ) || exit;

/**
 * Detector de abuso de REST API.
 *
 * Bloquea enumeración de usuarios y acceso no autenticado a la REST API
 * según la configuración del plugin.
 */
class WPS_Restapi_Detector {

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
		// Bloquear REST API completa para no autenticados.
		add_filter( 'rest_authentication_errors', array( $this, 'maybe_block_public_rest' ), 99 );

		// Bloquear enumeración de usuarios.
		add_filter( 'rest_pre_dispatch', array( $this, 'block_user_enumeration' ), 10, 3 );

		// Bloquear ?author=N y feed de autores.
		add_action( 'template_redirect', array( $this, 'block_author_enumeration' ) );
	}

	/**
	 * Bloquear REST API para usuarios no autenticados (si activado).
	 *
	 * @param \WP_Error|null|true $errors
	 * @return \WP_Error|null|true
	 */
	public function maybe_block_public_rest( $errors ) {
		// Si ya hay un error, no interferir.
		if ( is_wp_error( $errors ) ) {
			return $errors;
		}

		if ( ! $this->loader->get_setting( 'rest_disable_public', false ) ) {
			return $errors;
		}

		// Usuarios autenticados → permitir.
		if ( is_user_logged_in() ) {
			return $errors;
		}

		// Verificar whitelist de IP.
		$request = WPS_Request::get_instance();
		if ( WPS_Whitelist::get_instance()->is_whitelisted( $request->ip() ) ) {
			return $errors;
		}

		// Verificar namespaces permitidos.
		$rest_route = $this->get_current_rest_route();
		if ( $this->is_namespace_allowed( $rest_route ) ) {
			return $errors;
		}

		$this->log_block( $request, 'rest_disabled_public', $rest_route );

		return new \WP_Error(
			'rest_disabled',
			__( 'La REST API está desactivada para visitantes no autenticados.', 'wp-secure' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Bloquear enumeración de usuarios via REST API.
	 *
	 * @param mixed            $result
	 * @param \WP_REST_Server  $server
	 * @param \WP_REST_Request $wp_request
	 * @return mixed|\WP_Error
	 */
	public function block_user_enumeration( $result, $server, $wp_request ) {
		if ( ! $this->loader->get_setting( 'rest_block_user_enum', true ) ) {
			return $result;
		}

		if ( is_user_logged_in() ) {
			return $result;
		}

		$route = $wp_request->get_route();

		// /wp/v2/users o /wp/v2/users/{id}.
		if ( preg_match( '#^/wp/v2/users(?:/\d+)?$#', $route ) ) {
			$request = WPS_Request::get_instance();
			$this->log_block( $request, 'user_enumeration', $route );

			return new \WP_Error(
				'rest_user_enum_blocked',
				__( 'La enumeración de usuarios está bloqueada.', 'wp-secure' ),
				array( 'status' => 403 )
			);
		}

		return $result;
	}

	/**
	 * Bloquear enumeración de autores via ?author=N.
	 */
	public function block_author_enumeration(): void {
		if ( ! $this->loader->get_setting( 'rest_block_user_enum', true ) ) {
			return;
		}

		if ( is_user_logged_in() ) {
			return;
		}

		if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
			$request = WPS_Request::get_instance();
			$this->log_block( $request, 'author_enumeration', $request->uri() );
			wp_die(
				esc_html__( 'Acceso denegado.', 'wp-secure' ),
				403,
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Verificar si un namespace REST está permitido.
	 */
	private function is_namespace_allowed( string $route ): bool {
		// oembed siempre permitido (necesario para embeds de WP).
		$always_allowed = array( 'oembed/1.0' );

		foreach ( $always_allowed as $ns ) {
			if ( 0 === strpos( $route, '/' . $ns ) ) {
				return true;
			}
		}

		// Namespaces configurados por el usuario.
		$allowed_raw = $this->loader->get_setting( 'rest_allowed_namespaces', '' );
		if ( empty( $allowed_raw ) ) {
			return false;
		}

		$allowed = array_filter( array_map( 'trim', explode( "\n", $allowed_raw ) ) );
		foreach ( $allowed as $ns ) {
			if ( 0 === strpos( $route, '/' . $ns ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Obtener la ruta REST actual.
	 */
	private function get_current_rest_route(): string {
		if ( ! empty( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
			return $GLOBALS['wp']->query_vars['rest_route'];
		}

		// Fallback: extraer de REQUEST_URI.
		$rest_prefix = rest_get_url_prefix();
		$request_uri = WPS_Request::get_instance()->uri();

		if ( false !== strpos( $request_uri, '/' . $rest_prefix . '/' ) ) {
			$route = substr( $request_uri, strpos( $request_uri, '/' . $rest_prefix . '/' ) + strlen( $rest_prefix ) + 1 );
			$route = strtok( $route, '?' );
			return '/' . ltrim( $route, '/' );
		}

		return '';
	}

	/**
	 * Registrar evento de bloqueo REST API.
	 */
	private function log_block( WPS_Request $request, string $reason, string $route ): void {
		$this->logger->event_immediate( WPS_Event_Types::RESTAPI_BLOCKED, array(
			'ip_address'  => $request->ip(),
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array(
				'reason' => $reason,
				'route'  => $route,
			),
		) );
	}
}
