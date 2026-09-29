<?php
defined( 'ABSPATH' ) || exit;

/**
 * Límite de búsquedas por cliente.
 *
 * Cada búsqueda del sitio es una consulta cara a la base de datos (LIKE sobre
 * títulos y contenido) que ninguna cache de páginas absorbe, porque cada
 * término es distinto. Es un vector barato de denegación de servicio.
 *
 * El control corre antes de que WordPress ejecute la consulta: en
 * `parse_request` para `?s=` y en `rest_pre_dispatch` para la REST API. Al
 * superar el límite se responde 429 sin bloquear la IP.
 */
class WPS_Search_Guard {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		if ( 0 === (int) $this->loader->get_setting( 'rate_search_per_min', 20 ) ) {
			return;
		}

		add_action( 'parse_request', array( $this, 'check_frontend' ), 1 );
		add_filter( 'rest_pre_dispatch', array( $this, 'check_rest' ), 5, 3 );
	}

	/**
	 * Búsqueda del frontend (`?s=`).
	 */
	public function check_frontend(): void {
		if ( is_admin() || ! self::is_search_query( $_GET ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		if ( ! $this->exceeded() ) {
			return;
		}

		if ( ! headers_sent() ) {
			header( 'Retry-After: 60' );
		}

		wp_die(
			esc_html__( 'Demasiadas búsquedas en poco tiempo. Esperá un minuto e intentá de nuevo.', 'wp-secure' ),
			esc_html__( 'Demasiadas búsquedas', 'wp-secure' ),
			array( 'response' => 429 )
		);
	}

	/**
	 * Búsqueda por la REST API (`/wp/v2/search` o el parámetro `search`).
	 *
	 * @param mixed           $result  Respuesta previa.
	 * @param WP_REST_Server  $server  Servidor REST.
	 * @param WP_REST_Request $request Petición REST.
	 * @return mixed
	 */
	public function check_rest( $result, $server, $request ) {
		if ( null !== $result || ! is_object( $request ) ) {
			return $result;
		}

		if ( ! self::is_rest_search( (string) $request->get_route(), $request->get_param( 'search' ) ) ) {
			return $result;
		}

		if ( ! $this->exceeded() ) {
			return $result;
		}

		return new \WP_Error(
			'wps_search_rate_limited',
			__( 'Demasiadas búsquedas en poco tiempo. Esperá un minuto e intentá de nuevo.', 'wp-secure' ),
			array( 'status' => 429 )
		);
	}

	/**
	 * ¿La petición pide una búsqueda del sitio?
	 *
	 * @param array $query Parámetros GET.
	 */
	public static function is_search_query( array $query ): bool {
		return isset( $query['s'] ) && is_string( $query['s'] ) && '' !== trim( $query['s'] );
	}

	/**
	 * ¿La petición REST es una búsqueda?
	 *
	 * @param string $route  Ruta REST.
	 * @param mixed  $search Valor del parámetro `search`.
	 */
	public static function is_rest_search( string $route, $search ): bool {
		if ( preg_match( '#^/+wp/+v2/+search/*$#i', $route ) ) {
			return true;
		}

		return is_string( $search ) && '' !== trim( $search );
	}

	/**
	 * Contar la búsqueda y decir si el cliente superó el límite.
	 *
	 * Quedan exentos quien edita el sitio, la whitelist, el propio servidor, y
	 * todo mientras el bloqueo esté suspendido.
	 */
	private function exceeded(): bool {
		if ( WPS_Blocker::blocking_disabled() || WPS_Request::is_trusted_user() ) {
			return false;
		}

		$request = WPS_Request::get_instance();
		$ip      = $request->ip();

		if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
			return false;
		}

		if ( ! WPS_Rate_Limiter::get_instance( $this->loader )->exceeds( $ip, 'search' ) ) {
			return false;
		}

		WPS_Logger::get_instance()->event( WPS_Event_Types::RATE_LIMITED, array(
			'ip_address'  => $ip,
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array( 'type' => 'search' ),
		) );

		return true;
	}
}
