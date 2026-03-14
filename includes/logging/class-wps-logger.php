<?php
defined( 'ABSPATH' ) || exit;

/**
 * Sistema de logging con buffer.
 *
 * Acumula entradas en memoria y las escribe al final de la petición
 * para no bloquear la respuesta.
 */
class WPS_Logger {

    /** @var WPS_Logger|null */
    private static $instance = null;

    /** @var array Buffer de eventos de seguridad pendientes de escribir. */
    private $event_buffer = array();

    /** @var array Buffer de entradas de tráfico pendientes de escribir. */
    private $traffic_buffer = array();

    /** @var bool Si ya se registró el shutdown. */
    private $shutdown_registered = false;

    private function __construct() {}

    public static function get_instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Registrar un evento de seguridad.
     *
     * @param string      $event_type Tipo de evento (usar constantes de WPS_Event_Types).
     * @param array       $data       Datos adicionales del evento.
     * @param string|null $severity   Severidad (info/warning/critical). Auto si null.
     */
    public function event( string $event_type, array $data = array(), ?string $severity = null ): void {
        if ( null === $severity ) {
            $severity = WPS_Event_Types::default_severity( $event_type );
        }

        $entry = array(
            'event_type'   => $event_type,
            'severity'     => $severity,
            'ip_address'   => $data['ip_address'] ?? null,
            'country_code' => $data['country_code'] ?? null,
            'asn'          => $data['asn'] ?? null,
            'details'      => isset( $data['details'] ) ? wp_json_encode( $data['details'] ) : null,
            'request_uri'  => $data['request_uri'] ?? null,
            'user_agent'   => isset( $data['user_agent'] ) ? substr( $data['user_agent'], 0, 1024 ) : null,
            'wp_user_id'   => $data['wp_user_id'] ?? null,
            'created_at'   => current_time( 'mysql', true ),
        );

        $this->event_buffer[] = $entry;
        $this->ensure_shutdown();
    }

    /**
     * Registrar una entrada de tráfico.
     */
    public function traffic( array $data ): void {
        $entry = array(
            'ip_address'     => $data['ip_address'] ?? '',
            'country_code'   => $data['country_code'] ?? null,
            'asn'            => $data['asn'] ?? null,
            'request_uri'    => isset( $data['request_uri'] ) ? substr( $data['request_uri'], 0, 2048 ) : '',
            'request_method' => $data['request_method'] ?? 'GET',
            'user_agent'     => isset( $data['user_agent'] ) ? substr( $data['user_agent'], 0, 1024 ) : null,
            'referer'        => isset( $data['referer'] ) ? substr( $data['referer'], 0, 2048 ) : null,
            'http_status'    => $data['http_status'] ?? null,
            'is_human'       => $data['is_human'] ?? null,
            'visitor_type'   => $data['visitor_type'] ?? 'unknown',
            'session_hash'   => $data['session_hash'] ?? null,
            'response_time_ms' => $data['response_time_ms'] ?? null,
            'created_at'     => current_time( 'mysql', true ),
        );

        $this->traffic_buffer[] = $entry;
        $this->ensure_shutdown();
    }

    /**
     * Registrar un evento de seguridad de forma inmediata (sin buffer).
     * Para situaciones donde se va a terminar la ejecución (bloqueo 403).
     */
    public function event_immediate( string $event_type, array $data = array(), ?string $severity = null ): void {
        $this->event( $event_type, $data, $severity );
        $this->flush();
    }

    /**
     * Escribir todos los buffers a la base de datos.
     */
    public function flush(): void {
        $db = WPS_Db::get_instance();

        // Escribir eventos de seguridad.
        foreach ( $this->event_buffer as $entry ) {
            $db->insert( 'security_events', $entry );
        }
        $this->event_buffer = array();

        // Escribir entradas de tráfico.
        foreach ( $this->traffic_buffer as $entry ) {
            $db->insert( 'traffic_log', $entry );
        }
        $this->traffic_buffer = array();
    }

    /**
     * Registrar el shutdown handler para hacer flush al final de la petición.
     */
    private function ensure_shutdown(): void {
        if ( ! $this->shutdown_registered ) {
            register_shutdown_function( array( $this, 'flush' ) );
            $this->shutdown_registered = true;
        }
    }
}
