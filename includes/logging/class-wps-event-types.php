<?php
defined( 'ABSPATH' ) || exit;

/**
 * Definición de tipos de eventos de seguridad.
 */
class WPS_Event_Types {

    /** Eventos de login. */
    const LOGIN_FAILED   = 'login_failed';
    const LOGIN_BLOCKED  = 'login_blocked';
    const LOGIN_SUCCESS  = 'login_success';

    /** Eventos de bloqueo. */
    const XMLRPC_BLOCKED    = 'xmlrpc_blocked';
    const SQLI_DETECTED     = 'sqli_detected';
    const XSS_DETECTED      = 'xss_detected';
    const TRAVERSAL_DETECTED = 'traversal_detected';
    const RATE_LIMITED       = 'rate_limited';
    const SCANNER_DETECTED   = 'scanner_detected';
    const COUNTRY_BLOCKED    = 'country_blocked';
    const ASN_BLOCKED        = 'asn_blocked';
    const IP_BLOCKED         = 'ip_blocked';

    /** Eventos de riesgo (rules engine). */
    const RISK_LOW    = 'risk_low';
    const RISK_MEDIUM = 'risk_medium';
    const RISK_HIGH   = 'risk_high';

    /** Eventos de whitelist. */
    const WHITELIST_BYPASS = 'whitelist_bypass';

    /** Eventos de hardening (Fase 6). */
    const RESTAPI_BLOCKED      = 'restapi_blocked';
    const CRAWLER_SPOOFED      = 'crawler_spoofed';
    const HTTP_METHOD_BLOCKED  = 'http_method_blocked';
    const EMPTY_UA_BLOCKED     = 'empty_ua_blocked';
    const MISSING_HOST_BLOCKED = 'missing_host_blocked';

    /** Eventos administrativos. */
    const MANUAL_BLOCK    = 'manual_block';
    const MANUAL_UNBLOCK  = 'manual_unblock';
    const SETTINGS_CHANGED = 'settings_changed';
    const CUSTOM_RULE_MATCHED = 'custom_rule_matched';

    /** Severidades. */
    const SEVERITY_INFO     = 'info';
    const SEVERITY_WARNING  = 'warning';
    const SEVERITY_CRITICAL = 'critical';

    /**
     * Todos los tipos de evento que el plugin puede registrar.
     *
     * Se deriva por reflexión de las constantes de la clase para que agregar un
     * tipo nuevo no requiera acordarse de sumarlo también a los filtros del
     * visor de eventos.
     *
     * @return string[]
     */
    public static function all(): array {
        static $types = null;

        if ( null !== $types ) {
            return $types;
        }

        $constants = ( new ReflectionClass( __CLASS__ ) )->getConstants();

        $types = array();
        foreach ( $constants as $name => $value ) {
            if ( 0 === strpos( $name, 'SEVERITY_' ) ) {
                continue;
            }
            $types[] = $value;
        }

        return $types;
    }

    /**
     * Severidad predefinida para cada tipo de evento.
     */
    public static function default_severity( string $event_type ): string {
        $map = array(
            self::LOGIN_SUCCESS     => self::SEVERITY_INFO,
            self::WHITELIST_BYPASS  => self::SEVERITY_INFO,
            self::SETTINGS_CHANGED  => self::SEVERITY_INFO,
            self::CUSTOM_RULE_MATCHED => self::SEVERITY_WARNING,
            self::MANUAL_BLOCK      => self::SEVERITY_INFO,
            self::MANUAL_UNBLOCK    => self::SEVERITY_INFO,

            self::LOGIN_FAILED      => self::SEVERITY_WARNING,
            self::LOGIN_BLOCKED     => self::SEVERITY_WARNING,
            self::XMLRPC_BLOCKED    => self::SEVERITY_WARNING,
            self::RATE_LIMITED      => self::SEVERITY_WARNING,
            self::COUNTRY_BLOCKED      => self::SEVERITY_WARNING,
            self::ASN_BLOCKED          => self::SEVERITY_WARNING,
            self::IP_BLOCKED           => self::SEVERITY_WARNING,
            self::RESTAPI_BLOCKED      => self::SEVERITY_WARNING,
            self::HTTP_METHOD_BLOCKED  => self::SEVERITY_WARNING,
            self::EMPTY_UA_BLOCKED     => self::SEVERITY_WARNING,
            self::MISSING_HOST_BLOCKED => self::SEVERITY_WARNING,
            self::CRAWLER_SPOOFED      => self::SEVERITY_WARNING,

            self::SQLI_DETECTED     => self::SEVERITY_CRITICAL,
            self::XSS_DETECTED      => self::SEVERITY_CRITICAL,
            self::TRAVERSAL_DETECTED => self::SEVERITY_CRITICAL,
            self::SCANNER_DETECTED   => self::SEVERITY_CRITICAL,

            self::RISK_LOW           => self::SEVERITY_INFO,
            self::RISK_MEDIUM        => self::SEVERITY_WARNING,
            self::RISK_HIGH          => self::SEVERITY_CRITICAL,
        );

        return $map[ $event_type ] ?? self::SEVERITY_WARNING;
    }

    /**
     * Etiqueta legible del tipo de evento.
     */
    public static function label( string $event_type ): string {
        $labels = array(
            self::LOGIN_FAILED       => __( 'Login fallido', 'wp-secure' ),
            self::LOGIN_BLOCKED      => __( 'Login bloqueado', 'wp-secure' ),
            self::LOGIN_SUCCESS      => __( 'Login exitoso', 'wp-secure' ),
            self::XMLRPC_BLOCKED     => __( 'XML-RPC bloqueado', 'wp-secure' ),
            self::SQLI_DETECTED      => __( 'Inyección SQL', 'wp-secure' ),
            self::XSS_DETECTED       => __( 'XSS detectado', 'wp-secure' ),
            self::TRAVERSAL_DETECTED => __( 'Path traversal', 'wp-secure' ),
            self::RATE_LIMITED       => __( 'Rate limit excedido', 'wp-secure' ),
            self::SCANNER_DETECTED   => __( 'Scanner detectado', 'wp-secure' ),
            self::COUNTRY_BLOCKED    => __( 'País bloqueado', 'wp-secure' ),
            self::ASN_BLOCKED        => __( 'ASN bloqueado', 'wp-secure' ),
            self::IP_BLOCKED         => __( 'IP bloqueada', 'wp-secure' ),
            self::RESTAPI_BLOCKED      => __( 'REST API bloqueada', 'wp-secure' ),
            self::CRAWLER_SPOOFED      => __( 'Crawler falsificado', 'wp-secure' ),
            self::HTTP_METHOD_BLOCKED  => __( 'Método HTTP bloqueado', 'wp-secure' ),
            self::EMPTY_UA_BLOCKED     => __( 'UA vacío bloqueado', 'wp-secure' ),
            self::MISSING_HOST_BLOCKED => __( 'Host ausente bloqueado', 'wp-secure' ),
            self::WHITELIST_BYPASS   => __( 'Whitelist bypass', 'wp-secure' ),
            self::MANUAL_BLOCK       => __( 'Bloqueo manual', 'wp-secure' ),
            self::MANUAL_UNBLOCK     => __( 'Desbloqueo manual', 'wp-secure' ),
            self::SETTINGS_CHANGED   => __( 'Configuración cambiada', 'wp-secure' ),
            self::CUSTOM_RULE_MATCHED => __( 'Regla personalizada', 'wp-secure' ),
            self::RISK_LOW           => __( 'Riesgo bajo', 'wp-secure' ),
            self::RISK_MEDIUM        => __( 'Riesgo medio', 'wp-secure' ),
            self::RISK_HIGH          => __( 'Riesgo alto', 'wp-secure' ),
        );

        return $labels[ $event_type ] ?? $event_type;
    }
}
