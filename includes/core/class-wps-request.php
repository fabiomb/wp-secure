<?php
defined( 'ABSPATH' ) || exit;

/**
 * Objeto Request: captura y normaliza todos los datos de la petición HTTP actual.
 */
class WPS_Request {

    /** @var WPS_Request|null */
    private static $instance = null;

    /** @var string */
    private $ip;

    /** @var string */
    private $uri;

    /** @var string */
    private $method;

    /** @var string */
    private $user_agent;

    /** @var string */
    private $referer;

    /** @var string */
    private $query_string;

    /** @var string */
    private $host;

    /** @var array */
    private $headers;

    /** @var string */
    private $session_hash;

    /** @var string */
    private $visitor_type;

    /** @var float */
    private $start_time;

    private function __construct() {
        $this->start_time   = microtime( true );
        $this->ip           = $this->resolve_ip();
        $this->uri          = $this->sanitize_uri( $_SERVER['REQUEST_URI'] ?? '/' );
        $this->method       = strtoupper( $_SERVER['REQUEST_METHOD'] ?? 'GET' );
        $this->user_agent   = substr( $_SERVER['HTTP_USER_AGENT'] ?? '', 0, 1024 );
        $this->referer      = substr( $_SERVER['HTTP_REFERER'] ?? '', 0, 2048 );
        $this->query_string = $_SERVER['QUERY_STRING'] ?? '';
        $this->host         = $_SERVER['HTTP_HOST'] ?? '';
        $this->headers      = $this->collect_headers();
        $this->session_hash = $this->build_session_hash();
        $this->visitor_type = $this->classify_visitor_type();
    }

    public static function get_instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /*──────────────────────────────────────────────
     * Getters
     *──────────────────────────────────────────────*/

    public function ip(): string {
        return $this->ip;
    }

    public function uri(): string {
        return $this->uri;
    }

    public function method(): string {
        return $this->method;
    }

    public function user_agent(): string {
        return $this->user_agent;
    }

    public function referer(): string {
        return $this->referer;
    }

    public function query_string(): string {
        return $this->query_string;
    }

    public function host(): string {
        return $this->host;
    }

    public function headers(): array {
        return $this->headers;
    }

    public function session_hash(): string {
        return $this->session_hash;
    }

    public function visitor_type(): string {
        return $this->visitor_type;
    }

    /**
     * Tiempo transcurrido en milisegundos desde el inicio de la petición.
     */
    public function elapsed_ms(): int {
        return (int) round( ( microtime( true ) - $this->start_time ) * 1000 );
    }

    /**
     * ¿El visitante tiene cookie de sesión WordPress activa?
     */
    public function has_wp_cookie(): bool {
        foreach ( $_COOKIE as $name => $value ) {
            if ( 0 === strpos( $name, 'wordpress_logged_in_' ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Devuelve los datos de la request como array (para logging).
     */
    public function to_array(): array {
        return array(
            'ip_address'     => $this->ip,
            'request_uri'    => $this->uri,
            'request_method' => $this->method,
            'user_agent'     => $this->user_agent,
            'referer'        => $this->referer,
            'visitor_type'   => $this->visitor_type,
            'session_hash'   => $this->session_hash,
        );
    }

    /*──────────────────────────────────────────────
     * Resolución de IP
     *──────────────────────────────────────────────*/

    /**
     * Determinar la IP real del visitante, delegando a WPS_Proxy_Config.
     */
    private function resolve_ip(): string {
        // Usar WPS_Proxy_Config si está disponible (Capa 2 con loader configurado).
        if ( class_exists( 'WPS_Proxy_Config' ) ) {
            $proxy = WPS_Proxy_Config::get_instance();
            $ip    = $proxy->get_real_ip();
            if ( WPS_Ip_Utils::is_valid_ip( $ip ) ) {
                return $ip;
            }
        }

        // Fallback: lectura directa (Layer 0/1 o si proxy no está configurado).
        $headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
        );

        foreach ( $headers as $header ) {
            if ( ! empty( $_SERVER[ $header ] ) ) {
                $ip = trim( explode( ',', $_SERVER[ $header ] )[0] );
                if ( WPS_Ip_Utils::is_valid_ip( $ip ) && ! WPS_Ip_Utils::is_private_ip( $ip ) ) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Sanitizar la URI.
     */
    private function sanitize_uri( string $uri ): string {
        // Limitar longitud.
        $uri = substr( $uri, 0, 2048 );
        // Decodificar doble encoding.
        $uri = rawurldecode( $uri );
        // Normalizar barras.
        $uri = str_replace( '\\', '/', $uri );
        return $uri;
    }

    /**
     * Recopilar todos los headers HTTP.
     */
    private function collect_headers(): array {
        $headers = array();

        if ( function_exists( 'getallheaders' ) ) {
            $raw = getallheaders();
            if ( is_array( $raw ) ) {
                foreach ( $raw as $name => $value ) {
                    $headers[ strtolower( $name ) ] = $value;
                }
            }
        } else {
            // Fallback para servidores que no soportan getallheaders().
            foreach ( $_SERVER as $key => $value ) {
                if ( 0 === strpos( $key, 'HTTP_' ) ) {
                    $name = strtolower( str_replace( '_', '-', substr( $key, 5 ) ) );
                    $headers[ $name ] = $value;
                }
            }
        }

        return $headers;
    }

    /**
     * Generar hash de sesión para agrupar peticiones de un mismo visitante.
     */
    private function build_session_hash(): string {
        $accept_lang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
        return hash( 'sha256', $this->ip . '|' . $this->user_agent . '|' . $accept_lang );
    }

    /**
     * Clasificar el tipo de visita basado en la URI.
     */
    private function classify_visitor_type(): string {
        $uri = strtolower( $this->uri );
        $path = wp_parse_url( $uri, PHP_URL_PATH ) ?: $uri;

        // Recurso estático.
        if ( preg_match( '/\.(css|js|jpg|jpeg|png|gif|svg|ico|woff2?|ttf|eot|map|webp|avif)$/i', $path ) ) {
            return 'static';
        }

        // Login.
        if ( false !== strpos( $path, 'wp-login.php' ) ) {
            return 'login';
        }

        // XML-RPC.
        if ( false !== strpos( $path, 'xmlrpc.php' ) ) {
            return 'xmlrpc';
        }

        // REST API.
        if ( false !== strpos( $path, '/wp-json/' ) || false !== strpos( $path, '?rest_route=' ) ) {
            return 'restapi';
        }

        // WP-Cron.
        if ( false !== strpos( $path, 'wp-cron.php' ) ) {
            return 'cron';
        }

        // Admin AJAX.
        if ( false !== strpos( $path, 'admin-ajax.php' ) ) {
            return 'ajax';
        }

        // Admin.
        if ( false !== strpos( $path, '/wp-admin/' ) ) {
            return 'admin';
        }

        // Feed.
        if ( preg_match( '#/(feed|rss|atom)/?$#', $path ) ) {
            return 'feed';
        }

        return 'page';
    }
}
