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
     * ¿El usuario autenticado actual es de confianza para los detectores?
     *
     * Los detectores de patrones bloquean la IP de origen. Aplicárselos a quien
     * edita el sitio genera falsos positivos caros: un autor que escribe sobre
     * SQL o pega un fragmento de HTML en un post dispara los mismos patrones
     * que un atacante, y termina bloqueado en su propio sitio.
     *
     * Se toma `edit_posts` (colaborador en adelante) como límite: publicar
     * contenido implica manipular código como parte del trabajo normal.
     */
    public static function is_trusted_user(): bool {
        if ( ! function_exists( 'current_user_can' ) ) {
            return false;
        }

        return current_user_can( 'edit_posts' );
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
     * Determinar si la URI corresponde a una URL de taxonomía de WordPress
     * (tag, category, taxonomías personalizadas).
     *
     * Estas URLs contienen slugs que provienen de contenido publicado
     * y pueden incluir palabras que coinciden con patrones de seguridad
     * sin ser un ataque real.
     */
    public function is_wp_content_path(): bool {
        $path = wp_parse_url( $this->uri, PHP_URL_PATH );
        if ( ! $path ) {
            return false;
        }

        $path = rtrim( $path, '/' );

        // Bases de taxonomías por defecto.
        $bases = array( 'tag', 'category' );

        // Obtener bases personalizadas de WordPress.
        if ( function_exists( 'get_option' ) ) {
            $tag_base = get_option( 'tag_base' );
            if ( $tag_base ) {
                $bases[] = trim( $tag_base, '/' );
            }
            $cat_base = get_option( 'category_base' );
            if ( $cat_base ) {
                $bases[] = trim( $cat_base, '/' );
            }
        }

        // Obtener taxonomías personalizadas registradas.
        if ( function_exists( 'get_taxonomies' ) ) {
            $custom = get_taxonomies( array( 'public' => true, '_builtin' => false ), 'objects' );
            foreach ( $custom as $tax ) {
                if ( ! empty( $tax->rewrite['slug'] ) ) {
                    $bases[] = $tax->rewrite['slug'];
                }
            }
        }

        $bases = array_unique( $bases );

        foreach ( $bases as $base ) {
            // Coincidir: /base/slug o /base/slug/page/2, etc.
            if ( preg_match( '#^/' . preg_quote( $base, '#' ) . '/[a-z0-9_-]+#i', $path ) ) {
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
     *
     * La resolución pasa siempre por WPS_Proxy_Config, que es quien decide si
     * los headers de proxy son confiables para esta petición. No existe una
     * ruta alternativa que los lea directamente: un respaldo así ignoraría la
     * configuración `proxy_mode` y permitiría falsificar la IP de origen
     * enviando un header cualquiera.
     */
    private function resolve_ip(): string {
        if ( class_exists( 'WPS_Proxy_Config' ) ) {
            $ip = WPS_Proxy_Config::get_instance()->get_real_ip();
            if ( WPS_Ip_Utils::is_valid_ip( $ip ) ) {
                return $ip;
            }
        }

        // Sin proxy config disponible sólo se confía en la conexión real.
        $remote_addr = WPS_Ip_Utils::strip_port( $_SERVER['REMOTE_ADDR'] ?? '' );

        return WPS_Ip_Utils::is_valid_ip( $remote_addr ) ? $remote_addr : '0.0.0.0';
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

        // REST API. `rest_route` viaja en el query string, que $path ya no
        // contiene, así que se busca sobre la URI completa.
        if ( false !== strpos( $path, '/wp-json/' ) || false !== strpos( $uri, 'rest_route=' ) ) {
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

        // WooCommerce frontend AJAX (wc-ajax=action).
        if ( isset( $_GET['wc-ajax'] ) ) {
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
