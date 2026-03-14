<?php
defined( 'ABSPATH' ) || exit;

/**
 * Carga y orquestación del plugin.
 *
 * Registra hooks, carga componentes y coordina la ejecución.
 */
class WPS_Loader {

    /** @var WPS_Loader|null */
    private static $instance = null;

    /** @var array Cache de settings con autoload. */
    private $settings_cache = array();

    /** @var bool */
    private $initialized = false;

    private function __construct() {}

    public static function get_instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Inicializar el plugin.
     */
    public function init(): void {
        if ( $this->initialized ) {
            return;
        }
        $this->initialized = true;

        // Verificar migraciones de BD.
        $this->maybe_upgrade();

        // Cargar settings en cache.
        $this->load_settings();

        // Configurar proxy (necesario antes de WPS_Request).
        $proxy = WPS_Proxy_Config::get_instance();
        $proxy->set_loader( $this );

        // Registrar hooks de mantenimiento.
        add_action( 'wps_daily_maintenance', array( 'WPS_Db_Maintenance', 'daily' ) );
        add_action( 'wps_hourly_maintenance', array( 'WPS_Db_Maintenance', 'hourly' ) );

        // Performance monitor.
        $perf = WPS_Performance_Monitor::get_instance();
        $perf->init( $this );

        // Inicializar detectores de seguridad.
        $perf->start( 'detectors' );
        $this->init_detectors();
        $perf->stop( 'detectors' );

        // Security hardener (headers, métodos HTTP, ocultar versión).
        $hardener = new WPS_Security_Hardener( $this );
        $hardener->init();

        // Verificar bloqueo de IP actual en cada petición.
        $this->check_current_ip();

        // Registrar tráfico en cada petición (frontend + admin).
        $this->init_traffic_logging();

        // Registrar panel de administración.
        if ( is_admin() ) {
            $admin = new WPS_Admin( $this );
            $admin->init();

            $ajax = new WPS_Admin_Ajax( $this );
            $ajax->init();
        }
    }

    /**
     * Inicializar detectores de seguridad y componentes de firewall.
     */
    private function init_detectors(): void {
        $login_detector = new WPS_Login_Detector( $this );
        $login_detector->init();

        $xmlrpc_detector = new WPS_Xmlrpc_Detector( $this );
        $xmlrpc_detector->init();

        // Detectores de Fase 4.
        $sqli_detector = new WPS_Sqli_Detector( $this );
        $sqli_detector->init();

        $xss_detector = new WPS_Xss_Detector( $this );
        $xss_detector->init();

        $traversal_detector = new WPS_Path_Traversal_Detector( $this );
        $traversal_detector->init();

        $scanner_detector = new WPS_Scanner_Detector( $this );
        $scanner_detector->init();

        // Detector de REST API (Fase 6).
        $restapi_detector = new WPS_Restapi_Detector( $this );
        $restapi_detector->init();

        // Rate Limiter: registrar hooks para conteo de peticiones.
        $this->init_rate_limiting();
    }

    /**
     * Inicializar el rate limiting en cada petición.
     */
    private function init_rate_limiting(): void {
        add_action( 'init', function () {
            if ( is_admin() && current_user_can( 'manage_options' ) ) {
                return;
            }

            $request = WPS_Request::get_instance();
            $ip      = $request->ip();

            if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
                return;
            }

            // No aplicar rate limit a cron.
            if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
                return;
            }

            $rate_limiter = WPS_Rate_Limiter::get_instance( $this );
            $visitor_type = $request->visitor_type();

            // Total (todas las peticiones).
            $rate_limiter->record_hit( $ip, 'total' );

            // Pages (que generan carga WordPress).
            if ( 'static' !== $visitor_type ) {
                $rate_limiter->record_hit( $ip, 'pages' );
            }
        }, 3 );

        // Registrar 404 hits.
        add_action( 'template_redirect', function () {
            if ( ! is_404() ) {
                return;
            }

            $request = WPS_Request::get_instance();
            $ip      = $request->ip();

            if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
                return;
            }

            $rate_limiter = WPS_Rate_Limiter::get_instance( $this );
            $rate_limiter->record_hit( $ip, '404' );
        } );
    }

    /**
     * Registrar cada petición en la tabla traffic_log.
     */
    private function init_traffic_logging(): void {
        // No registrar cron.
        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        // No registrar tráfico de IPs en whitelist (ej: admin).
        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return;
        }

        // Geo data (si está disponible).
        $country = null;
        $asn     = null;
        if ( class_exists( 'WPS_Geo' ) ) {
            $has_mmdb = WPS_Ipdb_Manager::get_instance()->is_local_available();
            if ( $has_mmdb && ! WPS_Ip_Utils::is_private_ip( $ip ) ) {
                $geo_data = WPS_Geo::get_instance()->lookup( $ip );
                $country  = $geo_data['country'] ?? null;
                $asn      = $geo_data['asn'] ?? null;
            }
        }

        $logger = WPS_Logger::get_instance();
        $logger->traffic( array(
            'ip_address'     => $ip,
            'country_code'   => $country,
            'asn'            => $asn,
            'request_uri'    => $request->uri(),
            'request_method' => $request->method(),
            'user_agent'     => $request->user_agent(),
            'referer'        => $request->referer(),
            'visitor_type'   => $request->visitor_type(),
            'session_hash'   => $request->session_hash(),
            'response_time_ms' => $request->elapsed_ms(),
        ) );
    }

    /**
     * Verificar si la IP actual está bloqueada.
     */
    private function check_current_ip(): void {
        // No bloquear peticiones de admin AJAX ni cron para evitar auto-bloqueo.
        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        // Whitelist primero.
        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return;
        }

        $blocker = WPS_Blocker::get_instance();
        $logger  = WPS_Logger::get_instance();

        // 1. Verificar bloqueo directo por IP.
        $block = $blocker->is_blocked( $ip );
        if ( $block ) {
            $blocker->increment_hits( (int) $block['id'] );

            $logger->event_immediate( WPS_Event_Types::IP_BLOCKED, array(
                'ip_address'  => $ip,
                'request_uri' => $request->uri(),
                'user_agent'  => $request->user_agent(),
                'details'     => array(
                    'block_id'   => $block['id'],
                    'block_type' => $block['block_type'],
                ),
            ) );

            $blocker->send_block_response();
        }

        // 2. Verificar bloqueo por país/ASN (solo si hay API key o MMDB).
        $this->check_geo_block( $ip, $request, $blocker, $logger );
    }

    /**
     * Verificar bloqueo por país o ASN usando geolocalización.
     */
    private function check_geo_block( string $ip, WPS_Request $request, WPS_Blocker $blocker, WPS_Logger $logger ): void {
        // Solo verificar si hay configuración de geo disponible.
        $api_key  = $this->get_setting( 'ipinfo_api_key', '' );
        $has_mmdb = WPS_Ipdb_Manager::get_instance()->is_local_available();

        if ( empty( $api_key ) && ! $has_mmdb ) {
            return;
        }

        // Skip for private/reserved IPs.
        if ( WPS_Ip_Utils::is_private_ip( $ip ) ) {
            return;
        }

        $geo  = WPS_Geo::get_instance();
        $data = $geo->lookup( $ip );

        // Check country block.
        if ( ! empty( $data['country'] ) && $blocker->is_country_blocked( $data['country'] ) ) {
            $logger->event_immediate( WPS_Event_Types::COUNTRY_BLOCKED, array(
                'ip_address'   => $ip,
                'country_code' => $data['country'],
                'request_uri'  => $request->uri(),
                'user_agent'   => $request->user_agent(),
                'details'      => array(
                    'country'      => $data['country'],
                    'country_name' => WPS_Geo::country_name( $data['country'] ),
                ),
            ) );

            $blocker->send_block_response();
        }

        // Check ASN block.
        if ( ! empty( $data['asn'] ) && $blocker->is_asn_blocked( (int) $data['asn'] ) ) {
            $logger->event_immediate( WPS_Event_Types::ASN_BLOCKED, array(
                'ip_address'  => $ip,
                'asn'         => $data['asn'],
                'request_uri' => $request->uri(),
                'user_agent'  => $request->user_agent(),
                'details'     => array(
                    'asn'      => $data['asn'],
                    'asn_name' => $data['asn_name'] ?? '',
                ),
            ) );

            $blocker->send_block_response();
        }
    }

    /**
     * Ejecutar migraciones si cambió la versión.
     */
    private function maybe_upgrade(): void {
        $stored_version = get_option( 'wps_version', '0.0.0' );
        if ( version_compare( $stored_version, WPS_VERSION, '<' ) ) {
            WPS_Db_Migrations::run();
            update_option( 'wps_version', WPS_VERSION );
        }
    }

    /**
     * Cargar todos los settings con autoload en memoria.
     */
    private function load_settings(): void {
        $db = WPS_Db::get_instance();
        if ( WPS_Db_Schema::tables_exist() ) {
            $this->settings_cache = $db->get_autoload_settings();
        }
    }

    /**
     * Obtener un setting desde cache.
     *
     * @param string $key     Clave del setting.
     * @param mixed  $default Valor por defecto.
     * @return mixed
     */
    public function get_setting( string $key, $default = null ) {
        if ( array_key_exists( $key, $this->settings_cache ) ) {
            return $this->settings_cache[ $key ];
        }

        // Fallback: leer de BD si no está en cache.
        $db    = WPS_Db::get_instance();
        $value = $db->get_setting( $key, $default );
        $this->settings_cache[ $key ] = $value;

        return $value;
    }

    /**
     * Guardar un setting y actualizar cache.
     */
    public function set_setting( string $key, $value, bool $autoload = true ): bool {
        $db     = WPS_Db::get_instance();
        $result = $db->set_setting( $key, $value, $autoload );
        if ( $result ) {
            $this->settings_cache[ $key ] = $value;
        }
        return $result;
    }

    /**
     * Obtener todos los settings en cache.
     */
    public function get_all_settings(): array {
        return $this->settings_cache;
    }
}
