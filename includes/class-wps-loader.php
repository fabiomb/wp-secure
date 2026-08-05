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

        // Sincronizar MU-plugin si la versión instalada difiere del fuente.
        $this->maybe_sync_muplugin();

        // Cargar settings en cache.
        $this->load_settings();

        // Configurar proxy (necesario antes de WPS_Request).
        $proxy = WPS_Proxy_Config::get_instance();
        $proxy->set_loader( $this );

        // Registrar hooks de mantenimiento.
        add_action( 'wps_daily_maintenance', array( 'WPS_Db_Maintenance', 'daily' ) );
        add_action( 'wps_hourly_maintenance', array( 'WPS_Db_Maintenance', 'hourly' ) );

        // Regenerar archivo de Capa 0 después de actualizar el plugin.
        add_action( 'upgrader_process_complete', array( 'WPS_Activator', 'on_upgrade_complete' ), 10, 2 );

        // Verificar que las tareas cron existen (auto-reparación).
        WPS_Db_Maintenance::schedule();

        // Inicializar notificador (debe estar fuera de is_admin para que funcione en cron).
        $notifier = WPS_Admin_Notifier::get_instance( $this );
        $notifier->init();

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

        // Evaluar reglas personalizadas del usuario.
        $this->check_custom_rules();

        // Motor de puntuación de riesgo (apagado salvo que se configure).
        $this->init_risk_engine();

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
        if ( $this->get_setting( 'detector_login_enabled', true ) ) {
            $login_detector = new WPS_Login_Detector( $this );
            $login_detector->init();
        }

        if ( $this->get_setting( 'detector_xmlrpc_enabled', true ) ) {
            $xmlrpc_detector = new WPS_Xmlrpc_Detector( $this );
            $xmlrpc_detector->init();
        }

        // Detectores de Fase 4.
        if ( $this->get_setting( 'detector_sqli_enabled', true ) ) {
            $sqli_detector = new WPS_Sqli_Detector( $this );
            $sqli_detector->init();
        }

        if ( $this->get_setting( 'detector_xss_enabled', true ) ) {
            $xss_detector = new WPS_Xss_Detector( $this );
            $xss_detector->init();
        }

        if ( $this->get_setting( 'detector_path_traversal_enabled', true ) ) {
            $traversal_detector = new WPS_Path_Traversal_Detector( $this );
            $traversal_detector->init();
        }

        if ( $this->get_setting( 'detector_scanner_enabled', true ) ) {
            $scanner_detector = new WPS_Scanner_Detector( $this );
            $scanner_detector->init();
        }

        // Detector de REST API (Fase 6).
        if ( $this->get_setting( 'detector_restapi_enabled', true ) ) {
            $restapi_detector = new WPS_Restapi_Detector( $this );
            $restapi_detector->init();
        }

        // Rate Limiter: registrar hooks para conteo de peticiones.
        $this->init_rate_limiting();
    }

    /**
     * Inicializar el rate limiting en cada petición.
     */
    private function init_rate_limiting(): void {
        add_action( 'init', function () {
            // No aplicar rate limiting a administradores logueados (cualquier página).
            if ( current_user_can( 'manage_options' ) ) {
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

            // No contabilizar 404 para administradores logueados.
            if ( current_user_can( 'manage_options' ) ) {
                return;
            }

            $rate_limiter = WPS_Rate_Limiter::get_instance( $this );
            $rate_limiter->record_hit( $ip, '404' );
        } );
    }

    /**
     * ¿Corresponde registrar esta petición en el log de tráfico?
     *
     * @param string $visitor_type Tipo de visita clasificado por WPS_Request.
     */
    public function should_log_traffic( string $visitor_type ): bool {
        if ( 'static' === $visitor_type && $this->get_setting( 'exclude_static_from_log', true ) ) {
            return false;
        }

        return true;
    }

    /**
     * ¿Está habilitada una capa del firewall?
     *
     * @param int $layer 0 (auto_prepend_file) o 1 (MU-Plugin).
     */
    public function is_layer_enabled( int $layer ): bool {
        $defaults = array( 0 => false, 1 => true );

        return (bool) $this->get_setting(
            'firewall_layer' . $layer . '_enabled',
            $defaults[ $layer ] ?? false
        );
    }

    /**
     * Registrar cada petición en la tabla traffic_log.
     *
     * El registro se difiere al shutdown: en plugins_loaded todavía no existen
     * ni el código de respuesta ni un tiempo de proceso con sentido, así que
     * medirlos acá daba siempre http_status vacío y response_time_ms ≈ 0.
     */
    private function init_traffic_logging(): void {
        // No registrar cron.
        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        $request = WPS_Request::get_instance();

        if ( ! $this->should_log_traffic( $request->visitor_type() ) ) {
            return;
        }

        // No registrar tráfico de IPs en whitelist (ej: admin).
        if ( WPS_Whitelist::get_instance()->is_whitelisted( $request->ip() ) ) {
            return;
        }

        add_action( 'shutdown', array( $this, 'log_current_request' ), 0 );
    }

    /**
     * Volcar la petición actual al log de tráfico, al final del ciclo.
     */
    public function log_current_request(): void {
        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

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

        $status = http_response_code();

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
            'http_status'    => is_int( $status ) ? $status : null,
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
     * Enganchar el motor de puntuación de riesgo.
     *
     * Corre después de los detectores individuales (prioridad 2) para que una
     * petición que ya fue bloqueada por un patrón concreto no vuelva a
     * evaluarse. Si el motor está apagado no se registra ningún hook.
     */
    private function init_risk_engine(): void {
        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        $engine = WPS_Rules_Engine::get_instance( $this );

        if ( ! $engine->is_enabled() ) {
            return;
        }

        add_action( 'init', function () use ( $engine ) {
            if ( WPS_Request::is_trusted_user() ) {
                return;
            }

            $request = WPS_Request::get_instance();

            if ( WPS_Whitelist::get_instance()->is_whitelisted( $request->ip() ) ) {
                return;
            }

            $engine->evaluate_and_act( $request, $this->build_risk_context( $request ) );
        }, 3 );
    }

    /**
     * Contexto adicional para la evaluación de riesgo.
     */
    private function build_risk_context( WPS_Request $request ): array {
        $context = array();

        $country = $this->resolve_country( $request->ip() );
        if ( $country ) {
            $context['country_code'] = $country;
        }

        return $context;
    }

    /**
     * Resolver el país de una IP, si hay geolocalización disponible.
     */
    private function resolve_country( string $ip ): ?string {
        $api_key  = $this->get_setting( 'ipinfo_api_key', '' );
        $has_mmdb = WPS_Ipdb_Manager::get_instance()->is_local_available();

        if ( empty( $api_key ) && ! $has_mmdb ) {
            return null;
        }

        if ( WPS_Ip_Utils::is_private_ip( $ip ) ) {
            return null;
        }

        $geo_data = WPS_Geo::get_instance()->lookup( $ip );

        return ! empty( $geo_data['country'] ) ? $geo_data['country'] : null;
    }

    /**
     * Evaluar reglas personalizadas del usuario contra la petición actual.
     */
    private function check_custom_rules(): void {
        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            return;
        }

        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return;
        }

        // No aplicar reglas personalizadas a administradores logueados.
        if ( current_user_can( 'manage_options' ) ) {
            return;
        }

        // Construir contexto geo si está disponible.
        $context = $this->build_risk_context( $request );

        $custom_rules = WPS_Custom_Rules::get_instance();
        $custom_rules->evaluate_and_act( $request, $context );
    }

    /**
     * Ejecutar migraciones si cambió la versión.
     */
    private function maybe_upgrade(): void {
        $stored_version = get_option( 'wps_version', '0.0.0' );
        if ( version_compare( $stored_version, WPS_VERSION, '<' ) ) {
            WPS_Db_Migrations::run();
            WPS_Activator::install_muplugin();
            update_option( 'wps_version', WPS_VERSION );
        }
    }

    /**
     * Comparar la versión del MU-plugin instalado contra el fuente.
     * Si difieren, reemplazar el archivo instalado.
     */
    private function maybe_sync_muplugin(): void {
        $installed = WPMU_PLUGIN_DIR . '/wps-firewall-muplugin.php';
        $source    = WPS_INCLUDES_DIR . 'firewall/wps-firewall-muplugin.php';

        if ( ! is_file( $installed ) || ! is_file( $source ) ) {
            return;
        }

        $installed_version = $this->get_file_header_version( $installed );
        $source_version    = $this->get_file_header_version( $source );

        if ( $source_version && $installed_version !== $source_version ) {
            WPS_Activator::install_muplugin();
        }
    }

    /**
     * Extraer la versión del header "Version:" de un archivo PHP de plugin.
     */
    private function get_file_header_version( string $file ): ?string {
        // Leer solo los primeros 2 KB para buscar el header.
        $content = file_get_contents( $file, false, null, 0, 2048 );
        if ( $content && preg_match( '/^\s*\*?\s*Version:\s*(.+)$/mi', $content, $matches ) ) {
            return trim( $matches[1] );
        }
        return null;
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
