<?php
defined( 'ABSPATH' ) || exit;

/**
 * Lógica de activación del plugin.
 */
class WPS_Activator {

    /**
     * Hook de activación.
     */
    public static function activate(): void {
        self::check_requirements();
        self::create_tables();
        self::set_defaults();
        self::protect_data_dir();
        self::schedule_maintenance();
        self::install_muplugin();
        self::create_blocked_ips_file();

        // Marcar como recién activado para mostrar wizard.
        update_option( 'wps_activated', true );
        update_option( 'wps_version', WPS_VERSION );
    }

    /**
     * Verificar requisitos mínimos.
     */
    private static function check_requirements(): void {
        if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
            deactivate_plugins( WPS_PLUGIN_BASENAME );
            wp_die(
                esc_html__( 'WP Seguro requiere PHP 7.4 o superior.', 'wp-secure' ),
                'Plugin Activation Error',
                array( 'back_link' => true )
            );
        }

        global $wp_version;
        if ( version_compare( $wp_version, '6.0', '<' ) ) {
            deactivate_plugins( WPS_PLUGIN_BASENAME );
            wp_die(
                esc_html__( 'WP Seguro requiere WordPress 6.0 o superior.', 'wp-secure' ),
                'Plugin Activation Error',
                array( 'back_link' => true )
            );
        }
    }

    /**
     * Crear tablas propias.
     */
    private static function create_tables(): void {
        WPS_Db_Schema::create_tables();

        $db = WPS_Db::get_instance();
        $db->set_setting( 'db_version', WPS_VERSION );
    }

    /**
     * Establecer valores de configuración por defecto.
     */
    private static function set_defaults(): void {
        $db = WPS_Db::get_instance();

        $defaults = array(
            // API.
            'ipinfo_api_key'       => '',
            'ipinfo_mode'          => 'api', // 'api' | 'local'.

            // Login.
            'login_max_attempts'   => 5,
            'login_block_minutes'  => 15,
            'login_escalate_after' => 3,
            'login_escalate_hours' => 24,
            'login_permanent_after'=> 3,
            'login_block_unknown_user' => true,
            'login_whitelist_only' => false,

            // XML-RPC.
            'xmlrpc_block_all'     => true,

            // REST API.
            'rest_block_user_enum' => true,
            'rest_disable_public'  => false,
            'rest_allowed_namespaces' => array(),

            // Rate limiting.
            'rate_pages_per_min'   => 60,
            'rate_total_per_min'   => 240,
            'rate_404_per_min'     => 10,
            'rate_login_per_hour'  => 5,
            'rate_xmlrpc_per_hour' => 0,
            'rate_block_minutes'   => 15,

            // Firewall layers.
            'firewall_layer0_enabled' => false,
            'firewall_layer1_enabled' => true,

            // Risk scoring — países de alto riesgo (lista vacía por defecto).
            'risky_countries'      => '',

            // Respuesta de bloqueo.
            'block_response_code'  => 403,
            'block_custom_message' => '',

            // Retención.
            'retention_traffic_days' => 30,
            'retention_events_days'  => 90,
            'retention_login_days'   => 7,

            // Rendimiento.
            'exclude_static_from_log' => true,

            // Notificaciones.
            'notify_email'             => get_option( 'admin_email' ),
            'notify_auto_blocks'       => false,
            'notify_new_login_ip'      => true,
            'notify_settings_change'   => true,
            'notify_daily_summary'     => true,
        );

        foreach ( $defaults as $key => $value ) {
            // Solo establecer si no existe.
            if ( null === $db->get_setting( $key ) ) {
                $db->set_setting( $key, $value );
            }
        }
    }

    /**
     * Proteger el directorio data/ con .htaccess.
     */
    private static function protect_data_dir(): void {
        $htaccess = WPS_DATA_DIR . '.htaccess';
        if ( ! file_exists( $htaccess ) ) {
            if ( ! is_dir( WPS_DATA_DIR ) ) {
                wp_mkdir_p( WPS_DATA_DIR );
            }
            file_put_contents( $htaccess, "Order deny,allow\nDeny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
        }
    }

    /**
     * Programar tareas de mantenimiento.
     */
    private static function schedule_maintenance(): void {
        WPS_Db_Maintenance::schedule();
    }

    /**
     * Instalar el MU-Plugin (Capa 1).
     *
     * Copia el archivo de firewall al directorio mu-plugins de WordPress.
     */
    public static function install_muplugin(): void {
        $mu_dir = WPMU_PLUGIN_DIR;
        if ( ! is_dir( $mu_dir ) ) {
            wp_mkdir_p( $mu_dir );
        }

        $source = WPS_INCLUDES_DIR . 'firewall/wps-firewall-muplugin.php';
        $dest   = $mu_dir . '/wps-firewall-muplugin.php';

        if ( is_file( $source ) ) {
            @copy( $source, $dest );
        }
    }

    /**
     * Eliminar el MU-Plugin (Capa 1).
     */
    public static function remove_muplugin(): void {
        $dest = WPMU_PLUGIN_DIR . '/wps-firewall-muplugin.php';
        if ( is_file( $dest ) ) {
            @unlink( $dest );
        }
    }

    /**
     * Crear el archivo inicial de IPs bloqueadas para Capa 0.
     */
    public static function create_blocked_ips_file(): void {
        $file = WPS_DATA_DIR . 'wps-blocked-ips.php';
        if ( ! is_file( $file ) ) {
            self::sync_blocked_ips_file();
        }
    }

    /**
     * Sincronizar el archivo de IPs bloqueadas con la BD.
     * Se llama periódicamente desde el cron de mantenimiento.
     */
    public static function sync_blocked_ips_file(): void {
        if ( ! is_dir( WPS_DATA_DIR ) ) {
            wp_mkdir_p( WPS_DATA_DIR );
        }

        $blocker = WPS_Blocker::get_instance();
        $db      = WPS_Db::get_instance();

        // Obtener IPs bloqueadas activas.
        $table    = WPS_Db_Schema::table( 'blocked_ips' );
        $blocked  = $db->get_results(
            "SELECT ip_address, cidr FROM {$table} WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > NOW())"
        );

        $ips   = array();
        $cidrs = array();

        foreach ( $blocked as $row ) {
            if ( ! empty( $row['ip_address'] ) ) {
                $ips[ $row['ip_address'] ] = 1;
            }
            if ( ! empty( $row['cidr'] ) ) {
                $cidrs[] = $row['cidr'];
            }
        }

        // Obtener whitelist.
        $wl_table  = WPS_Db_Schema::table( 'whitelist' );
        $whitelist_rows = $db->get_results(
            "SELECT ip_address FROM {$wl_table} WHERE ip_address IS NOT NULL"
        );

        $whitelist = array();
        foreach ( $whitelist_rows as $row ) {
            if ( ! empty( $row['ip_address'] ) ) {
                $whitelist[ $row['ip_address'] ] = 1;
            }
        }

        $data = array(
            'ips'       => $ips,
            'cidrs'     => array_values( $cidrs ),
            'whitelist' => $whitelist,
            'updated'   => time(),
        );

        $content = '<?php return ' . var_export( $data, true ) . ';' . "\n";

        $file = WPS_DATA_DIR . 'wps-blocked-ips.php';
        file_put_contents( $file, $content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions
    }
}
