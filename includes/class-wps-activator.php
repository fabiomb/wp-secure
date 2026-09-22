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
        self::migrate_data_dir();
        self::protect_data_dir();
        self::schedule_maintenance();
        self::install_muplugin();
        self::install_prepend_loader();
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
     *
     * Sólo completa las claves que faltan. Se llama al activar y en cada
     * migración de versión, para que los ajustes nuevos existan también en
     * instalaciones actualizadas (si no, cada petición los busca en la BD).
     */
    public static function set_defaults(): void {
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
            'login_unknown_user_threshold' => 3,
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
            'ipv6_block_prefix'    => 64,

            // Firewall layers.
            'firewall_layer0_enabled' => false,
            'firewall_layer1_enabled' => true,

            // Motor de riesgo. Arranca apagado: los puntajes por defecto nunca
            // se calibraron contra tráfico real, así que se enciende primero en
            // modo sombra y se pasa a 'enforce' con datos del propio sitio.
            'risk_engine_mode'     => 'off',
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
     * Ruta del cargador de la Capa 0, que es a donde debe apuntar
     * `auto_prepend_file`.
     */
    public static function prepend_loader_path(): string {
        return WPS_DATA_DIR . 'wps-firewall-loader.php';
    }

    /**
     * Instalar el cargador estable de la Capa 0.
     *
     * `auto_prepend_file` no debe apuntar dentro de la carpeta del plugin:
     * durante una actualización WordPress la borra y la vuelve a copiar, y si
     * el plugin se elimina o se renombra (el procedimiento habitual para
     * recuperar el acceso), PHP no encuentra el archivo y *cada* petición del
     * sitio termina en error fatal, incluido wp-admin. El cargador vive en
     * wp-content/wps-data/, que sobrevive a las actualizaciones, e incluye el
     * firewall sólo si existe.
     */
    public static function install_prepend_loader(): bool {
        if ( ! is_dir( WPS_DATA_DIR ) ) {
            wp_mkdir_p( WPS_DATA_DIR );
        }

        $content = self::build_prepend_loader( WPS_INCLUDES_DIR . 'firewall/wps-firewall-prepend.php' );
        $file    = self::prepend_loader_path();

        if ( is_file( $file ) && file_get_contents( $file ) === $content ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
            return true;
        }

        return self::write_file_atomically( $file, $content );
    }

    /**
     * Contenido del cargador de la Capa 0.
     *
     * @param string $prepend_path Ruta absoluta al firewall del plugin.
     */
    public static function build_prepend_loader( string $prepend_path ): string {
        $lines = array(
            '<?php',
            '/**',
            ' * WP Seguro — cargador de la Capa 0. Archivo generado; no editar.',
            ' *',
            ' * Apuntar auto_prepend_file a este archivo, no al del plugin. Si el plugin',
            ' * se está actualizando o ya no está, no hace nada en lugar de provocar un',
            ' * error fatal en todo el sitio.',
            ' */',
            '( static function () {',
            "\t" . '$prepend = ' . var_export( $prepend_path, true ) . ';',
            "\t" . 'if ( is_file( $prepend ) ) {',
            "\t\t" . 'include_once $prepend;',
            "\t" . '}',
            '} )();',
        );

        return implode( "\n", $lines ) . "\n";
    }

    /**
     * ¿`auto_prepend_file` apunta directamente al firewall dentro del plugin?
     */
    public static function prepend_points_into_plugin(): bool {
        $current = (string) ini_get( 'auto_prepend_file' );
        if ( '' === $current ) {
            return false;
        }

        return false !== strpos( wp_normalize_path( $current ), 'firewall/wps-firewall-prepend.php' );
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
     * Callback para upgrader_process_complete.
     * Regenera el archivo de Capa 0 después de actualizar este plugin.
     *
     * @param WP_Upgrader $upgrader Instancia del actualizador.
     * @param array        $hook_extra Información sobre la actualización.
     */
    public static function on_upgrade_complete( $upgrader, $hook_extra ): void {
        if ( 'plugin' !== ( $hook_extra['type'] ?? '' ) ) {
            return;
        }

        $our_basename = plugin_basename( WPS_PLUGIN_FILE );
        $plugins      = array();

        if ( 'update' === ( $hook_extra['action'] ?? '' ) ) {
            // Bulk update → array de plugins.
            if ( ! empty( $hook_extra['plugins'] ) ) {
                $plugins = (array) $hook_extra['plugins'];
            }
            // Single update → plugin field.
            if ( ! empty( $hook_extra['plugin'] ) ) {
                $plugins[] = $hook_extra['plugin'];
            }
        }

        if ( in_array( $our_basename, $plugins, true ) ) {
            self::migrate_data_dir();
            self::protect_data_dir();
            self::sync_blocked_ips_file();
            self::install_muplugin();
            self::install_prepend_loader();
        }
    }

    /**
     * Migrar archivos de datos desde la ubicación antigua (plugin/data/)
     * a la nueva ubicación (wp-content/wps-data/).
     *
     * Se ejecuta en upgrade y en activación para cubrir ambos escenarios.
     */
    public static function migrate_data_dir(): void {
        $old_dir = WPS_PLUGIN_DIR . 'data/';
        $new_dir = WPS_DATA_DIR; // wp-content/wps-data/

        // Si la carpeta nueva ya tiene el archivo, no hay nada que migrar.
        if ( is_file( $new_dir . 'wps-blocked-ips.php' ) ) {
            return;
        }

        // Crear la carpeta nueva si no existe.
        if ( ! is_dir( $new_dir ) ) {
            wp_mkdir_p( $new_dir );
        }

        // Archivos a migrar desde la ubicación antigua.
        $files_to_migrate = array(
            'wps-blocked-ips.php',
            'country_asn.mmdb',
            'wps-firewall.log',
        );

        foreach ( $files_to_migrate as $filename ) {
            $old_path = $old_dir . $filename;
            $new_path = $new_dir . $filename;

            if ( is_file( $old_path ) && ! is_file( $new_path ) ) {
                @copy( $old_path, $new_path );
                @unlink( $old_path );
            }
        }
    }

    /**
     * Sincronizar el archivo de IPs bloqueadas con la BD.
     * Se llama periódicamente desde el cron de mantenimiento.
     */
    public static function sync_blocked_ips_file(): void {
        $file = WPS_DATA_DIR . 'wps-blocked-ips.php';

        // Con la Capa 0 desactivada no se mantiene el archivo de datos, y se
        // elimina el que hubiera: dejarlo desactualizado haría que un prepend
        // todavía configurado bloqueara con una lista vieja.
        if ( ! WPS_Loader::get_instance()->is_layer_enabled( 0 ) ) {
            if ( is_file( $file ) ) {
                @unlink( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
            }
            return;
        }

        if ( ! is_dir( WPS_DATA_DIR ) ) {
            wp_mkdir_p( WPS_DATA_DIR );
        }

        $db = WPS_Db::get_instance();

        // Obtener IPs bloqueadas activas.
        $table    = WPS_Db_Schema::table( 'blocked_ips' );
        $blocked  = $db->get_results(
            "SELECT ip_address, cidr, expires_at FROM {$table} WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())"
        );

        // Sólo la whitelist global: las entradas de tipo login eximen del
        // detector de login, no de un bloqueo de IP.
        $wl_table       = WPS_Db_Schema::table( 'whitelist' );
        $whitelist_rows = $db->get_results(
            "SELECT ip_address, cidr FROM {$wl_table} WHERE whitelist_type = 'global'"
        );

        $data    = self::build_blocked_ips_data( $blocked, $whitelist_rows, time() );
        $content = '<?php return ' . var_export( $data, true ) . ';' . "\n";

        self::write_file_atomically( $file, $content );
    }

    /**
     * Armar el contenido del archivo de la Capa 0.
     *
     * Cada IP o CIDR bloqueado lleva su vencimiento como timestamp (0 si es
     * permanente): la Capa 0 no tiene base de datos y, sin ese dato, un
     * bloqueo de 15 minutos seguía vigente hasta la siguiente regeneración.
     *
     * @param array $blocked   Filas con ip_address, cidr y expires_at (UTC).
     * @param array $whitelist Filas con ip_address y cidr.
     * @param int   $now       Timestamp de generación.
     */
    public static function build_blocked_ips_data( array $blocked, array $whitelist, int $now ): array {
        $ips   = array();
        $cidrs = array();

        foreach ( $blocked as $row ) {
            $expires = empty( $row['expires_at'] ) ? 0 : (int) strtotime( $row['expires_at'] . ' UTC' );

            if ( ! empty( $row['ip_address'] ) ) {
                $ips[ $row['ip_address'] ] = self::merge_expiry( $ips[ $row['ip_address'] ] ?? null, $expires );
            }
            if ( ! empty( $row['cidr'] ) ) {
                $cidrs[ $row['cidr'] ] = self::merge_expiry( $cidrs[ $row['cidr'] ] ?? null, $expires );
            }
        }

        $whitelist_ips   = array();
        $whitelist_cidrs = array();

        foreach ( $whitelist as $row ) {
            if ( ! empty( $row['ip_address'] ) ) {
                $whitelist_ips[ $row['ip_address'] ] = 1;
            }
            if ( ! empty( $row['cidr'] ) ) {
                $whitelist_cidrs[] = $row['cidr'];
            }
        }

        return array(
            'ips'             => $ips,
            'cidrs'           => $cidrs,
            'whitelist'       => $whitelist_ips,
            'whitelist_cidrs' => array_values( array_unique( $whitelist_cidrs ) ),
            'updated'         => $now,
        );
    }

    /**
     * Combinar vencimientos de dos bloqueos de la misma IP: gana el más largo.
     */
    private static function merge_expiry( ?int $current, int $expires ): int {
        if ( null === $current ) {
            return $expires;
        }
        if ( 0 === $current || 0 === $expires ) {
            return 0;
        }
        return max( $current, $expires );
    }

    /**
     * Escribir un archivo PHP que otra petición puede estar incluyendo.
     *
     * Se escribe en un temporal y se renombra: el rename es atómico, así que
     * la Capa 0 lee la versión anterior o la nueva, nunca una a medio escribir
     * (que daría un ParseError en cada petición). Después se invalida OPcache,
     * que con validate_timestamps desactivado serviría el archivo viejo.
     */
    public static function write_file_atomically( string $file, string $content ): bool {
        $tmp = $file . '.' . uniqid( 'tmp', true );

        if ( false === @file_put_contents( $tmp, $content, LOCK_EX ) ) { // phpcs:ignore
            return false;
        }

        if ( ! @rename( $tmp, $file ) ) { // phpcs:ignore
            @unlink( $tmp ); // phpcs:ignore
            return false;
        }

        if ( function_exists( 'opcache_invalidate' ) ) {
            @opcache_invalidate( $file, true ); // phpcs:ignore
        }

        return true;
    }
}
