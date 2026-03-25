<?php
defined( 'ABSPATH' ) || exit;

/**
 * Esquema de base de datos del plugin.
 *
 * Todas las tablas usan prefijo {wpdb->prefix}wps_ para evitar colisiones.
 * No se utiliza wp_options para datos operativos.
 */
class WPS_Db_Schema {

    /**
     * Devuelve el nombre completo de una tabla del plugin.
     */
    public static function table( string $name ): string {
        global $wpdb;
        return $wpdb->prefix . 'wps_' . $name;
    }

    /**
     * Crea o actualiza todas las tablas del plugin mediante dbDelta.
     */
    public static function create_tables(): void {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $sql = array();

        // ── Configuración ──
        $table = self::table( 'settings' );
        $sql[] = "CREATE TABLE {$table} (
            setting_key varchar(100) NOT NULL,
            setting_value longtext NOT NULL,
            autoload tinyint(1) NOT NULL DEFAULT 1,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY  (setting_key)
        ) {$charset};";

        // ── IPs bloqueadas ──
        $table = self::table( 'blocked_ips' );
        $sql[] = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) DEFAULT NULL,
            ip_range_start varbinary(16) DEFAULT NULL,
            ip_range_end varbinary(16) DEFAULT NULL,
            cidr varchar(49) DEFAULT NULL,
            block_type varchar(30) NOT NULL,
            reason varchar(500) NOT NULL,
            blocked_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime DEFAULT NULL,
            hit_count int(10) unsigned NOT NULL DEFAULT 0,
            is_active tinyint(1) NOT NULL DEFAULT 1,
            PRIMARY KEY  (id),
            KEY idx_ip (ip_address),
            KEY idx_range (ip_range_start,ip_range_end),
            KEY idx_expires (expires_at),
            KEY idx_active (is_active,expires_at)
        ) {$charset};";

        // ── Países bloqueados ──
        $table = self::table( 'blocked_countries' );
        $sql[] = "CREATE TABLE {$table} (
            country_code char(2) NOT NULL,
            country_name varchar(100) NOT NULL,
            blocked_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            blocked_by varchar(100) NOT NULL DEFAULT 'admin',
            PRIMARY KEY  (country_code)
        ) {$charset};";

        // ── ASNs bloqueados ──
        $table = self::table( 'blocked_asns' );
        $sql[] = "CREATE TABLE {$table} (
            asn int(10) unsigned NOT NULL,
            asn_name varchar(255) NOT NULL,
            blocked_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            blocked_by varchar(100) NOT NULL DEFAULT 'admin',
            PRIMARY KEY  (asn)
        ) {$charset};";

        // ── Whitelist ──
        $table = self::table( 'whitelist' );
        $sql[] = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) DEFAULT NULL,
            cidr varchar(49) DEFAULT NULL,
            label varchar(255) NOT NULL,
            whitelist_type varchar(10) NOT NULL DEFAULT 'global',
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY idx_ip (ip_address),
            KEY idx_type (whitelist_type)
        ) {$charset};";

        // ── Log de tráfico ──
        $table = self::table( 'traffic_log' );
        $sql[] = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            country_code char(2) DEFAULT NULL,
            asn int(10) unsigned DEFAULT NULL,
            request_uri varchar(2048) NOT NULL,
            request_method varchar(10) NOT NULL,
            user_agent varchar(1024) DEFAULT NULL,
            referer varchar(2048) DEFAULT NULL,
            http_status smallint(5) unsigned DEFAULT NULL,
            is_human tinyint(1) DEFAULT NULL,
            visitor_type varchar(20) NOT NULL DEFAULT 'unknown',
            session_hash varchar(64) DEFAULT NULL,
            response_time_ms int(10) unsigned DEFAULT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY idx_ip_time (ip_address,created_at),
            KEY idx_created (created_at),
            KEY idx_type (visitor_type,created_at),
            KEY idx_session (session_hash,created_at),
            KEY idx_country (country_code,created_at)
        ) {$charset};";

        // ── Eventos de seguridad ──
        $table = self::table( 'security_events' );
        $sql[] = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            event_type varchar(40) NOT NULL,
            severity varchar(10) NOT NULL DEFAULT 'warning',
            ip_address varchar(45) DEFAULT NULL,
            country_code char(2) DEFAULT NULL,
            asn int(10) unsigned DEFAULT NULL,
            details text DEFAULT NULL,
            request_uri varchar(2048) DEFAULT NULL,
            user_agent varchar(1024) DEFAULT NULL,
            wp_user_id bigint(20) unsigned DEFAULT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY idx_type_time (event_type,created_at),
            KEY idx_severity_time (severity,created_at),
            KEY idx_ip_time (ip_address,created_at),
            KEY idx_created (created_at)
        ) {$charset};";

        // ── Intentos de login ──
        $table = self::table( 'login_attempts' );
        $sql[] = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(255) NOT NULL,
            user_exists tinyint(1) NOT NULL,
            success tinyint(1) NOT NULL DEFAULT 0,
            attempted_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY idx_ip_time (ip_address,attempted_at),
            KEY idx_user_time (username,attempted_at)
        ) {$charset};";

        // ── Rate limits ──
        $table = self::table( 'rate_limits' );
        $sql[] = "CREATE TABLE {$table} (
            ip_address varchar(45) NOT NULL,
            limit_type varchar(30) NOT NULL,
            window_start datetime NOT NULL,
            request_count int(10) unsigned NOT NULL DEFAULT 1,
            PRIMARY KEY  (ip_address,limit_type,window_start),
            KEY idx_window (window_start)
        ) {$charset};";

        // ── Reglas manuales personalizadas ──
        $table = self::table( 'custom_rules' );
        $sql[] = "CREATE TABLE {$table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            name varchar(255) NOT NULL,
            description varchar(500) DEFAULT NULL,
            conditions longtext NOT NULL,
            action_type varchar(30) NOT NULL,
            action_duration int(10) unsigned DEFAULT NULL,
            action_params text DEFAULT NULL,
            is_active tinyint(1) NOT NULL DEFAULT 1,
            priority int(10) unsigned NOT NULL DEFAULT 10,
            hit_count bigint(20) unsigned NOT NULL DEFAULT 0,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY idx_active_priority (is_active,priority)
        ) {$charset};";

        foreach ( $sql as $query ) {
            dbDelta( $query );
        }
    }

    /**
     * Elimina todas las tablas del plugin.
     */
    public static function drop_tables(): void {
        global $wpdb;

        $tables = array(
            'settings',
            'blocked_ips',
            'blocked_countries',
            'blocked_asns',
            'whitelist',
            'traffic_log',
            'security_events',
            'login_attempts',
            'rate_limits',
            'custom_rules',
        );

        foreach ( $tables as $name ) {
            $table = self::table( $name );
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
        }
    }

    /**
     * Verifica que todas las tablas existan.
     */
    public static function tables_exist(): bool {
        global $wpdb;

        $tables = array(
            'settings',
            'blocked_ips',
            'blocked_countries',
            'blocked_asns',
            'whitelist',
            'traffic_log',
            'security_events',
            'login_attempts',
            'rate_limits',
            'custom_rules',
        );

        foreach ( $tables as $name ) {
            $table = self::table( $name );
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $result = $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" );
            if ( $result !== $table ) {
                return false;
            }
        }

        return true;
    }
}
