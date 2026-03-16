<?php
defined( 'ABSPATH' ) || exit;

/**
 * Mantenimiento de base de datos.
 *
 * Purga de datos expirados, optimización de tablas.
 */
class WPS_Db_Maintenance {

    /**
     * Registrar tareas de cron.
     */
    public static function schedule(): void {
        if ( ! wp_next_scheduled( 'wps_daily_maintenance' ) ) {
            wp_schedule_event( time(), 'daily', 'wps_daily_maintenance' );
        }
        if ( ! wp_next_scheduled( 'wps_hourly_maintenance' ) ) {
            wp_schedule_event( time(), 'hourly', 'wps_hourly_maintenance' );
        }
    }

    /**
     * Eliminar tareas de cron.
     */
    public static function unschedule(): void {
        wp_clear_scheduled_hook( 'wps_daily_maintenance' );
        wp_clear_scheduled_hook( 'wps_hourly_maintenance' );
    }

    /**
     * Tareas diarias.
     */
    public static function daily(): void {
        $db = WPS_Db::get_instance();

        $traffic_days  = (int) $db->get_setting( 'retention_traffic_days', 30 );
        $events_days   = (int) $db->get_setting( 'retention_events_days', 90 );
        $login_days    = (int) $db->get_setting( 'retention_login_days', 7 );
        $blocks_days   = (int) $db->get_setting( 'retention_blocks_days', 30 );

        $traffic_table = WPS_Db_Schema::table( 'traffic_log' );
        $events_table  = WPS_Db_Schema::table( 'security_events' );
        $login_table   = WPS_Db_Schema::table( 'login_attempts' );
        $blocked_table = WPS_Db_Schema::table( 'blocked_ips' );

        // Purgar logs de tráfico.
        $db->query(
            "DELETE FROM {$traffic_table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $traffic_days
        );

        // Purgar eventos de seguridad.
        $db->query(
            "DELETE FROM {$events_table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $events_days
        );

        // Purgar intentos de login.
        $db->query(
            "DELETE FROM {$login_table} WHERE attempted_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $login_days
        );

        // Purgar bloqueos temporales ya cumplidos (expirados e inactivos).
        $db->query(
            "DELETE FROM {$blocked_table}
             WHERE is_active = 0
             AND expires_at IS NOT NULL
             AND expires_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $blocks_days
        );
    }

    /**
     * Tareas cada hora.
     */
    public static function hourly(): void {
        $db = WPS_Db::get_instance();

        // Purgar rate limits expirados (ventanas de más de 2 horas).
        $rate_table = WPS_Db_Schema::table( 'rate_limits' );
        $db->query(
            "DELETE FROM {$rate_table} WHERE window_start < DATE_SUB(NOW(), INTERVAL 2 HOUR)"
        );

        // Desactivar bloqueos temporales expirados.
        $blocked_table = WPS_Db_Schema::table( 'blocked_ips' );
        $db->query(
            "UPDATE {$blocked_table} SET is_active = 0 WHERE expires_at IS NOT NULL AND expires_at < NOW() AND is_active = 1"
        );

        // Sincronizar el archivo de IPs bloqueadas para Capa 0.
        WPS_Activator::sync_blocked_ips_file();
    }
}
