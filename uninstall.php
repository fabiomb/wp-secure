<?php
/**
 * Desinstalación del plugin WP Seguro.
 *
 * Elimina todas las tablas y datos del plugin.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Cargar las clases necesarias.
require_once __DIR__ . '/includes/database/class-wps-db-schema.php';

// Eliminar tablas propias.
WPS_Db_Schema::drop_tables();

// Eliminar opciones de WordPress (solo las mínimas que usa el plugin).
delete_option( 'wps_version' );
delete_option( 'wps_activated' );

// Eliminar directorio data/.
$data_dir = __DIR__ . '/data/';
if ( is_dir( $data_dir ) ) {
    $files = glob( $data_dir . '*' );
    if ( $files ) {
        foreach ( $files as $file ) {
            if ( is_file( $file ) ) {
                unlink( $file );
            }
        }
    }
    rmdir( $data_dir );
}

// Limpiar crons.
wp_clear_scheduled_hook( 'wps_daily_maintenance' );
wp_clear_scheduled_hook( 'wps_hourly_maintenance' );
