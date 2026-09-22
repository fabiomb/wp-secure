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

// Eliminar opciones de WordPress.
delete_option( 'wps_version' );
delete_option( 'wps_activated' );
delete_option( 'wps_unsafe_mode' );
delete_option( 'wps_block_digest' );

// Eliminar transients propios (cache de geolocalización y de verificación
// de crawlers): uno por IP, pueden ser miles de filas en wp_options.
global $wpdb;
$wpdb->query(
	"DELETE FROM {$wpdb->options}
	 WHERE option_name LIKE '\\_transient\\_wps\\_%'
	    OR option_name LIKE '\\_transient\\_timeout\\_wps\\_%'"
);

// MU-Plugin (Capa 1). La desactivación ya lo quita; se repite por si el
// plugin se eliminó sin desactivarse.
$wps_muplugin = WPMU_PLUGIN_DIR . '/wps-firewall-muplugin.php';
if ( is_file( $wps_muplugin ) ) {
	@unlink( $wps_muplugin ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
}

// Datos en wp-content/wps-data/ (y en la ubicación anterior, dentro del plugin).
//
// El cargador de la Capa 0 se conserva a propósito: si auto_prepend_file sigue
// apuntando a él, borrarlo dejaría a todo el sitio en error fatal. Sin el
// plugin no hace nada; se elimina a mano después de quitar la directiva.
foreach ( array( WP_CONTENT_DIR . '/wps-data/', __DIR__ . '/data/' ) as $wps_data_dir ) {
	if ( ! is_dir( $wps_data_dir ) ) {
		continue;
	}

	foreach ( (array) scandir( $wps_data_dir ) as $wps_name ) {
		$wps_file = $wps_data_dir . $wps_name;
		if ( is_file( $wps_file ) && 'wps-firewall-loader.php' !== $wps_name ) {
			@unlink( $wps_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
	}

	@rmdir( $wps_data_dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- falla si quedó el cargador.
}

// Limpiar crons.
wp_clear_scheduled_hook( 'wps_daily_maintenance' );
wp_clear_scheduled_hook( 'wps_hourly_maintenance' );
