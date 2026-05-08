<?php
/**
 * Plugin Name: WP Seguro
 * Plugin URI:  https://github.com/wp-secure
 * Description: Sistema de protección contra bots, spiders e intrusiones. Orientado a rendimiento y claridad.
 * Version:     0.2.9
 * Author:      Fabio Baccaglioni
 * Author URI:  https://github.com/fabiomb
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-secure
 * Domain Path: /languages
 * Requires at least: 6.0
 * Requires PHP: 7.4
 */

defined( 'ABSPATH' ) || exit;

/*──────────────────────────────────────────────
 * Constantes globales
 *──────────────────────────────────────────────*/
defined( 'WPS_VERSION' )         || define( 'WPS_VERSION', '0.2.7' );
defined( 'WPS_PLUGIN_FILE' )     || define( 'WPS_PLUGIN_FILE', __FILE__ );
defined( 'WPS_PLUGIN_DIR' )      || define( 'WPS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
defined( 'WPS_PLUGIN_URL' )      || define( 'WPS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
defined( 'WPS_PLUGIN_BASENAME' ) || define( 'WPS_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
defined( 'WPS_DATA_DIR' )        || define( 'WPS_DATA_DIR', WP_CONTENT_DIR . '/wps-data/' );
defined( 'WPS_INCLUDES_DIR' )    || define( 'WPS_INCLUDES_DIR', WPS_PLUGIN_DIR . 'includes/' );

/*──────────────────────────────────────────────
 * Autoloader sencillo
 *──────────────────────────────────────────────*/
spl_autoload_register( function ( $class ) {

    // Solo clases con prefijo WPS_
    if ( 0 !== strpos( $class, 'WPS_' ) ) {
        return;
    }

    // WPS_Admin_Dashboard → class-wps-admin-dashboard.php
    $file = 'class-' . strtolower( str_replace( '_', '-', $class ) ) . '.php';

    // Directorios donde buscar, en orden de prioridad
    $dirs = array(
        WPS_INCLUDES_DIR,
        WPS_INCLUDES_DIR . 'core/',
        WPS_INCLUDES_DIR . 'database/',
        WPS_INCLUDES_DIR . 'logging/',
        WPS_INCLUDES_DIR . 'admin/',
        WPS_INCLUDES_DIR . 'firewall/',
        WPS_INCLUDES_DIR . 'detectors/',
        WPS_INCLUDES_DIR . 'ipdb/',
    );

    foreach ( $dirs as $dir ) {
        $path = $dir . $file;
        if ( file_exists( $path ) ) {
            require_once $path;
            return;
        }
    }
} );

/*──────────────────────────────────────────────
 * Activación / Desactivación
 *──────────────────────────────────────────────*/
register_activation_hook( __FILE__, array( 'WPS_Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WPS_Deactivator', 'deactivate' ) );

/*──────────────────────────────────────────────
 * Arranque del plugin
 *──────────────────────────────────────────────*/
add_action( 'plugins_loaded', function () {
    load_plugin_textdomain( 'wp-secure', false, dirname( WPS_PLUGIN_BASENAME ) . '/languages' );
    WPS_Loader::get_instance()->init();
} );
