<?php
/**
 * Bootstrap for WP Seguro tests.
 *
 * Loads WordPress test framework, then the plugin.
 */

// Attempt to load WP test framework.
$_tests_dir = getenv( 'WP_TESTS_DIR' );
if ( ! $_tests_dir ) {
	$_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
}

// Check if WP test framework is available.
if ( file_exists( $_tests_dir . '/includes/functions.php' ) ) {
	// WP test framework available → full integration mode.
	require_once $_tests_dir . '/includes/functions.php';

	tests_add_filter( 'muplugins_loaded', function () {
		require dirname( __DIR__ ) . '/wp-secure.php';
	} );

	require $_tests_dir . '/includes/bootstrap.php';
} else {
	// Standalone mode: load only the plugin classes for unit tests.
	define( 'ABSPATH', __DIR__ . '/wp-stubs/' );
	define( 'WPS_VERSION', '0.1.0' );
	define( 'WPS_PLUGIN_FILE', dirname( __DIR__ ) . '/wp-secure.php' );
	define( 'WPS_PLUGIN_DIR', dirname( __DIR__ ) . '/' );
	define( 'WPS_PLUGIN_URL', 'http://localhost/wordpress/wp-content/plugins/wp-secure/' );
	define( 'WPS_PLUGIN_BASENAME', 'wp-secure/wp-secure.php' );
	define( 'WPS_DATA_DIR', WPS_PLUGIN_DIR . 'data/' );
	define( 'WPS_INCLUDES_DIR', WPS_PLUGIN_DIR . 'includes/' );

	// Minimal WP function stubs for unit tests.
	if ( ! function_exists( 'sanitize_text_field' ) ) {
		function sanitize_text_field( $str ) { return trim( strip_tags( $str ) ); }
	}
	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = 'default' ) { return $text; }
	}
	if ( ! function_exists( 'esc_html__' ) ) {
		function esc_html__( $text, $domain = 'default' ) { return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' ); }
	}
	if ( ! function_exists( 'esc_attr' ) ) {
		function esc_attr( $text ) { return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' ); }
	}
	if ( ! function_exists( 'absint' ) ) {
		function absint( $value ) { return abs( intval( $value ) ); }
	}
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( $value ) { return is_string( $value ) ? stripslashes( $value ) : $value; }
	}

	// Autoloader.
	spl_autoload_register( function ( $class ) {
		if ( 0 !== strpos( $class, 'WPS_' ) ) return;
		$file = 'class-' . strtolower( str_replace( '_', '-', $class ) ) . '.php';
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
}
