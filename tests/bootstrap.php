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
	if ( ! function_exists( 'current_user_can' ) ) {
		function current_user_can( $capability ) {
			return ! empty( $GLOBALS['wps_test_caps'][ $capability ] );
		}
	}
	if ( ! function_exists( 'is_user_logged_in' ) ) {
		function is_user_logged_in() { return ! empty( $GLOBALS['wps_test_caps'] ); }
	}
	if ( ! function_exists( 'wp_parse_url' ) ) {
		function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
	}
	if ( ! function_exists( 'get_transient' ) ) {
		function get_transient( $key ) { return $GLOBALS['wps_test_transients'][ $key ] ?? false; }
	}
	if ( ! function_exists( 'set_transient' ) ) {
		function set_transient( $key, $value, $ttl = 0 ) {
			$GLOBALS['wps_test_transients'][ $key ] = $value;
			return true;
		}
	}
	if ( ! function_exists( 'delete_transient' ) ) {
		function delete_transient( $key ) {
			unset( $GLOBALS['wps_test_transients'][ $key ] );
			return true;
		}
	}
	if ( ! function_exists( 'wp_json_encode' ) ) {
		function wp_json_encode( $data, $options = 0, $depth = 512 ) { return json_encode( $data, $options, $depth ); }
	}
	if ( ! function_exists( 'get_user_by' ) ) {
		function get_user_by( $field, $value ) { return $GLOBALS['wps_test_users'][ $value ] ?? false; }
	}
	// HTTP: la respuesta la fija cada test en $GLOBALS['wps_test_http_response']
	// (array con 'code' y 'body', o un WP_Error simulado con 'error').
	if ( ! function_exists( 'wp_remote_get' ) ) {
		function wp_remote_get( $url, $args = array() ) {
			$GLOBALS['wps_test_http_calls'] = ( $GLOBALS['wps_test_http_calls'] ?? 0 ) + 1;
			return $GLOBALS['wps_test_http_response'] ?? array( 'code' => 200, 'body' => '{}' );
		}
	}
	if ( ! function_exists( 'is_wp_error' ) ) {
		function is_wp_error( $thing ) { return is_array( $thing ) && isset( $thing['error'] ); }
	}
	if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
		function wp_remote_retrieve_response_code( $response ) { return $response['code'] ?? ''; }
	}
	if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
		function wp_remote_retrieve_body( $response ) { return $response['body'] ?? ''; }
	}
	if ( ! function_exists( 'wp_normalize_path' ) ) {
		function wp_normalize_path( $path ) { return str_replace( '\\', '/', $path ); }
	}
	if ( ! function_exists( 'current_time' ) ) {
		function current_time( $type, $gmt = 0 ) {
			return 'mysql' === $type ? gmdate( 'Y-m-d H:i:s' ) : time();
		}
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}
	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'ARRAY_A' ) ) {
		define( 'ARRAY_A', 'ARRAY_A' );
	}
	if ( ! defined( 'OBJECT' ) ) {
		define( 'OBJECT', 'OBJECT' );
	}

	/**
	 * Doble mínimo de $wpdb.
	 *
	 * Devuelve resultados vacíos en vez de fallar, para que el código que
	 * consulta la base de datos tome sus valores por defecto durante los
	 * tests unitarios.
	 */
	class WPS_Test_Wpdb {
		public $prefix     = 'wp_';
		public $last_error = '';
		public $insert_id  = 0;

		/** @var string[] Queries ejecutadas, para verificar costo de acceso a BD. */
		public $queries = array();

		/** @var array[] Inserts ejecutados: array( tabla, datos ). */
		public $inserts = array();

		/** @var array[] Argumentos pasados a prepare(), en orden. */
		public $prepared_args = array();

		public function reset_queries() {
			$this->queries       = array();
			$this->inserts       = array();
			$this->prepared_args = array();
		}

		public function prepare( $query, ...$args ) {
			$this->prepared_args[] = $args;
			return $query;
		}
		public function get_var( $query = null ) { $this->queries[] = $query; return null; }
		public function get_row( $query = null, $output = null ) { $this->queries[] = $query; return null; }
		public function get_results( $query = null, $output = null ) { $this->queries[] = $query; return array(); }
		public function get_col( $query = null, $column = 0 ) { $this->queries[] = $query; return array(); }
		public function query( $query ) { $this->queries[] = $query; return 0; }
		public function insert( $table, $data, $format = null ) {
			$this->inserts[] = array( $table, $data );
			return false;
		}
		public function update( $table, $data, $where, $format = null, $where_format = null ) { return false; }
		public function delete( $table, $where, $where_format = null ) { return false; }
		public function esc_like( $text ) { return $text; }
		public function get_charset_collate() { return ''; }
	}

	$GLOBALS['wpdb'] = new WPS_Test_Wpdb();

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
