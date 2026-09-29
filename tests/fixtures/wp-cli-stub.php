<?php
/**
 * Doble mínimo de WP-CLI para los tests de WPS_CLI.
 *
 * `error()` lanza una excepción en lugar de terminar el proceso; los mensajes
 * y las tablas quedan registrados para verificarlos.
 */

namespace {
	if ( ! class_exists( 'WP_CLI' ) ) {
		class WP_CLI {
			public static $log = array();

			public static function success( $message ) { self::$log[] = array( 'success', $message ); }
			public static function warning( $message ) { self::$log[] = array( 'warning', $message ); }
			public static function line( $message = '' ) { self::$log[] = array( 'line', $message ); }
			public static function error( $message ) {
				self::$log[] = array( 'error', $message );
				throw new \RuntimeException( $message );
			}
			public static function last() { return end( self::$log ) ?: array( '', '' ); }
		}
	}
}

namespace WP_CLI\Utils {
	if ( ! function_exists( 'WP_CLI\Utils\format_items' ) ) {
		function format_items( $format, $items, $fields ) {
			$GLOBALS['wps_test_cli_items'] = array( 'format' => $format, 'items' => $items, 'fields' => $fields );
		}
	}
}
