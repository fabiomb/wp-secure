<?php
defined( 'ABSPATH' ) || exit;

/**
 * Exportación de logs a CSV y configuración a JSON.
 *
 * Genera archivos CSV descargables para eventos de seguridad
 * y tráfico, con filtros por rango de fechas.
 * Permite exportar e importar la configuración completa del plugin en formato JSON.
 */
class WPS_Admin_Export {

	/**
	 * Exportar la configuración completa del plugin como JSON.
	 */
	public static function export_config(): void {
		$loader   = WPS_Loader::get_instance();
		$settings = $loader->get_all_settings();

		// Excluir datos sensibles que no deben exportarse.
		$exclude_keys = array( 'db_version', 'wizard_completed' );
		foreach ( $exclude_keys as $key ) {
			unset( $settings[ $key ] );
		}

		// Obtener reglas personalizadas.
		$rules_engine = WPS_Custom_Rules::get_instance();
		$rules_data   = $rules_engine->get_all( 1, 1000 );
		$rules        = array();
		foreach ( $rules_data['items'] as $rule ) {
			unset( $rule['id'], $rule['hit_count'], $rule['created_at'], $rule['updated_at'] );
			$rules[] = $rule;
		}

		$export = array(
			'plugin'    => 'wp-secure',
			'version'   => WPS_VERSION,
			'exported'  => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'settings'  => $settings,
			'rules'     => $rules,
		);

		$filename = 'wp-seguro-config-' . gmdate( 'Y-m-d-His' ) . '.json';

		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		echo wp_json_encode( $export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
		exit;
	}

	/**
	 * Importar configuración desde datos JSON.
	 *
	 * @param array $data Datos decodificados del JSON.
	 * @return array{success: bool, message: string, imported_settings: int, imported_rules: int}
	 */
	public static function import_config( array $data ): array {
		// Validar estructura.
		if ( empty( $data['plugin'] ) || 'wp-secure' !== $data['plugin'] ) {
			return array(
				'success'           => false,
				'message'           => __( 'Archivo de configuración inválido. No corresponde a WP Seguro.', 'wp-secure' ),
				'imported_settings' => 0,
				'imported_rules'    => 0,
			);
		}

		$loader            = WPS_Loader::get_instance();
		$imported_settings = 0;
		$imported_rules    = 0;

		// Importar settings.
		if ( ! empty( $data['settings'] ) && is_array( $data['settings'] ) ) {
			$exclude_keys = array( 'db_version', 'wizard_completed' );
			foreach ( $data['settings'] as $key => $value ) {
				$key = sanitize_text_field( $key );
				if ( in_array( $key, $exclude_keys, true ) || '' === $key ) {
					continue;
				}
				if ( is_string( $value ) ) {
					$value = sanitize_text_field( $value );
				}
				$loader->set_setting( $key, $value );
				$imported_settings++;
			}
		}

		// Importar reglas personalizadas.
		if ( ! empty( $data['rules'] ) && is_array( $data['rules'] ) ) {
			$rules_engine = WPS_Custom_Rules::get_instance();
			foreach ( $data['rules'] as $rule ) {
				if ( empty( $rule['name'] ) || empty( $rule['conditions'] ) || empty( $rule['action_type'] ) ) {
					continue;
				}
				$result = $rules_engine->create( $rule );
				if ( $result ) {
					$imported_rules++;
				}
			}
		}

		return array(
			'success'           => true,
			'message'           => sprintf(
				__( 'Importación completada: %1$d ajustes y %2$d reglas importadas.', 'wp-secure' ),
				$imported_settings,
				$imported_rules
			),
			'imported_settings' => $imported_settings,
			'imported_rules'    => $imported_rules,
		);
	}

	/**
	 * Exportar eventos de seguridad a CSV.
	 *
	 * @param string $date_from Fecha inicio (Y-m-d).
	 * @param string $date_to   Fecha fin (Y-m-d).
	 * @param string $severity  Filtro de severidad ('' = todas).
	 * @param string $event_type Filtro de tipo ('' = todos).
	 */
	public static function export_events( string $date_from = '', string $date_to = '', string $severity = '', string $event_type = '' ): void {
		$db    = WPS_Db::get_instance();
		$table = WPS_Db_Schema::table( 'security_events' );

		$where  = array( '1=1' );
		$params = array();

		if ( $date_from ) {
			$where[]  = 'created_at >= %s';
			$params[] = $date_from . ' 00:00:00';
		}
		if ( $date_to ) {
			$where[]  = 'created_at <= %s';
			$params[] = $date_to . ' 23:59:59';
		}
		if ( $severity ) {
			$where[]  = 'severity = %s';
			$params[] = $severity;
		}
		if ( $event_type ) {
			$where[]  = 'event_type = %s';
			$params[] = $event_type;
		}

		$where_sql = implode( ' AND ', $where );
		$query     = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY created_at DESC LIMIT 10000";

		if ( ! empty( $params ) ) {
			$query = $db->prepare( $query, ...$params );
		}

		$results = $db->get_results( $query );

		$headers = array(
			__( 'ID', 'wp-secure' ),
			__( 'Fecha', 'wp-secure' ),
			__( 'Tipo', 'wp-secure' ),
			__( 'Severidad', 'wp-secure' ),
			__( 'IP', 'wp-secure' ),
			__( 'País', 'wp-secure' ),
			__( 'ASN', 'wp-secure' ),
			__( 'URI', 'wp-secure' ),
			__( 'User-Agent', 'wp-secure' ),
			__( 'Detalles', 'wp-secure' ),
		);

		$rows = array();
		foreach ( $results as $row ) {
			$rows[] = array(
				$row['id'],
				$row['created_at'],
				$row['event_type'],
				$row['severity'],
				$row['ip_address'] ?? '',
				$row['country_code'] ?? '',
				$row['asn'] ?? '',
				$row['request_uri'] ?? '',
				$row['user_agent'] ?? '',
				$row['details'] ?? '',
			);
		}

		self::send_csv( 'wp-seguro-eventos', $headers, $rows );
	}

	/**
	 * Exportar tráfico a CSV.
	 *
	 * @param string $date_from Fecha inicio (Y-m-d).
	 * @param string $date_to   Fecha fin (Y-m-d).
	 * @param string $visitor_type Filtro de tipo ('' = todos).
	 */
	public static function export_traffic( string $date_from = '', string $date_to = '', string $visitor_type = '' ): void {
		$db    = WPS_Db::get_instance();
		$table = WPS_Db_Schema::table( 'traffic_log' );

		$where  = array( '1=1' );
		$params = array();

		if ( $date_from ) {
			$where[]  = 'created_at >= %s';
			$params[] = $date_from . ' 00:00:00';
		}
		if ( $date_to ) {
			$where[]  = 'created_at <= %s';
			$params[] = $date_to . ' 23:59:59';
		}
		if ( $visitor_type ) {
			$where[]  = 'visitor_type = %s';
			$params[] = $visitor_type;
		}

		$where_sql = implode( ' AND ', $where );
		$query     = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY created_at DESC LIMIT 10000";

		if ( ! empty( $params ) ) {
			$query = $db->prepare( $query, ...$params );
		}

		$results = $db->get_results( $query );

		$headers = array(
			__( 'ID', 'wp-secure' ),
			__( 'Fecha', 'wp-secure' ),
			__( 'IP', 'wp-secure' ),
			__( 'País', 'wp-secure' ),
			__( 'ASN', 'wp-secure' ),
			__( 'Método', 'wp-secure' ),
			__( 'URI', 'wp-secure' ),
			__( 'Status', 'wp-secure' ),
			__( 'Tipo', 'wp-secure' ),
			__( 'User-Agent', 'wp-secure' ),
			__( 'Referer', 'wp-secure' ),
			__( 'Tiempo (ms)', 'wp-secure' ),
		);

		$rows = array();
		foreach ( $results as $row ) {
			$rows[] = array(
				$row['id'],
				$row['created_at'],
				$row['ip_address'],
				$row['country_code'] ?? '',
				$row['asn'] ?? '',
				$row['request_method'],
				$row['request_uri'],
				$row['http_status'] ?? '',
				$row['visitor_type'],
				$row['user_agent'] ?? '',
				$row['referer'] ?? '',
				$row['response_time_ms'] ?? '',
			);
		}

		self::send_csv( 'wp-seguro-trafico', $headers, $rows );
	}

	/**
	 * Enviar el archivo CSV como descarga directa.
	 */
	private static function send_csv( string $prefix, array $headers, array $rows ): void {
		$filename = $prefix . '-' . gmdate( 'Y-m-d-His' ) . '.csv';

		// Headers HTTP.
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		header( 'Cache-Control: no-cache, no-store, must-revalidate' );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		$output = fopen( 'php://output', 'w' );

		// BOM para Excel.
		fprintf( $output, chr( 0xEF ) . chr( 0xBB ) . chr( 0xBF ) );

		// Encabezados.
		fputcsv( $output, $headers );

		// Filas.
		foreach ( $rows as $row ) {
			fputcsv( $output, $row );
		}

		fclose( $output );
		exit;
	}
}
