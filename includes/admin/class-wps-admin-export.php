<?php
defined( 'ABSPATH' ) || exit;

/**
 * Exportación de logs a CSV.
 *
 * Genera archivos CSV descargables para eventos de seguridad
 * y tráfico, con filtros por rango de fechas.
 */
class WPS_Admin_Export {

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
