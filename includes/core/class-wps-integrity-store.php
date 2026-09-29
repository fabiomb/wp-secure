<?php
defined( 'ABSPATH' ) || exit;

/**
 * Almacenamiento de la referencia de integridad de archivos.
 *
 * Una fila por archivo vigilado, con el hash de referencia y su estado:
 * `ok`, `modified`, `added` o `deleted`. Separado de WPS_File_Integrity para
 * poder probar la lógica sin base de datos.
 */
class WPS_Integrity_Store {

	/** Filas por INSERT al tomar una referencia completa. */
	const BATCH = 200;

	private function table(): string {
		return WPS_Db_Schema::table( 'file_integrity' );
	}

	/**
	 * Filas de un área, indexadas por path_hash.
	 *
	 * @return array<string, array>
	 */
	public function rows_for_area( string $area ): array {
		$rows = WPS_Db::get_instance()->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT path_hash, path, file_hash, status FROM {$this->table()} WHERE area = %s",
			$area
		);

		return array_column( $rows, null, 'path_hash' );
	}

	/**
	 * Insertar filas en lotes.
	 *
	 * @param array[] $rows Filas con path_hash, path, area, file_hash, size, status, detected_at, checked_at.
	 */
	public function insert_many( array $rows ): void {
		global $wpdb;

		foreach ( array_chunk( $rows, self::BATCH ) as $chunk ) {
			$placeholders = array();
			$values       = array();

			foreach ( $chunk as $row ) {
				$placeholders[] = '(%s, %s, %s, %s, %d, %s, ' . ( null === $row['detected_at'] ? 'NULL' : '%s' ) . ', %s)';
				array_push( $values, $row['path_hash'], $row['path'], $row['area'], $row['file_hash'], $row['size'], $row['status'] );
				if ( null !== $row['detected_at'] ) {
					$values[] = $row['detected_at'];
				}
				$values[] = $row['checked_at'];
			}

			// phpcs:ignore WordPress.DB.PreparedSQL
			$wpdb->query( $wpdb->prepare(
				"REPLACE INTO {$this->table()} (path_hash, path, area, file_hash, size, status, detected_at, checked_at) VALUES " . implode( ', ', $placeholders ),
				$values
			) );
		}
	}

	/**
	 * @param array $fields Campos a actualizar.
	 */
	public function update( string $path_hash, array $fields ): void {
		WPS_Db::get_instance()->update( 'file_integrity', $fields, array( 'path_hash' => $path_hash ) );
	}

	/**
	 * @param string[] $path_hashes
	 */
	public function delete( array $path_hashes ): void {
		foreach ( $path_hashes as $path_hash ) {
			WPS_Db::get_instance()->delete( 'file_integrity', array( 'path_hash' => $path_hash ) );
		}
	}

	public function delete_area( string $area ): void {
		WPS_Db::get_instance()->delete( 'file_integrity', array( 'area' => $area ) );
	}

	/**
	 * Borrar las filas de áreas que ya no existen (plugins o temas eliminados).
	 *
	 * @param string[] $areas Áreas vigentes.
	 */
	public function delete_areas_except( array $areas ): void {
		if ( ! $areas ) {
			return;
		}

		global $wpdb;
		$placeholders = implode( ', ', array_fill( 0, count( $areas ), '%s' ) );

		// phpcs:ignore WordPress.DB.PreparedSQL
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$this->table()} WHERE area NOT IN ({$placeholders})", $areas ) );
	}

	/**
	 * Archivos con cambios sin aceptar.
	 *
	 * @param string|null $area Filtrar por área.
	 * @return array[]
	 */
	public function changes( ?string $area = null ): array {
		$db = WPS_Db::get_instance();

		if ( null !== $area ) {
			return $db->get_results(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT path_hash, path, area, status, detected_at FROM {$this->table()} WHERE status <> 'ok' AND area = %s ORDER BY detected_at DESC",
				$area
			);
		}

		return $db->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT path_hash, path, area, status, detected_at FROM {$this->table()} WHERE status <> 'ok' ORDER BY detected_at DESC LIMIT 1000"
		);
	}

	public function count_files(): int {
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) WPS_Db::get_instance()->get_var( "SELECT COUNT(*) FROM {$this->table()} WHERE status <> 'deleted'" );
	}
}
