<?php
defined( 'ABSPATH' ) || exit;

/**
 * Actualización periódica de la base de datos IP (MMDB).
 *
 * Descarga la base de datos de ipinfo.io en formato MMDB.
 */
class WPS_Ipdb_Updater {

	/** @var WPS_Ipdb_Updater|null */
	private static $instance = null;

	/** @var WPS_Loader */
	private $loader;

	/** File name for the downloaded database. */
	const MMDB_FILENAME = 'country_asn.mmdb';

	/** Temporary file name during download. */
	const MMDB_TEMP_FILENAME = 'country_asn.mmdb.tmp';

	private function __construct() {
		$this->loader = WPS_Loader::get_instance();
	}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Download the MMDB database from ipinfo.io.
	 *
	 * @return array{success: bool, message: string}
	 */
	public function download(): array {
		$api_key = $this->loader->get_setting( 'ipinfo_api_key', '' );
		if ( empty( $api_key ) ) {
			return array(
				'success' => false,
				'message' => __( 'No se ha configurado la API key de ipinfo.io.', 'wp-secure' ),
			);
		}

		// Verify data directory exists and is writable.
		$data_dir = WPS_DATA_DIR;
		if ( ! is_dir( $data_dir ) ) {
			wp_mkdir_p( $data_dir );
		}

		if ( ! is_writable( $data_dir ) ) {
			return array(
				'success' => false,
				'message' => __( 'El directorio data/ no es escribible.', 'wp-secure' ),
			);
		}

		// ipinfo.io MMDB download URL for Country+ASN database.
		$url = sprintf(
			'https://ipinfo.io/data/free/country_asn.mmdb?token=%s',
			rawurlencode( $api_key )
		);

		$temp_path  = $data_dir . self::MMDB_TEMP_FILENAME;
		$final_path = $data_dir . self::MMDB_FILENAME;

		// Download to temp file.
		$response = wp_remote_get( $url, array(
			'timeout'  => 120,
			'stream'   => true,
			'filename' => $temp_path,
			'sslverify' => true,
		) );

		if ( is_wp_error( $response ) ) {
			$this->cleanup_temp( $temp_path );
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: error message */
					__( 'Error de descarga: %s', 'wp-secure' ),
					$response->get_error_message()
				),
			);
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$this->cleanup_temp( $temp_path );
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %d: HTTP status code */
					__( 'Error de descarga: código HTTP %d', 'wp-secure' ),
					$code
				),
			);
		}

		// Verify the file is a valid MMDB.
		if ( ! is_file( $temp_path ) || filesize( $temp_path ) < 1000 ) {
			$this->cleanup_temp( $temp_path );
			return array(
				'success' => false,
				'message' => __( 'El archivo descargado es demasiado pequeño o no es válido.', 'wp-secure' ),
			);
		}

		// Verify it can be read as MMDB.
		try {
			$reader = new WPS_Mmdb_Reader( $temp_path );
			$reader->close();
		} catch ( \RuntimeException $e ) {
			$this->cleanup_temp( $temp_path );
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: %s: error message */
					__( 'El archivo descargado no es un MMDB válido: %s', 'wp-secure' ),
					$e->getMessage()
				),
			);
		}

		// Replace the old file atomically.
		if ( is_file( $final_path ) ) {
			wp_delete_file( $final_path );
		}

		if ( ! rename( $temp_path, $final_path ) ) {
			$this->cleanup_temp( $temp_path );
			return array(
				'success' => false,
				'message' => __( 'No se pudo mover el archivo descargado a su ubicación final.', 'wp-secure' ),
			);
		}

		// Store the update timestamp.
		$this->loader->set_setting( 'ipdb_last_update', time() );

		$size_mb = round( filesize( $final_path ) / 1048576, 1 );

		return array(
			'success' => true,
			'message' => sprintf(
				/* translators: %s: file size in MB */
				__( 'Base de datos descargada correctamente (%s MB).', 'wp-secure' ),
				$size_mb
			),
		);
	}

	/**
	 * Get the timestamp of the last successful update.
	 */
	public function get_last_update(): int {
		return (int) $this->loader->get_setting( 'ipdb_last_update', 0 );
	}

	/**
	 * Check if an update is recommended (older than 30 days).
	 */
	public function needs_update(): bool {
		$last = $this->get_last_update();
		if ( 0 === $last ) {
			return true;
		}
		return ( time() - $last ) > ( 30 * DAY_IN_SECONDS );
	}

	/**
	 * Clean up temporary download file.
	 */
	private function cleanup_temp( string $path ): void {
		if ( is_file( $path ) ) {
			wp_delete_file( $path );
		}
	}
}
