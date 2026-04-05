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
		$api_key = trim( $this->loader->get_setting( 'ipinfo_api_key', '' ) );
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
		// Token va tanto en query string como en Authorization header para
		// que funcione aunque ipinfo.io redirija a un CDN sin query string.
		$url = sprintf(
			'https://ipinfo.io/data/free/country_asn.mmdb?token=%s',
			rawurlencode( $api_key )
		);

		$temp_path  = $data_dir . self::MMDB_TEMP_FILENAME;
		$final_path = $data_dir . self::MMDB_FILENAME;

		// Paso 1: HEAD sin stream para verificar el token antes de descargar.
		// Esto detecta 401/403 sin escribir basura en el archivo temporal.
		$head = wp_remote_head( $url, array(
			'timeout'     => 15,
			'redirection' => 5,
			'sslverify'   => true,
			'headers'     => array(
				'Authorization' => 'Bearer ' . $api_key,
			),
		) );

		if ( ! is_wp_error( $head ) ) {
			$head_code = (int) wp_remote_retrieve_response_code( $head );
			if ( 401 === $head_code || 403 === $head_code ) {
				return array(
					'success' => false,
					'message' => $this->explain_auth_error( $head_code, wp_remote_retrieve_body( $head ) ),
				);
			}
		}

		// Paso 2: Descarga real al archivo temporal.
		$response = wp_remote_get( $url, array(
			'timeout'     => 120,
			'redirection' => 5,
			'stream'      => true,
			'filename'    => $temp_path,
			'sslverify'   => true,
			'headers'     => array(
				'Authorization' => 'Bearer ' . $api_key,
			),
		) );

		if ( is_wp_error( $response ) ) {
			$this->cleanup_temp( $temp_path );
			$error_msg = $response->get_error_message();

			// En localhost, el error más común es SSL. Reintentar sin verificación.
			if ( false !== strpos( $error_msg, 'SSL' ) || false !== strpos( $error_msg, 'certificate' ) ) {
				$response = wp_remote_get( $url, array(
					'timeout'     => 120,
					'redirection' => 5,
					'stream'      => true,
					'filename'    => $temp_path,
					'sslverify'   => false,
					'headers'     => array(
						'Authorization' => 'Bearer ' . $api_key,
					),
				) );

				if ( is_wp_error( $response ) ) {
					$this->cleanup_temp( $temp_path );
					return array(
						'success' => false,
						'message' => sprintf(
							/* translators: %s: error message */
							__( 'Error de conexión: %s', 'wp-secure' ),
							$response->get_error_message()
						),
					);
				}
			} else {
				return array(
					'success' => false,
					'message' => sprintf(
						/* translators: %s: error message */
						__( 'Error de descarga: %s', 'wp-secure' ),
						$error_msg
					),
				);
			}
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$this->cleanup_temp( $temp_path );

			if ( 401 === $code || 403 === $code ) {
				// Con stream:true el body no está disponible; usar mensaje explicativo.
				return array(
					'success' => false,
					'message' => $this->explain_auth_error( $code, '' ),
				);
			}

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

	/**
	 * Devolver un mensaje de error explicativo para 401/403 de ipinfo.io.
	 *
	 * ipinfo.io devuelve 401 cuando:
	 * - El token es inválido o tiene espacios extra.
	 * - El plan no incluye descarga de bases de datos MMDB.
	 * - La cuenta requiere activar "Database Downloads" en el panel.
	 *
	 * @param int    $code HTTP status code (401 or 403).
	 * @param string $body Response body (puede estar vacío con stream:true).
	 * @return string Mensaje de error para mostrar al usuario.
	 */
	private function explain_auth_error( int $code, string $body ): string {
		// Intentar extraer mensaje de ipinfo.io del body JSON.
		$remote_message = '';
		if ( ! empty( $body ) ) {
			$decoded = json_decode( $body, true );
			if ( isset( $decoded['error']['message'] ) ) {
				$remote_message = $decoded['error']['message'];
			} elseif ( isset( $decoded['message'] ) ) {
				$remote_message = $decoded['message'];
			} elseif ( is_string( $decoded ) ) {
				$remote_message = $decoded;
			}
		}

		$hint = implode( ' ', array(
			__( 'Verifica que:', 'wp-secure' ),
			'(1) ' . __( 'La API key no tenga espacios extra.', 'wp-secure' ),
			'(2) ' . __( 'Tu cuenta de ipinfo.io tiene habilitado "Database Downloads" (panel → Account → Downloads).', 'wp-secure' ),
			'(3) ' . __( 'El plan incluye descarga de bases de datos MMDB (el plan gratuito requiere registro en ipinfo.io/account/data-downloads).', 'wp-secure' ),
		) );

		if ( $remote_message ) {
			return sprintf(
				/* translators: 1: HTTP code, 2: remote message, 3: hint */
				__( 'Error %1$d de ipinfo.io: "%2$s". %3$s', 'wp-secure' ),
				$code,
				$remote_message,
				$hint
			);
		}

		return sprintf(
			/* translators: 1: HTTP code, 2: hint */
			__( 'Error %1$d: Token no autorizado para descargar bases de datos. %2$s', 'wp-secure' ),
			$code,
			$hint
		);
	}
}
