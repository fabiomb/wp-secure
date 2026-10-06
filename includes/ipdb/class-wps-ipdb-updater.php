<?php
defined( 'ABSPATH' ) || exit;

/**
 * Descarga y actualización de las bases de geolocalización locales (MMDB).
 *
 * Actúa sobre el proveedor activo:
 * - ipinfo.io: base Country+ASN en un solo archivo MMDB.
 * - MaxMind GeoLite2: bases Country y ASN, cada una dentro de un .tar.gz.
 *
 * El mantenimiento diario actualiza las bases del proveedor activo cuando
 * está en modo local y la copia descargada falta o es vieja.
 */
class WPS_Ipdb_Updater {

	/** @var WPS_Ipdb_Updater|null */
	private static $instance = null;

	/** @var WPS_Loader */
	private $loader;

	/** File name for the downloaded ipinfo.io database. */
	const MMDB_FILENAME = 'country_asn.mmdb';

	/** Temporary file name during download. */
	const MMDB_TEMP_FILENAME = 'country_asn.mmdb.tmp';

	/** Archivo temporal del .tar.gz de MaxMind. */
	const MAXMIND_ARCHIVE_TEMP = 'maxmind-download.tar.gz.tmp';

	/** Tamaño máximo aceptado de una base de MaxMind extraída (64 MB). */
	const MAXMIND_MAX_BYTES = 67108864;

	/** Ajuste con la fecha de la última descarga completa, por proveedor. */
	const LAST_UPDATE_KEYS = array(
		'ipinfo'  => 'ipdb_last_update',
		'maxmind' => 'maxmind_last_update',
	);

	/**
	 * Días a partir de los que se recomienda actualizar, por proveedor.
	 * MaxMind publica GeoLite2 dos veces por semana y su licencia pide no
	 * usar copias de más de 30 días.
	 */
	const MAX_AGE_DAYS = array(
		'ipinfo'  => 30,
		'maxmind' => 7,
	);

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
	 * Descargar las bases locales del proveedor indicado (por defecto, el activo).
	 *
	 * @param string|null $provider 'ipinfo', 'maxmind' o null para el activo.
	 * @return array{success: bool, message: string}
	 */
	public function download( ?string $provider = null ): array {
		$provider = $provider ?? WPS_Ipdb_Manager::get_instance()->get_provider();

		if ( WPS_Ipdb_Manager::PROVIDER_MAXMIND === $provider ) {
			return $this->download_maxmind();
		}

		if ( WPS_Ipdb_Manager::PROVIDER_IPINFO === $provider ) {
			return $this->download_ipinfo();
		}

		return array(
			'success' => false,
			'message' => __( 'La geolocalización está desactivada: elegí un proveedor (ipinfo.io o MaxMind) antes de descargar una base de datos.', 'wp-secure' ),
		);
	}

	/**
	 * Actualización programada (mantenimiento diario).
	 *
	 * Sólo descarga si el proveedor activo usa la base local, tiene
	 * credenciales y la copia actual falta o es vieja. Nunca toca al
	 * proveedor inactivo.
	 */
	public static function scheduled_update(): void {
		$manager  = WPS_Ipdb_Manager::get_instance();
		$provider = $manager->get_provider();

		if ( WPS_Ipdb_Manager::PROVIDER_NONE === $provider
			|| 'local' !== $manager->get_mode( $provider )
			|| ! $manager->has_credentials( $provider ) ) {
			return;
		}

		$updater = self::get_instance();
		if ( $manager->is_local_complete( $provider ) && ! $updater->needs_update( $provider ) ) {
			return;
		}

		$updater->download( $provider );
	}

	/**
	 * Get the timestamp of the last successful update.
	 */
	public function get_last_update( ?string $provider = null ): int {
		$provider = $provider ?? WPS_Ipdb_Manager::get_instance()->get_provider();
		if ( ! isset( self::LAST_UPDATE_KEYS[ $provider ] ) ) {
			return 0;
		}
		return (int) $this->loader->get_setting( self::LAST_UPDATE_KEYS[ $provider ], 0 );
	}

	/**
	 * Check if an update is recommended.
	 */
	public function needs_update( ?string $provider = null ): bool {
		$provider = $provider ?? WPS_Ipdb_Manager::get_instance()->get_provider();
		if ( ! isset( self::MAX_AGE_DAYS[ $provider ] ) ) {
			return false;
		}

		$last = $this->get_last_update( $provider );
		if ( 0 === $last ) {
			return true;
		}
		return ( time() - $last ) > ( self::MAX_AGE_DAYS[ $provider ] * DAY_IN_SECONDS );
	}

	/**
	 * Directorio de datos listo para escribir; null si no lo es.
	 */
	private function prepare_data_dir(): ?string {
		$data_dir = WPS_Ipdb_Manager::get_instance()->get_data_dir();
		if ( ! is_dir( $data_dir ) ) {
			wp_mkdir_p( $data_dir );
		}

		return is_writable( $data_dir ) ? $data_dir : null;
	}

	/*──────────────────────────────────────────────
	 * ipinfo.io
	 *──────────────────────────────────────────────*/

	/**
	 * Download the MMDB database from ipinfo.io.
	 *
	 * @return array{success: bool, message: string}
	 */
	private function download_ipinfo(): array {
		$api_key = trim( (string) $this->loader->get_setting( 'ipinfo_api_key', '' ) );
		if ( empty( $api_key ) ) {
			return array(
				'success' => false,
				'message' => __( 'No se ha configurado la API key de ipinfo.io.', 'wp-secure' ),
			);
		}

		// Verify data directory exists and is writable.
		$data_dir = $this->prepare_data_dir();
		if ( null === $data_dir ) {
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

		$error = $this->install_mmdb( $temp_path, $final_path, '' );
		if ( null !== $error ) {
			return array(
				'success' => false,
				'message' => $error,
			);
		}

		// Store the update timestamp.
		$this->loader->set_setting( self::LAST_UPDATE_KEYS['ipinfo'], time() );

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

	/*──────────────────────────────────────────────
	 * MaxMind GeoLite2
	 *──────────────────────────────────────────────*/

	/**
	 * Descargar GeoLite2-Country y GeoLite2-ASN.
	 *
	 * @return array{success: bool, message: string}
	 */
	private function download_maxmind(): array {
		$account = trim( (string) $this->loader->get_setting( 'maxmind_account_id', '' ) );
		$license = trim( (string) $this->loader->get_setting( 'maxmind_license_key', '' ) );
		if ( '' === $account || '' === $license ) {
			return array(
				'success' => false,
				'message' => __( 'Faltan el Account ID o la License Key de MaxMind. Configuralos en Configuración → Geolocalización.', 'wp-secure' ),
			);
		}

		$data_dir = $this->prepare_data_dir();
		if ( null === $data_dir ) {
			return array(
				'success' => false,
				'message' => __( 'El directorio data/ no es escribible.', 'wp-secure' ),
			);
		}

		$done   = array();
		$errors = array();
		foreach ( WPS_Ipdb_Maxmind::editions() as $edition => $filename ) {
			list( $error, $account_error ) = $this->download_maxmind_edition( $edition, $data_dir, $filename, $account, $license );

			if ( null === $error ) {
				$done[] = $edition;
				continue;
			}

			$errors[] = $edition . ': ' . $error;

			// Credenciales rechazadas o cuota agotada: la otra edición fallaría igual.
			if ( $account_error ) {
				break;
			}
		}

		if ( ! empty( $errors ) ) {
			$message = implode( ' ', $errors );
			if ( ! empty( $done ) ) {
				$message .= ' ' . sprintf(
					/* translators: %s: database names */
					__( 'Se descargó correctamente: %s.', 'wp-secure' ),
					implode( ', ', $done )
				);
			}
			return array(
				'success' => false,
				'message' => $message,
			);
		}

		$this->loader->set_setting( self::LAST_UPDATE_KEYS['maxmind'], time() );

		return array(
			'success' => true,
			'message' => __( 'Bases GeoLite2-Country y GeoLite2-ASN de MaxMind descargadas correctamente.', 'wp-secure' ),
		);
	}

	/**
	 * Descargar una edición de GeoLite2 e instalarla.
	 *
	 * MaxMind responde a la petición autenticada con una redirección a una
	 * URL firmada en otro dominio (R2/CDN). Esa segunda petición se hace sin
	 * la cabecera Authorization: las credenciales sólo se envían a MaxMind.
	 *
	 * @return array{0: string|null, 1: bool} [mensaje de error o null si se
	 *                                         instaló, si el error es de la cuenta].
	 */
	private function download_maxmind_edition( string $edition, string $data_dir, string $filename, string $account, string $license ): array {
		$archive    = $data_dir . self::MAXMIND_ARCHIVE_TEMP;
		$final_path = $data_dir . $filename;
		$temp       = $final_path . '.tmp';

		$response = wp_remote_get( sprintf( WPS_Ipdb_Maxmind::DOWNLOAD_URL, rawurlencode( $edition ) ), array(
			'timeout'     => 30,
			'redirection' => 0,
			'sslverify'   => true,
			'headers'     => array(
				'Authorization' => WPS_Ipdb_Maxmind::auth_header( $account, $license ),
			),
		) );

		if ( is_wp_error( $response ) ) {
			return array(
				sprintf(
					/* translators: %s: error message */
					__( 'Error de conexión con MaxMind: %s', 'wp-secure' ),
					$response->get_error_message()
				),
				false,
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( $code >= 300 && $code < 400 ) {
			$location = wp_remote_retrieve_header( $response, 'location' );
			if ( is_array( $location ) ) {
				$location = end( $location );
			}
			$location = (string) $location;
			if ( 0 !== strpos( $location, 'https://' ) ) {
				return array( __( 'MaxMind devolvió una redirección inválida.', 'wp-secure' ), false );
			}

			// Descarga del archivo firmado, sin credenciales.
			$download = wp_remote_get( $location, array(
				'timeout'     => 300,
				'redirection' => 3,
				'stream'      => true,
				'filename'    => $archive,
				'sslverify'   => true,
			) );

			if ( is_wp_error( $download ) ) {
				$this->cleanup_temp( $archive );
				return array(
					sprintf(
						/* translators: %s: error message */
						__( 'Error de descarga: %s', 'wp-secure' ),
						$download->get_error_message()
					),
					false,
				);
			}

			$download_code = (int) wp_remote_retrieve_response_code( $download );
			if ( 200 !== $download_code ) {
				$this->cleanup_temp( $archive );
				return array(
					sprintf(
						/* translators: %d: HTTP status code */
						__( 'Error de descarga: código HTTP %d', 'wp-secure' ),
						$download_code
					),
					false,
				);
			}
		} elseif ( 200 === $code ) {
			// Sin redirección: el archivo viene en la misma respuesta.
			if ( false === file_put_contents( $archive, (string) wp_remote_retrieve_body( $response ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
				return array( __( 'No se pudo escribir el archivo temporal.', 'wp-secure' ), false );
			}
		} else {
			return array( self::explain_maxmind_error( $code ), in_array( $code, array( 401, 403, 429 ), true ) );
		}

		// Extraer el .mmdb del .tar.gz.
		try {
			WPS_Tar_Reader::extract( $archive, $temp, '.mmdb', self::MAXMIND_MAX_BYTES );
		} catch ( \RuntimeException $e ) {
			$this->cleanup_temp( $archive );
			$this->cleanup_temp( $temp );
			return array(
				sprintf(
					/* translators: %s: error message */
					__( 'No se pudo extraer la base de datos: %s', 'wp-secure' ),
					$e->getMessage()
				),
				false,
			);
		}
		$this->cleanup_temp( $archive );

		// El tipo declarado en la base es "GeoLite2-Country" o "GeoLite2-ASN".
		$expected = WPS_Ipdb_Maxmind::EDITION_ASN === $edition ? 'ASN' : 'Country';

		return array( $this->install_mmdb( $temp, $final_path, $expected ), false );
	}

	/**
	 * Mensaje para los errores HTTP de la descarga de MaxMind.
	 */
	public static function explain_maxmind_error( int $code ): string {
		switch ( $code ) {
			case 401:
				return __( 'MaxMind rechazó las credenciales: revisá el Account ID y la License Key.', 'wp-secure' );
			case 403:
				return __( 'MaxMind no autorizó la descarga: verificá que la License Key esté activa y que la cuenta tenga acceso a GeoLite2.', 'wp-secure' );
			case 429:
				return __( 'MaxMind limitó las descargas de esta cuenta por hoy. Probá de nuevo más tarde.', 'wp-secure' );
		}

		return sprintf(
			/* translators: %d: HTTP status code */
			__( 'Error de descarga: código HTTP %d', 'wp-secure' ),
			$code
		);
	}

	/*──────────────────────────────────────────────
	 * Instalación
	 *──────────────────────────────────────────────*/

	/**
	 * Validar un MMDB descargado y reemplazar el archivo final.
	 *
	 * @param string $temp_path     Archivo descargado.
	 * @param string $final_path    Destino.
	 * @param string $expected_type Texto que debe figurar en el tipo de la base
	 *                              ('' = no se verifica).
	 * @return string|null Mensaje de error, o null si se instaló.
	 */
	private function install_mmdb( string $temp_path, string $final_path, string $expected_type ): ?string {
		// Verify the file is a valid MMDB.
		if ( ! is_file( $temp_path ) || filesize( $temp_path ) < 1000 ) {
			$this->cleanup_temp( $temp_path );
			return __( 'El archivo descargado es demasiado pequeño o no es válido.', 'wp-secure' );
		}

		// Verify it can be read as MMDB.
		try {
			$reader = new WPS_Mmdb_Reader( $temp_path );
			$type   = $reader->get_type();
			$reader->close();
		} catch ( \RuntimeException $e ) {
			$this->cleanup_temp( $temp_path );
			return sprintf(
				/* translators: %s: error message */
				__( 'El archivo descargado no es un MMDB válido: %s', 'wp-secure' ),
				$e->getMessage()
			);
		}

		if ( '' !== $expected_type && false === stripos( $type, $expected_type ) ) {
			$this->cleanup_temp( $temp_path );
			return sprintf(
				/* translators: %s: database type */
				__( 'La base descargada no es del tipo esperado (%s).', 'wp-secure' ),
				$type
			);
		}

		// Replace the old file.
		if ( is_file( $final_path ) ) {
			wp_delete_file( $final_path );
		}

		if ( ! rename( $temp_path, $final_path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			$this->cleanup_temp( $temp_path );
			return __( 'No se pudo mover el archivo descargado a su ubicación final.', 'wp-secure' );
		}

		return null;
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
