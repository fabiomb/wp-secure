<?php
defined( 'ABSPATH' ) || exit;

/**
 * Chequeo de endurecimiento del sitio.
 *
 * Verifica la configuración que el firewall no puede cubrir: constantes de
 * wp-config.php, errores visibles, permisos, versión de PHP, listado de
 * directorios. Sólo informa y explica cómo corregir; no toca wp-config.php
 * ni la configuración del servidor.
 *
 * Las comprobaciones por HTTP (listado de directorios, debug.log) son
 * peticiones del sitio a sí mismo, sin servicios externos, y se guardan 12 h.
 */
class WPS_Hardening_Check {

	const PASS = 'pass';
	const WARN = 'warn';
	const FAIL = 'fail';
	const INFO = 'info';

	/** Resultado de las comprobaciones por HTTP. */
	const HTTP_CACHE = 'wps_hardening_http';

	/** Fin del soporte de seguridad de cada versión de PHP (php.net). */
	const PHP_EOL_DATES = array(
		'7.4' => '2022-11-28',
		'8.0' => '2023-11-26',
		'8.1' => '2025-12-31',
		'8.2' => '2026-12-31',
		'8.3' => '2027-12-31',
		'8.4' => '2028-12-31',
		'8.5' => '2029-12-31',
	);

	/** Aviso anticipado del fin de soporte de PHP. */
	const PHP_EOL_NOTICE = 180 * 86400;

	/** @var WPS_Loader */
	protected $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Ejecutar todas las comprobaciones.
	 *
	 * @param bool $fresh Repetir las comprobaciones por HTTP en vez de usar las guardadas.
	 * @return array[] Resultados: id, status, label, message, fix.
	 */
	public function run( bool $fresh = false ): array {
		$http = $fresh ? false : get_transient( self::HTTP_CACHE );
		if ( ! is_array( $http ) ) {
			$http = array(
				'directory_listing' => $this->check_directory_listing(),
				'debug_log'         => $this->check_debug_log(),
			);
			set_transient( self::HTTP_CACHE, $http, 12 * HOUR_IN_SECONDS );
		}

		return array(
			$this->check_file_edit(),
			$this->check_debug_display(),
			$http['debug_log'],
			$http['directory_listing'],
			$this->check_php_version(),
			$this->check_wp_config_permissions(),
			$this->check_admin_user(),
			$this->check_https(),
			$this->check_uploads_php(),
			$this->check_db_prefix(),
		);
	}

	/**
	 * Cantidad de resultados por estado.
	 *
	 * @param array[] $results Resultados de run().
	 * @return array<string, int>
	 */
	public static function counts( array $results ): array {
		$counts = array( self::FAIL => 0, self::WARN => 0, self::PASS => 0, self::INFO => 0 );
		foreach ( $results as $result ) {
			$counts[ $result['status'] ]++;
		}
		return $counts;
	}

	/*──────────────────────────────────────────────
	 * Comprobaciones
	 *──────────────────────────────────────────────*/

	public function check_file_edit(): array {
		$label = __( 'Editor de archivos del panel', 'wp-secure' );

		if ( $this->constant( 'DISALLOW_FILE_EDIT' ) || $this->constant( 'DISALLOW_FILE_MODS' ) ) {
			return self::result( 'file_edit', self::PASS, $label, __( 'Desactivado: nadie puede editar el código de plugins y temas desde el panel.', 'wp-secure' ) );
		}

		return self::result(
			'file_edit',
			self::WARN,
			$label,
			__( 'Activo. Quien tome una cuenta de administrador puede inyectar código en un plugin o tema desde el panel, sin FTP.', 'wp-secure' ),
			"define( 'DISALLOW_FILE_EDIT', true );"
		);
	}

	public function check_debug_display(): array {
		$label = __( 'Errores de PHP visibles', 'wp-secure' );

		if ( $this->errors_displayed() ) {
			return self::result(
				'debug_display',
				self::FAIL,
				$label,
				__( 'Los errores de PHP se muestran en las páginas: revelan rutas del servidor, versiones y detalles internos que ayudan a un atacante.', 'wp-secure' ),
				"define( 'WP_DEBUG_DISPLAY', false );\n@ini_set( 'display_errors', 0 );"
			);
		}

		if ( $this->constant( 'WP_DEBUG' ) ) {
			return self::result(
				'debug_display',
				self::WARN,
				$label,
				__( 'No se muestran, pero WP_DEBUG está activo. En producción conviene apagarlo.', 'wp-secure' ),
				"define( 'WP_DEBUG', false );"
			);
		}

		return self::result( 'debug_display', self::PASS, $label, __( 'No se muestran y WP_DEBUG está apagado.', 'wp-secure' ) );
	}

	public function check_debug_log(): array {
		$label = __( 'debug.log público', 'wp-secure' );
		$file  = WP_CONTENT_DIR . '/debug.log';

		if ( ! is_file( $file ) ) {
			return self::result( 'debug_log', self::PASS, $label, __( 'No hay wp-content/debug.log.', 'wp-secure' ) );
		}

		$response = $this->http_get( content_url( 'debug.log' ) );
		$fix      = __( 'Borrá el archivo y, si necesitás el log, guardalo fuera de la carpeta pública:', 'wp-secure' ) . "\ndefine( 'WP_DEBUG_LOG', '/ruta/fuera/de/public_html/debug.log' );";

		if ( null !== $response && 200 === $response['code'] ) {
			return self::result( 'debug_log', self::FAIL, $label, __( 'wp-content/debug.log se puede descargar: suele tener rutas, consultas y datos de usuarios.', 'wp-secure' ), $fix );
		}

		return self::result( 'debug_log', self::WARN, $label, __( 'Existe wp-content/debug.log. No se pudo descargar desde el propio sitio, pero conviene no dejarlo en la carpeta pública.', 'wp-secure' ), $fix );
	}

	/**
	 * Crea una carpeta temporal sin índice en uploads, la pide y se fija si el
	 * servidor lista su contenido. La carpeta se borra enseguida.
	 */
	public function check_directory_listing(): array {
		$label   = __( 'Listado de directorios', 'wp-secure' );
		$uploads = function_exists( 'wp_get_upload_dir' ) ? wp_get_upload_dir() : array();
		$fix     = __( 'Apache: agregá «Options -Indexes» al .htaccess de la raíz. nginx: «autoindex off;» en el bloque server.', 'wp-secure' );

		if ( empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) || ! wp_is_writable( $uploads['basedir'] ) ) {
			return self::result( 'directory_listing', self::INFO, $label, __( 'No se pudo comprobar: la carpeta de subidas no es escribible.', 'wp-secure' ), $fix );
		}

		$name = 'wps-listing-check-' . wp_generate_password( 12, false );
		$dir  = $uploads['basedir'] . '/' . $name;
		$file = 'wps-listing-check.txt';

		if ( ! @mkdir( $dir ) || false === @file_put_contents( $dir . '/' . $file, 'WP Seguro' ) ) { // phpcs:ignore
			@rmdir( $dir ); // phpcs:ignore
			return self::result( 'directory_listing', self::INFO, $label, __( 'No se pudo comprobar: no se pudo crear la carpeta de prueba.', 'wp-secure' ), $fix );
		}

		$response = $this->http_get( $uploads['baseurl'] . '/' . $name . '/' );

		@unlink( $dir . '/' . $file ); // phpcs:ignore
		@rmdir( $dir ); // phpcs:ignore

		if ( null === $response ) {
			return self::result( 'directory_listing', self::INFO, $label, __( 'No se pudo comprobar: el sitio no responde a peticiones hechas desde el propio servidor.', 'wp-secure' ), $fix );
		}

		if ( 200 === $response['code'] && false !== strpos( $response['body'], $file ) ) {
			return self::result( 'directory_listing', self::FAIL, $label, __( 'El servidor lista el contenido de las carpetas sin índice: cualquiera puede recorrer uploads, backups y archivos de plugins.', 'wp-secure' ), $fix );
		}

		return self::result( 'directory_listing', self::PASS, $label, __( 'El servidor no lista el contenido de las carpetas.', 'wp-secure' ) );
	}

	public function check_php_version(): array {
		$label   = __( 'Versión de PHP', 'wp-secure' );
		$version = $this->php_version();
		$branch  = implode( '.', array_slice( explode( '.', $version ), 0, 2 ) );
		$fix     = __( 'Pedile a tu hosting una versión de PHP con soporte de seguridad (o cambiala desde su panel).', 'wp-secure' );

		if ( ! isset( self::PHP_EOL_DATES[ $branch ] ) ) {
			return self::result( 'php_version', version_compare( $branch, '7.4', '<' ) ? self::FAIL : self::PASS, $label, sprintf( 'PHP %s.', $version ) );
		}

		$eol = strtotime( self::PHP_EOL_DATES[ $branch ] . ' 23:59:59 UTC' );
		$now = $this->timestamp();

		if ( $eol < $now ) {
			/* translators: 1: PHP version, 2: date */
			return self::result( 'php_version', self::FAIL, $label, sprintf( __( 'PHP %1$s dejó de recibir parches de seguridad el %2$s.', 'wp-secure' ), $version, self::PHP_EOL_DATES[ $branch ] ), $fix );
		}

		if ( $eol - $now < self::PHP_EOL_NOTICE ) {
			/* translators: 1: PHP version, 2: date */
			return self::result( 'php_version', self::WARN, $label, sprintf( __( 'PHP %1$s deja de recibir parches de seguridad el %2$s.', 'wp-secure' ), $version, self::PHP_EOL_DATES[ $branch ] ), $fix );
		}

		/* translators: 1: PHP version, 2: date */
		return self::result( 'php_version', self::PASS, $label, sprintf( __( 'PHP %1$s, con soporte de seguridad hasta el %2$s.', 'wp-secure' ), $version, self::PHP_EOL_DATES[ $branch ] ) );
	}

	public function check_wp_config_permissions(): array {
		$label = __( 'Permisos de wp-config.php', 'wp-secure' );
		$file  = $this->wp_config_path();

		if ( '' === $file ) {
			return self::result( 'wp_config_permissions', self::INFO, $label, __( 'No se encontró wp-config.php.', 'wp-secure' ) );
		}

		$perms = $this->file_permissions( $file );
		if ( null === $perms ) {
			return self::result( 'wp_config_permissions', self::INFO, $label, __( 'No aplica: el servidor no usa permisos de Unix.', 'wp-secure' ) );
		}

		$octal = sprintf( '%04o', $perms & 0777 );
		$fix   = 'chmod 640 ' . $file;

		if ( $perms & 0002 ) {
			/* translators: %s: permissions */
			return self::result( 'wp_config_permissions', self::FAIL, $label, sprintf( __( '%s: cualquier usuario del servidor puede modificarlo.', 'wp-secure' ), $octal ), $fix );
		}

		if ( $perms & 0004 ) {
			/* translators: %s: permissions */
			return self::result( 'wp_config_permissions', self::WARN, $label, sprintf( __( '%s: cualquier usuario del servidor puede leer las credenciales de la base de datos. Se recomienda 640, 600 o 400.', 'wp-secure' ), $octal ), $fix );
		}

		/* translators: %s: permissions */
		return self::result( 'wp_config_permissions', self::PASS, $label, sprintf( __( '%s: sólo el dueño y su grupo pueden leerlo.', 'wp-secure' ), $octal ) );
	}

	public function check_admin_user(): array {
		$label = __( 'Usuario «admin»', 'wp-secure' );
		$user  = $this->user_by_login( 'admin' );

		if ( ! $user ) {
			return self::result( 'admin_user', self::PASS, $label, __( 'No existe un usuario «admin».', 'wp-secure' ) );
		}

		if ( ! user_can( $user, 'manage_options' ) ) {
			return self::result( 'admin_user', self::INFO, $label, __( 'Existe un usuario «admin», pero no es administrador.', 'wp-secure' ) );
		}

		return self::result(
			'admin_user',
			self::WARN,
			$label,
			__( 'Hay un administrador llamado «admin»: es el primer nombre que prueban los ataques de contraseñas, así que sólo les falta adivinar la clave.', 'wp-secure' ),
			__( 'Creá un administrador con otro nombre, entrá con él y eliminá «admin» atribuyendo su contenido al nuevo usuario.', 'wp-secure' )
		);
	}

	public function check_https(): array {
		$label = __( 'HTTPS', 'wp-secure' );

		if ( 0 === strpos( $this->home_url(), 'https://' ) ) {
			return self::result( 'https', self::PASS, $label, __( 'El sitio usa HTTPS.', 'wp-secure' ) );
		}

		return self::result(
			'https',
			self::WARN,
			$label,
			__( 'El sitio no usa HTTPS: las contraseñas y las cookies de sesión viajan sin cifrar.', 'wp-secure' ),
			__( 'Instalá un certificado (la mayoría de los hostings lo ofrecen gratis) y cambiá las direcciones en Ajustes → Generales.', 'wp-secure' )
		);
	}

	public function check_uploads_php(): array {
		$label = __( 'PHP en la carpeta de subidas', 'wp-secure' );

		if ( $this->loader->get_setting( 'uploads_block_php', false ) ) {
			return self::result( 'uploads_php', self::PASS, $label, __( 'La ejecución de PHP en la carpeta de subidas está bloqueada.', 'wp-secure' ) );
		}

		return self::result(
			'uploads_php',
			self::WARN,
			$label,
			__( 'Un archivo PHP subido por un formulario o un plugin vulnerable se puede ejecutar.', 'wp-secure' ),
			__( 'Activá «PHP en uploads» en Configuración → Firewall Avanzado.', 'wp-secure' )
		);
	}

	public function check_db_prefix(): array {
		$label = __( 'Prefijo de tablas', 'wp-secure' );

		if ( 'wp_' !== $this->db_prefix() ) {
			return self::result( 'db_prefix', self::PASS, $label, __( 'Las tablas no usan el prefijo por defecto.', 'wp-secure' ) );
		}

		return self::result(
			'db_prefix',
			self::INFO,
			$label,
			__( 'Las tablas usan el prefijo por defecto «wp_». Sólo dificulta algunas inyecciones SQL automatizadas; cambiarlo en un sitio existente es delicado, así que conviene hacerlo en instalaciones nuevas.', 'wp-secure' )
		);
	}

	/*──────────────────────────────────────────────
	 * Entorno (se reemplaza en los tests)
	 *──────────────────────────────────────────────*/

	protected function constant( string $name ) {
		return defined( $name ) ? constant( $name ) : null;
	}

	/**
	 * ¿PHP muestra los errores en la salida? WordPress sólo toca display_errors
	 * con WP_DEBUG activo; si no, vale lo que diga php.ini.
	 */
	protected function errors_displayed(): bool {
		$value = strtolower( (string) ini_get( 'display_errors' ) );
		return in_array( $value, array( '1', 'on', 'yes', 'true', 'stdout' ), true );
	}

	protected function php_version(): string {
		return PHP_VERSION;
	}

	protected function timestamp(): int {
		return time();
	}

	protected function db_prefix(): string {
		global $wpdb;
		return isset( $wpdb->base_prefix ) ? (string) $wpdb->base_prefix : (string) ( $wpdb->prefix ?? '' );
	}

	protected function user_by_login( string $login ) {
		return get_user_by( 'login', $login );
	}

	protected function home_url(): string {
		return (string) home_url( '/' );
	}

	/**
	 * Ruta de wp-config.php, que puede estar un nivel arriba de WordPress.
	 */
	protected function wp_config_path(): string {
		if ( is_file( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}

		$parent = dirname( ABSPATH ) . '/';
		if ( is_file( $parent . 'wp-config.php' ) && ! is_file( $parent . 'wp-settings.php' ) ) {
			return $parent . 'wp-config.php';
		}

		return '';
	}

	/**
	 * Permisos de un archivo, o null donde no hay permisos de Unix (Windows).
	 */
	protected function file_permissions( string $file ): ?int {
		if ( '\\' === DIRECTORY_SEPARATOR ) {
			return null;
		}
		$perms = @fileperms( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return false === $perms ? null : $perms;
	}

	/**
	 * Petición del sitio a sí mismo.
	 *
	 * @return array{code: int, body: string}|null Null si no hubo respuesta.
	 */
	protected function http_get( string $url ): ?array {
		$response = wp_remote_get( $url, array(
			'timeout'     => 5,
			'redirection' => 0,
			'sslverify'   => false,
		) );

		if ( is_wp_error( $response ) ) {
			return null;
		}

		return array(
			'code' => (int) wp_remote_retrieve_response_code( $response ),
			'body' => (string) wp_remote_retrieve_body( $response ),
		);
	}

	private static function result( string $id, string $status, string $label, string $message, string $fix = '' ): array {
		return compact( 'id', 'status', 'label', 'message', 'fix' );
	}
}
