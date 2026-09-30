<?php
defined( 'ABSPATH' ) || exit;

/**
 * PHP en la carpeta de subidas: aviso y bloqueo de ejecución.
 *
 * La carpeta de subidas sólo debería tener medios. Un archivo PHP ahí es casi
 * siempre un webshell que entró por un formulario o un plugin vulnerable, y
 * ejecutarlo es el paso que convierte esa subida en el control del sitio.
 *
 * - Una vez por día busca archivos que el servidor podría ejecutar (también
 *   con doble extensión, como `foto.php.jpg`) y `.htaccess`/`.user.ini` que
 *   habiliten PHP, y avisa de los nuevos. A diferencia del monitor de
 *   integridad, lo que ya estaba en el primer escaneo también se avisa.
 * - Opcionalmente escribe en `uploads/.htaccess` reglas que niegan los
 *   archivos PHP (Apache y LiteSpeed). En nginx lo hace la Capa 0 o una regla
 *   del servidor (ver la documentación).
 */
class WPS_Uploads_Guard {

	/** Archivos encontrados, revisados y hora del último escaneo. */
	const OPTION = 'wps_uploads_php';

	/** Archivos que el servidor podría ejecutar como PHP, también con doble extensión. */
	const EXEC_PATTERN = '/\.(php\d*|phtml|phar|pht|phps)(\.|$)/i';

	/**
	 * Directivas que hacen ejecutar PHP o inyectan código en cada petición.
	 *
	 * Las reglas de protección de otros plugins (`php_flag engine 0`,
	 * `AddHandler cgi-script .php`) no coinciden.
	 */
	const CONFIG_PATTERNS = array(
		'/\b(AddHandler|SetHandler|AddType|ForceType)\s+\S*(php|proxy:)/i',
		'/\bengine\s*[=\s]\s*"?(on|1|true)\b/i',
		'/\bauto_(prepend|append)_file\b/i',
	);

	/** Máximo de archivos que se guardan y se listan. */
	const MAX_FILES = 200;

	/** Tamaño máximo de un PHP que se analiza para descartarlo como inofensivo. */
	const INERT_MAX_BYTES = 4096;

	/** Reglas para `uploads/.htaccess` (Apache 2.2 y 2.4, LiteSpeed). */
	const RULES = "# BEGIN WP Seguro\n"
		. "# Impide ejecutar PHP en la carpeta de subidas.\n"
		. "<FilesMatch \"\\.(?i:php[0-9]*|phtml|phar|pht|phps)(\\.|$)\">\n"
		. "\t<IfModule mod_authz_core.c>\n"
		. "\t\tRequire all denied\n"
		. "\t</IfModule>\n"
		. "\t<IfModule !mod_authz_core.c>\n"
		. "\t\tOrder allow,deny\n"
		. "\t\tDeny from all\n"
		. "\t</IfModule>\n"
		. "</FilesMatch>\n"
		. "# END WP Seguro\n";

	/** Bloque propio dentro de un .htaccess que puede tener reglas de otros. */
	const RULES_BLOCK = '/# BEGIN WP Seguro\R.*?# END WP Seguro\R?/s';

	/** @var WPS_Loader */
	private $loader;

	/** @var string|null Carpeta fijada (tests). */
	private $dir = null;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		if ( $this->loader->get_setting( 'integrity_enabled', true ) ) {
			add_action( 'wps_daily_maintenance', array( $this, 'scan' ) );
		}
	}

	public function set_dir( string $dir ): void {
		$this->dir = $dir;
	}

	/**
	 * Carpeta de subidas, sin barra final y con barras normales; '' si no existe.
	 */
	public static function uploads_dir(): string {
		if ( ! function_exists( 'wp_get_upload_dir' ) ) {
			return '';
		}

		$uploads = wp_get_upload_dir();
		$dir     = empty( $uploads['basedir'] ) ? false : realpath( $uploads['basedir'] );

		return false === $dir ? '' : rtrim( str_replace( '\\', '/', $dir ), '/' );
	}

	/*──────────────────────────────────────────────
	 * Búsqueda
	 *──────────────────────────────────────────────*/

	/**
	 * Archivos sospechosos de una carpeta.
	 *
	 * @param string $dir       Carpeta a recorrer.
	 * @param bool   $truncated Se marca si hubo más de MAX_FILES.
	 * @return array<string, array> Ruta => [reason (php|config), hash].
	 */
	public static function find( string $dir, ?bool &$truncated = false ): array {
		$truncated = false;
		$found     = array();

		if ( ! is_dir( $dir ) ) {
			return $found;
		}

		$files = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::LEAVES_ONLY,
			\RecursiveIteratorIterator::CATCH_GET_CHILD
		);

		foreach ( $files as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}

			$reason = self::reason( $file->getPathname(), $file->getFilename() );
			if ( null === $reason ) {
				continue;
			}

			if ( count( $found ) >= self::MAX_FILES ) {
				$truncated = true;
				break;
			}

			$path           = str_replace( '\\', '/', $file->getPathname() );
			$found[ $path ] = array(
				'reason' => $reason,
				'hash'   => (string) @md5_file( $file->getPathname() ), // phpcs:ignore WordPress.PHP.NoSilencedErrors
			);
		}

		ksort( $found );
		return $found;
	}

	/**
	 * Por qué un archivo es sospechoso, o null si no lo es.
	 */
	public static function reason( string $path, string $name ): ?string {
		if ( '.htaccess' === $name || '.user.ini' === $name ) {
			return self::enables_php( (string) @file_get_contents( $path ) ) ? 'config' : null; // phpcs:ignore
		}

		if ( ! preg_match( self::EXEC_PATTERN, $name ) ) {
			return null;
		}

		// El «Silence is golden» que algunos plugins dejan en sus carpetas.
		if ( @filesize( $path ) <= self::INERT_MAX_BYTES && self::is_inert_php( (string) @file_get_contents( $path ) ) ) { // phpcs:ignore
			return null;
		}

		return 'php';
	}

	/**
	 * ¿Un .htaccess o .user.ini habilita PHP o inyecta código?
	 */
	public static function enables_php( string $config ): bool {
		foreach ( self::CONFIG_PATTERNS as $pattern ) {
			if ( preg_match( $pattern, $config ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * ¿Un PHP no hace nada? Sólo etiquetas, comentarios, espacios y HTML.
	 *
	 * Se analiza con el tokenizer de PHP y no con expresiones regulares: un
	 * comentario de línea termina en `?>`, y `<?php // ?><?php código` pasaría
	 * por inofensivo. Sin tokenizer, todo PHP se informa.
	 */
	public static function is_inert_php( string $code ): bool {
		if ( ! function_exists( 'token_get_all' ) ) {
			return false;
		}

		$allowed = array( T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_WHITESPACE, T_INLINE_HTML );

		foreach ( @token_get_all( $code ) as $token ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! is_array( $token ) || ! in_array( $token[0], $allowed, true ) ) {
				return false;
			}
		}
		return true;
	}

	/*──────────────────────────────────────────────
	 * Escaneo y revisión
	 *──────────────────────────────────────────────*/

	/**
	 * Buscar, guardar el resultado y avisar de los archivos nuevos.
	 *
	 * @return array<string, array> Archivos nuevos (o que cambiaron) sin revisar.
	 */
	public function scan(): array {
		$dir = $this->dir ?? self::uploads_dir();
		if ( '' === $dir ) {
			return array();
		}

		$found    = self::find( $dir, $truncated );
		$state    = $this->state();
		$reviewed = array_intersect_key( $state['reviewed'], $found );
		$new      = array();

		foreach ( $found as $path => $file ) {
			$already_seen = isset( $state['files'][ $path ] ) && $state['files'][ $path ]['hash'] === $file['hash'];
			if ( ! $already_seen && ( $reviewed[ $path ] ?? null ) !== $file['hash'] ) {
				$new[ $path ] = $file;
			}
		}

		update_option( self::OPTION, array(
			'files'      => $found,
			'reviewed'   => $reviewed,
			'scanned_at' => time(),
			'truncated'  => $truncated,
		), false );

		if ( $new ) {
			$this->report( $new );
		}

		return $new;
	}

	/**
	 * Archivos encontrados que nadie revisó (o que cambiaron desde entonces).
	 *
	 * @return array<string, array> Ruta => [reason, hash].
	 */
	public function pending(): array {
		$state = $this->state();

		return array_filter( $state['files'], function ( $file, $path ) use ( $state ) {
			return ( $state['reviewed'][ $path ] ?? null ) !== $file['hash'];
		}, ARRAY_FILTER_USE_BOTH );
	}

	/**
	 * Marcar como revisados los archivos encontrados. Si cambian, se vuelven a avisar.
	 *
	 * @return int Archivos marcados.
	 */
	public function review(): int {
		$state   = $this->state();
		$pending = $this->pending();

		$state['reviewed'] = array_map( function ( $file ) {
			return $file['hash'];
		}, $state['files'] );

		update_option( self::OPTION, $state, false );

		return count( $pending );
	}

	/**
	 * @return array{files: array, reviewed: array, scanned_at: int, truncated: bool}
	 */
	public function state(): array {
		$state = get_option( self::OPTION, array() );

		return array_merge(
			array( 'files' => array(), 'reviewed' => array(), 'scanned_at' => 0, 'truncated' => false ),
			is_array( $state ) ? $state : array()
		);
	}

	/**
	 * @param array<string, array> $files Archivos nuevos.
	 */
	private function report( array $files ): void {
		WPS_Logger::get_instance()->event_immediate( WPS_Event_Types::FILE_CHANGED, array(
			'details' => array(
				'area'  => 'uploads',
				'count' => count( $files ),
				'files' => array_slice( array_keys( $files ), 0, 50 ),
			),
		) );

		WPS_Admin_Notifier::get_instance( $this->loader )->notify_uploads_php( $files );
	}

	/*──────────────────────────────────────────────
	 * Bloqueo de ejecución (.htaccess)
	 *──────────────────────────────────────────────*/

	/**
	 * Escribir o quitar las reglas en `uploads/.htaccess`.
	 *
	 * Se conservan las reglas de otros plugins que hubiera en el archivo.
	 *
	 * @return bool Si el archivo quedó como corresponde.
	 */
	public static function sync_rules( bool $enabled, string $dir = '' ): bool {
		$dir = '' !== $dir ? $dir : self::uploads_dir();
		if ( '' === $dir ) {
			return false;
		}

		$file    = $dir . '/.htaccess';
		$current = is_file( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions
		$updated = self::with_rules( $current, $enabled );

		if ( $updated === $current ) {
			return true;
		}

		// Si sólo tenía las reglas propias, no queda un .htaccess vacío.
		if ( '' === trim( $updated ) ) {
			return @unlink( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		return false !== @file_put_contents( $file, $updated, LOCK_EX ); // phpcs:ignore
	}

	/**
	 * Contenido de un .htaccess con (o sin) el bloque propio.
	 */
	public static function with_rules( string $content, bool $enabled ): string {
		$nl      = false !== strpos( $content, "\r\n" ) ? "\r\n" : "\n";
		$without = ltrim( (string) preg_replace( self::RULES_BLOCK, '', $content ), "\r\n" );

		if ( ! $enabled ) {
			return $without;
		}

		$rules = str_replace( "\n", $nl, self::RULES );
		return '' === trim( $without ) ? $rules : $rules . $nl . $without;
	}

	/**
	 * ¿El .htaccess de uploads tiene las reglas?
	 */
	public static function has_rules( string $dir = '' ): bool {
		$dir  = '' !== $dir ? $dir : self::uploads_dir();
		$file = $dir . '/.htaccess';

		return '' !== $dir && is_file( $file )
			&& false !== strpos( (string) file_get_contents( $file ), '# BEGIN WP Seguro' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/**
	 * ¿El servidor lee .htaccess? (Apache y LiteSpeed; nginx no).
	 */
	public static function server_reads_htaccess(): bool {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) $_SERVER['SERVER_SOFTWARE'] ) : '';

		return false !== strpos( $software, 'apache' ) || false !== strpos( $software, 'litespeed' );
	}
}
