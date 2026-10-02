<?php
defined( 'ABSPATH' ) || exit;

/**
 * Actualizaciones desde los releases de GitHub.
 *
 * El plugin no está en wordpress.org: sin esto, cada sitio tenía que bajar
 * el zip y reemplazarlo a mano. Con la cabecera `Update URI`, WordPress deja
 * de consultar wordpress.org por este plugin (otro plugin con el mismo slug
 * no puede «actualizarlo») y le pregunta a este filtro. A partir de ahí todo
 * es el mecanismo estándar: aviso en Plugins y en Escritorio → Actualizaciones,
 * actualización con un clic y actualizaciones automáticas si el
 * administrador las activa.
 *
 * - Se consulta el último release publicado (no borradores ni prereleases)
 *   con un User-Agent propio: WordPress manda por defecto la URL del sitio.
 * - Sólo se acepta el zip del release (`wp-secure-X.Y.Z.zip`) publicado en
 *   este repositorio, y sólo si su firma Ed25519 (`.zip.sig`) es válida
 *   para una de las claves públicas de abajo.
 * - Se desactiva con el ajuste «Buscar actualizaciones en GitHub» o con la
 *   constante WPS_DISABLE_UPDATE_CHECK.
 */
class WPS_Updater {

	const REPO = 'fabiomb/wp-secure';

	const API_URL = 'https://api.github.com/repos/fabiomb/wp-secure/releases/latest';

	/** Prefijo obligatorio de la URL del paquete. */
	const DOWNLOAD_PREFIX = 'https://github.com/fabiomb/wp-secure/releases/download/';

	/** Página (no API) que redirige al tag del último release. */
	const LATEST_URL = 'https://github.com/fabiomb/wp-secure/releases/latest';

	/**
	 * Release en caché (también el resultado fallido, para no insistir).
	 *
	 * Sólo unos minutos, para no repetir la consulta dentro de una misma
	 * revisión: WordPress ya decide cada cuánto revisa (dos veces por día por
	 * cron, una vez por hora en Plugins). Con 3 horas, una versión nueva
	 * tardaba horas en aparecer aun pidiéndola a mano.
	 */
	const CACHE = 'wps_update_release';

	const CACHE_TTL = 600;

	const ERROR_TTL = 900;

	/** Resultado de la última consulta, para mostrarlo en el panel. */
	const STATUS_OPTION = 'wps_update_status';

	const SLUG = 'wp-secure';

	/**
	 * Claves públicas Ed25519 de quien publica los releases.
	 *
	 * Quien tome la cuenta de GitHub podría publicar un release, pero no
	 * firmarlo: la clave privada no está en GitHub. La de emergencia se guarda
	 * fuera de línea y sirve para publicar, firmada con ella, una versión que
	 * deje de aceptar la principal si se pierde o se compromete.
	 */
	const PUBLIC_KEYS = array(
		'principal'  => 'CgMdPMp8D7EtUU/nbW8yQpHui85W9oEd8tYkyEWjQoM=',
		'emergencia' => 'tB2RxtzrBrGB0Zm+aoY1lpI1wwkCBMXUjTcEquJMFfg=',
	);

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Registrar hooks. Corre en todas las peticiones: WordPress busca
	 * actualizaciones desde el cron y desde el panel.
	 */
	public function init(): void {
		if ( ! $this->enabled() ) {
			return;
		}

		add_filter( 'update_plugins_github.com', array( $this, 'update_info' ), 10, 3 );
		add_filter( 'plugins_api', array( $this, 'plugin_info' ), 10, 3 );
		add_filter( 'upgrader_source_selection', array( $this, 'keep_folder_name' ), 10, 4 );
		add_filter( 'upgrader_pre_download', array( $this, 'download_verified' ), 10, 4 );
		add_action( 'load-update-core.php', array( $this, 'on_force_check' ), 9 );
	}

	/**
	 * «Comprobar de nuevo» en Escritorio → Actualizaciones.
	 *
	 * WordPress sólo fuerza ahí la revisión del núcleo: la de plugins se
	 * saltea si hubo una hace menos de un minuto, y al abrir la página ya se
	 * hizo una. Se borran el release guardado y el estado de actualizaciones
	 * de plugins, así la revisión (prioridad 10) consulta GitHub de verdad.
	 *
	 * Se borra en lugar de poner `last_checked` en 0: los actualizadores de
	 * muchos plugins premium (EDD Software Licensing) lo vuelven a fijar en
	 * cada guardado del transient, y el cambio no tenía efecto.
	 */
	public function on_force_check(): void {
		if ( empty( $_GET['force-check'] ) || ! current_user_can( 'update_plugins' ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return;
		}

		delete_transient( self::CACHE );
		delete_site_transient( 'update_plugins' );
	}

	public function enabled(): bool {
		if ( defined( 'WPS_DISABLE_UPDATE_CHECK' ) && WPS_DISABLE_UPDATE_CHECK ) {
			return false;
		}
		return (bool) $this->loader->get_setting( 'update_check_enabled', true );
	}

	/*──────────────────────────────────────────────
	 * Filtros de WordPress
	 *──────────────────────────────────────────────*/

	/**
	 * Datos de la última versión para `wp_update_plugins()`.
	 *
	 * WordPress compara la versión y lo ubica como actualización disponible o
	 * como «al día» (lo que también habilita el enlace de actualizaciones
	 * automáticas en la lista de plugins).
	 *
	 * @param array|false $update      Lo que haya devuelto otro filtro.
	 * @param array       $plugin_data Cabeceras del plugin.
	 * @param string      $plugin_file Plugin que se está revisando.
	 * @return array|false
	 */
	public function update_info( $update, $plugin_data, $plugin_file ) {
		// Otros plugins también pueden usar github.com como Update URI.
		if ( WPS_PLUGIN_BASENAME !== $plugin_file ) {
			return $update;
		}

		$release = $this->latest_release();
		if ( null === $release ) {
			return $update;
		}

		return array(
			'id'           => 'https://github.com/' . self::REPO,
			'slug'         => self::SLUG,
			'version'      => $release['version'],
			'url'          => $release['url'],
			'package'      => $release['package'],
			'requires_php' => (string) ( $plugin_data['RequiresPHP'] ?? '7.4' ),
			'requires'     => (string) ( $plugin_data['RequiresWP'] ?? '6.0' ),
			'tested'       => '',
			'icons'        => array(),
		);
	}

	/**
	 * Ventana «Ver detalles» con las notas del release.
	 *
	 * @param false|object|array $result Resultado de otro filtro.
	 * @param string             $action Acción pedida.
	 * @param object             $args   Argumentos (slug).
	 * @return false|object|array
	 */
	public function plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || ! is_object( $args ) || self::SLUG !== ( $args->slug ?? '' ) ) {
			return $result;
		}

		$release = $this->latest_release();
		if ( null === $release ) {
			return $result;
		}

		return (object) array(
			'name'          => 'WP Seguro',
			'slug'          => self::SLUG,
			'version'       => $release['version'],
			'author'        => '<a href="https://github.com/fabiomb">Fabio Baccaglioni</a>',
			'homepage'      => 'https://github.com/' . self::REPO,
			'requires'      => '6.0',
			'requires_php'  => '7.4',
			'last_updated'  => $release['published'],
			'download_link' => $release['package'],
			'sections'      => array(
				'changelog' => '' !== $release['notes']
					? self::markdown_to_html( $release['notes'] )
					: '<p><a href="' . esc_url( $release['url'] ) . '">' . esc_html__( 'Ver las notas del release en GitHub', 'wp-secure' ) . '</a></p>',
			),
		);
	}

	/**
	 * Descargar el paquete y verificar su firma antes de instalarlo.
	 *
	 * Reemplaza la descarga de WordPress sólo para paquetes de este
	 * repositorio. Si falta la firma o no es válida, la actualización se
	 * cancela antes de tocar el plugin instalado y queda un evento crítico.
	 *
	 * @param false|string|WP_Error $reply      Resultado de otro filtro.
	 * @param string                $package    URL del paquete.
	 * @param object|null           $upgrader   Upgrader.
	 * @param array                 $hook_extra Datos de la actualización.
	 * @return false|string|WP_Error Ruta del zip verificado.
	 */
	public function download_verified( $reply, $package, $upgrader = null, $hook_extra = array() ) {
		if ( false !== $reply || ! is_string( $package ) || 0 !== strpos( $package, self::DOWNLOAD_PREFIX ) ) {
			return $reply;
		}

		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		if ( is_object( $upgrader ) && isset( $upgrader->skin ) && is_object( $upgrader->skin ) ) {
			$upgrader->skin->feedback( __( 'Descargando WP Seguro y verificando su firma…', 'wp-secure' ) );
		}

		$zip = download_url( $package, 300 );
		if ( is_wp_error( $zip ) ) {
			return $zip;
		}

		$sig_file  = download_url( $package . '.sig', 60 );
		$signature = is_wp_error( $sig_file ) ? '' : (string) file_get_contents( $sig_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! is_wp_error( $sig_file ) ) {
			@unlink( $sig_file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$key = '' === $signature ? null : self::verify( (string) file_get_contents( $zip ), $signature, $this->public_keys() ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( null !== $key ) {
			return $zip;
		}

		@unlink( $zip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		$reason = '' === $signature ? 'missing' : 'invalid';
		WPS_Logger::get_instance()->event_immediate( WPS_Event_Types::UPDATE_REJECTED, array(
			'details' => array( 'package' => $package, 'reason' => $reason ),
		) );

		return new WP_Error(
			'wps_update_signature',
			'missing' === $reason
				? __( 'La actualización de WP Seguro no trae firma, así que no se instaló. El plugin sigue en la versión actual.', 'wp-secure' )
				: __( 'La firma de la actualización de WP Seguro no es válida: el paquete pudo haber sido alterado y no se instaló. El plugin sigue en la versión actual.', 'wp-secure' )
		);
	}

	/**
	 * Clave que valida la firma, o null si ninguna.
	 *
	 * La firma es la de `openssl pkeyutl -sign -rawin` (64 bytes); también se
	 * acepta en base64.
	 *
	 * @param array<string, string> $keys Nombre => clave pública en base64.
	 */
	public static function verify( string $data, string $signature, array $keys ): ?string {
		if ( 64 !== strlen( $signature ) ) {
			$decoded   = base64_decode( trim( $signature ), true );
			$signature = false === $decoded ? '' : $decoded;
		}
		if ( 64 !== strlen( $signature ) ) {
			return null;
		}

		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) && defined( 'WPINC' ) && is_file( ABSPATH . WPINC . '/sodium_compat/autoload.php' ) ) {
			require_once ABSPATH . WPINC . '/sodium_compat/autoload.php';
		}
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return null;
		}

		foreach ( $keys as $name => $key ) {
			$public = base64_decode( $key, true );
			try {
				if ( false !== $public && 32 === strlen( $public ) && sodium_crypto_sign_verify_detached( $signature, $data, $public ) ) {
					return (string) $name;
				}
			} catch ( \Throwable $e ) {
				continue;
			}
		}

		return null;
	}

	/**
	 * @return array<string, string>
	 */
	protected function public_keys(): array {
		return self::PUBLIC_KEYS;
	}

	/**
	 * Mantener el nombre de la carpeta instalada.
	 *
	 * El zip del release trae `wp-secure/`, pero si el plugin se instaló
	 * desde el «Download ZIP» de GitHub la carpeta es `wp-secure-main`:
	 * sin esto la actualización dejaba una segunda copia del plugin.
	 *
	 * @param string|WP_Error $source        Carpeta descomprimida.
	 * @param string          $remote_source Carpeta temporal que la contiene.
	 * @param object          $upgrader      Upgrader.
	 * @param array           $hook_extra    Datos de la actualización.
	 * @return string|WP_Error
	 */
	public function keep_folder_name( $source, $remote_source, $upgrader = null, $hook_extra = array() ) {
		if ( is_wp_error( $source ) || ! is_array( $hook_extra ) || WPS_PLUGIN_BASENAME !== ( $hook_extra['plugin'] ?? '' ) ) {
			return $source;
		}

		$target = self::target_source( (string) $source, (string) $remote_source, dirname( WPS_PLUGIN_BASENAME ) );
		if ( $target === $source ) {
			return $source;
		}

		global $wp_filesystem;
		if ( ! $wp_filesystem || ! $wp_filesystem->move( $source, $target, true ) ) {
			return new WP_Error( 'wps_update_folder', __( 'No se pudo preparar la carpeta de la actualización de WP Seguro.', 'wp-secure' ) );
		}

		return $target;
	}

	/**
	 * Carpeta que tiene que quedar: la del paquete con el nombre instalado.
	 */
	public static function target_source( string $source, string $remote_source, string $installed_dir ): string {
		if ( basename( untrailingslashit( $source ) ) === $installed_dir ) {
			return $source;
		}
		return trailingslashit( $remote_source ) . $installed_dir . '/';
	}

	/*──────────────────────────────────────────────
	 * Release de GitHub
	 *──────────────────────────────────────────────*/

	/**
	 * Último release válido, o null si no hay o GitHub no respondió.
	 *
	 * Se guarda en caché unos minutos (ver CACHE). «Comprobar de nuevo» en
	 * Escritorio → Actualizaciones (`force-check`) la saltea.
	 *
	 * @return array{version: string, package: string, url: string, notes: string, published: string}|null
	 */
	public function latest_release(): ?array {
		$force  = is_admin() && ! empty( $_GET['force-check'] ); // phpcs:ignore WordPress.Security.NonceVerification
		$cached = $force ? false : get_transient( self::CACHE );

		if ( is_array( $cached ) ) {
			return $cached['release'];
		}

		$release = $this->fetch_release();
		set_transient( self::CACHE, array( 'release' => $release ), null === $release ? self::ERROR_TTL : self::CACHE_TTL );

		return $release;
	}

	/**
	 * Consultar la API de GitHub.
	 */
	protected function fetch_release(): ?array {
		$response = $this->http( 'GET', self::API_URL );
		$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );

		if ( 200 === $code ) {
			$data    = json_decode( (string) wp_remote_retrieve_body( $response ), true );
			$release = is_array( $data ) ? self::parse_release( $data ) : null;
			$this->save_status( $release, 'api', null === $release ? __( 'GitHub no tiene un release válido (zip de la versión).', 'wp-secure' ) : '' );
			return $release;
		}

		$api_error = is_wp_error( $response ) ? $response->get_error_message() : sprintf(
			/* translators: %d: HTTP status code */
			__( 'la API de GitHub respondió %d', 'wp-secure' ),
			$code
		);
		if ( 403 === $code || 429 === $code ) {
			$api_error .= ' ' . __( '(límite de consultas por IP)', 'wp-secure' );
		}

		// Respaldo sin la API: la página del último release redirige a su tag
		// y no tiene el límite de 60 consultas por hora e IP de la API (que en
		// un hosting compartido gastan todos los sitios del servidor).
		$release = $this->release_from_web();
		$this->save_status( $release, 'web', null === $release ? $api_error : '' );

		return $release;
	}

	/**
	 * Último release según la redirección de `releases/latest`.
	 *
	 * Sin notas: «Ver detalles» enlaza al release. El zip y su firma tienen
	 * nombre fijo; si faltan, la descarga o la verificación lo rechazan.
	 */
	protected function release_from_web(): ?array {
		$response = $this->http( 'HEAD', self::LATEST_URL );
		if ( is_wp_error( $response ) ) {
			return null;
		}

		return self::release_from_location( (string) wp_remote_retrieve_header( $response, 'location' ) );
	}

	/**
	 * Release a partir de la URL del tag (`…/releases/tag/vX.Y.Z`).
	 */
	public static function release_from_location( string $location ): ?array {
		$prefix = 'https://github.com/' . self::REPO . '/releases/tag/v';
		if ( 0 !== strpos( $location, $prefix ) ) {
			return null;
		}

		$version = substr( $location, strlen( $prefix ) );
		if ( ! preg_match( '/^\d+\.\d+\.\d+$/', $version ) ) {
			return null;
		}

		return array(
			'version'   => $version,
			'package'   => self::DOWNLOAD_PREFIX . 'v' . $version . '/' . self::SLUG . '-' . $version . '.zip',
			'url'       => $location,
			'notes'     => '',
			'published' => '',
		);
	}

	/**
	 * Petición a GitHub (se reemplaza en los tests).
	 *
	 * @return array|WP_Error
	 */
	protected function http( string $method, string $url ) {
		$args = self::request_args();

		if ( 'HEAD' === $method ) {
			$args['redirection'] = 0;
			return wp_remote_head( $url, $args );
		}

		return wp_remote_get( $url, $args );
	}

	/**
	 * Guardar el resultado de la consulta para mostrarlo en el panel.
	 */
	private function save_status( ?array $release, string $source, string $error ): void {
		update_option( self::STATUS_OPTION, array(
			'checked_at' => time(),
			'version'    => null === $release ? '' : $release['version'],
			'source'     => $source,
			'error'      => $error,
		), false );
	}

	/**
	 * Resumen de la última consulta, para el panel.
	 */
	public static function status_text(): string {
		$status = get_option( self::STATUS_OPTION, array() );
		if ( ! is_array( $status ) || empty( $status['checked_at'] ) ) {
			return __( 'Todavía no se consultó.', 'wp-secure' );
		}

		$when = wp_date( 'Y-m-d H:i', (int) $status['checked_at'] );

		if ( '' !== (string) $status['error'] ) {
			/* translators: 1: date, 2: error */
			return sprintf( __( 'Última consulta: %1$s — falló: %2$s.', 'wp-secure' ), $when, $status['error'] );
		}

		$text = sprintf(
			/* translators: 1: date, 2: latest version */
			__( 'Última consulta: %1$s — última versión publicada: %2$s.', 'wp-secure' ),
			$when,
			$status['version']
		);

		if ( 'web' === $status['source'] ) {
			$text .= ' ' . __( '(La API de GitHub no respondió y se usó la página de releases.)', 'wp-secure' );
		}

		return $text;
	}

	/**
	 * Argumentos de la petición: User-Agent propio (el de WordPress incluye
	 * la URL del sitio) y la versión de la API.
	 */
	public static function request_args(): array {
		return array(
			'timeout'    => 5,
			'user-agent' => 'WP-Seguro/' . WPS_VERSION,
			'headers'    => array(
				'Accept'               => 'application/vnd.github+json',
				'X-GitHub-Api-Version' => '2022-11-28',
			),
		);
	}

	/**
	 * Validar un release de la API: versión X.Y.Z en el tag, publicado, no
	 * prerelease, y con el zip de esa versión en este repositorio.
	 */
	public static function parse_release( array $data ): ?array {
		if ( ! empty( $data['draft'] ) || ! empty( $data['prerelease'] ) ) {
			return null;
		}

		$version = ltrim( (string) ( $data['tag_name'] ?? '' ), 'v' );
		if ( ! preg_match( '/^\d+\.\d+\.\d+$/', $version ) ) {
			return null;
		}

		$expected = self::SLUG . '-' . $version . '.zip';
		$package  = '';
		foreach ( (array) ( $data['assets'] ?? array() ) as $asset ) {
			$url = (string) ( $asset['browser_download_url'] ?? '' );
			if ( $expected === ( $asset['name'] ?? '' ) && 0 === strpos( $url, self::DOWNLOAD_PREFIX ) ) {
				$package = $url;
				break;
			}
		}

		if ( '' === $package ) {
			return null;
		}

		return array(
			'version'   => $version,
			'package'   => $package,
			'url'       => (string) ( $data['html_url'] ?? 'https://github.com/' . self::REPO . '/releases' ),
			'notes'     => (string) ( $data['body'] ?? '' ),
			'published' => (string) ( $data['published_at'] ?? '' ),
		);
	}

	/**
	 * Markdown de las notas (el del changelog) a HTML para «Ver detalles».
	 *
	 * Sólo lo que usa el changelog: títulos, listas, negrita, código y
	 * enlaces. Se escapa todo antes de convertir.
	 */
	public static function markdown_to_html( string $markdown ): string {
		$html    = '';
		$in_list = false;

		foreach ( preg_split( '/\R/', $markdown ) as $line ) {
			$line = rtrim( $line );

			if ( preg_match( '/^\s*-\s+(.*)$/', $line, $m ) ) {
				if ( ! $in_list ) {
					$html   .= '<ul>';
					$in_list = true;
				}
				$html .= '<li>' . self::inline( $m[1] ) . '</li>';
				continue;
			}

			if ( $in_list ) {
				$html   .= '</ul>';
				$in_list = false;
			}

			if ( preg_match( '/^(#{1,4})\s+(.*)$/', $line, $m ) ) {
				$level = min( 4, strlen( $m[1] ) + 1 );
				$html .= "<h{$level}>" . self::inline( $m[2] ) . "</h{$level}>";
			} elseif ( '' !== trim( $line ) ) {
				$html .= '<p>' . self::inline( $line ) . '</p>';
			}
		}

		return $in_list ? $html . '</ul>' : $html;
	}

	private static function inline( string $text ): string {
		$text = esc_html( $text );
		$text = (string) preg_replace( '/`([^`]+)`/', '<code>$1</code>', $text );
		$text = (string) preg_replace( '/\*\*([^*]+)\*\*/', '<strong>$1</strong>', $text );

		return (string) preg_replace_callback( '/\[([^\]]+)\]\((https:\/\/[^)\s]+)\)/', function ( $m ) {
			return '<a href="' . esc_url( html_entity_decode( $m[2] ) ) . '">' . $m[1] . '</a>';
		}, $text );
	}
}
