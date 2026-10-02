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
 *   este repositorio.
 * - Se desactiva con el ajuste «Buscar actualizaciones en GitHub» o con la
 *   constante WPS_DISABLE_UPDATE_CHECK.
 */
class WPS_Updater {

	const REPO = 'fabiomb/wp-secure';

	const API_URL = 'https://api.github.com/repos/fabiomb/wp-secure/releases/latest';

	/** Prefijo obligatorio de la URL del paquete. */
	const DOWNLOAD_PREFIX = 'https://github.com/fabiomb/wp-secure/releases/download/';

	/** Release en caché (también el resultado fallido, para no insistir). */
	const CACHE = 'wps_update_release';

	const CACHE_TTL = 3 * 3600;

	const ERROR_TTL = 3600;

	const SLUG = 'wp-secure';

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
				'changelog' => self::markdown_to_html( $release['notes'] ),
			),
		);
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
	 * Se guarda en caché unas horas (y el fallo, una hora). «Buscar
	 * actualizaciones» en Escritorio → Actualizaciones (`force-check`) la
	 * saltea.
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
		$response = wp_remote_get( self::API_URL, self::request_args() );

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return is_array( $data ) ? self::parse_release( $data ) : null;
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
