<?php
defined( 'ABSPATH' ) || exit;

/**
 * Gestión de la geolocalización IP→País/ASN.
 *
 * La geolocalización es opcional: sin proveedor (`geo_provider` = 'none')
 * todas las consultas devuelven campos vacíos y el resto del plugin funciona
 * igual. Hay un solo proveedor activo a la vez:
 * - ipinfo.io: API en vivo (token) o base local Country+ASN.
 * - MaxMind GeoLite2: servicio web GeoLite o bases locales Country y ASN.
 *
 * Dentro del proveedor activo se usa el modo elegido y, si no da resultado,
 * el otro modo del mismo proveedor. Nunca se consulta al otro proveedor.
 */
class WPS_Ipdb_Manager {

	/** Sin geolocalización. */
	const PROVIDER_NONE = 'none';

	/** ipinfo.io. */
	const PROVIDER_IPINFO = 'ipinfo';

	/** MaxMind GeoLite2. */
	const PROVIDER_MAXMIND = 'maxmind';

	/** Valores válidos de `geo_provider`. */
	const PROVIDER_IDS = array( self::PROVIDER_NONE, self::PROVIDER_IPINFO, self::PROVIDER_MAXMIND );

	/** Archivos locales de ipinfo.io, en orden de preferencia. */
	const IPINFO_FILES = array(
		'country_asn.mmdb',
		'ipinfo-country-asn.mmdb',
		'asn.mmdb',
		'country.mmdb',
	);

	/** @var WPS_Ipdb_Manager|null */
	private static $instance = null;

	/** @var WPS_Loader */
	private $loader;

	/** @var string Directorio de las bases locales (sustituible en tests). */
	private $data_dir;

	/** @var WPS_Mmdb_Reader[] Lectores abiertos, por ruta. */
	private $readers = array();

	/** @var bool[] Rutas que no se pudieron abrir (no reintentar en la petición). */
	private $failed_paths = array();

	/** @var array In-memory cache of lookups for the current request. */
	private $cache = array();

	/** @var string|null Proveedor deducido de la configuración anterior (ver get_provider()). */
	private $legacy_provider = null;

	/** Timeout de la consulta a la API, en segundos. Corre dentro de la petición del visitante. */
	const API_TIMEOUT = 2;

	/** Segundos que se recuerda que una IP no pudo resolverse. */
	const API_FAILURE_TTL = 900;

	/** Segundos sin consultar la API después de un error del servicio. */
	const API_BACKOFF_TTL = 600;

	/** Transient que suspende la API de ipinfo.io mientras el servicio falla. */
	const API_BACKOFF_KEY = 'wps_geo_api_backoff';

	/** Duración del cache de resultados de ipinfo.io (2 horas). */
	const IPINFO_CACHE_TTL = 7200;

	/** Transient que suspende el servicio web de MaxMind mientras falla. */
	const MAXMIND_BACKOFF_KEY = 'wps_geo_maxmind_backoff';

	/**
	 * Duración del cache del servicio web de MaxMind (24 horas). Más larga que
	 * la de ipinfo.io: el plan gratuito admite sólo 1000 consultas por día.
	 */
	const MAXMIND_CACHE_TTL = 86400;

	private function __construct() {
		$this->loader   = WPS_Loader::get_instance();
		$this->data_dir = WPS_DATA_DIR;
	}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/*──────────────────────────────────────────────
	 * Proveedor y estado
	 *──────────────────────────────────────────────*/

	/**
	 * Proveedores disponibles con su nombre visible.
	 *
	 * @return array<string, string>
	 */
	public static function providers(): array {
		return array(
			self::PROVIDER_NONE    => __( 'Ninguno (geolocalización desactivada)', 'wp-secure' ),
			self::PROVIDER_IPINFO  => 'ipinfo.io',
			self::PROVIDER_MAXMIND => 'MaxMind GeoLite2',
		);
	}

	/**
	 * Proveedor de las instalaciones que todavía no tienen el ajuste.
	 *
	 * Antes sólo existía ipinfo.io: si había un token o una base descargada se
	 * conserva ese proveedor; si no, la geolocalización queda desactivada.
	 *
	 * @param string $ipinfo_api_key  Token de ipinfo.io guardado.
	 * @param bool   $has_ipinfo_mmdb Si existe una base local de ipinfo.io.
	 */
	public static function legacy_provider( string $ipinfo_api_key, bool $has_ipinfo_mmdb ): string {
		return ( '' !== trim( $ipinfo_api_key ) || $has_ipinfo_mmdb ) ? self::PROVIDER_IPINFO : self::PROVIDER_NONE;
	}

	/**
	 * Si existe una base local de ipinfo.io en el directorio de datos.
	 */
	public function has_ipinfo_mmdb(): bool {
		return null !== $this->find_ipinfo_mmdb();
	}

	/**
	 * Proveedor activo.
	 */
	public function get_provider(): string {
		$provider = $this->loader->get_setting( 'geo_provider', null );

		// Instalación actualizada cuya migración todavía no guardó el ajuste.
		if ( null === $provider ) {
			if ( null === $this->legacy_provider ) {
				$this->legacy_provider = self::legacy_provider(
					(string) $this->loader->get_setting( 'ipinfo_api_key', '' ),
					$this->has_ipinfo_mmdb()
				);
			}
			return $this->legacy_provider;
		}

		return in_array( $provider, self::PROVIDER_IDS, true ) ? $provider : self::PROVIDER_NONE;
	}

	/**
	 * Modo preferido ('api' o 'local') de un proveedor.
	 */
	public function get_mode( ?string $provider = null ): string {
		$provider = $provider ?? $this->get_provider();

		if ( self::PROVIDER_MAXMIND === $provider ) {
			return 'api' === $this->loader->get_setting( 'maxmind_mode', 'local' ) ? 'api' : 'local';
		}

		return 'local' === $this->loader->get_setting( 'ipinfo_mode', 'api' ) ? 'local' : 'api';
	}

	/**
	 * Si el proveedor tiene las credenciales de su API (en MaxMind son también
	 * las de la descarga).
	 */
	public function has_credentials( ?string $provider = null ): bool {
		$provider = $provider ?? $this->get_provider();

		if ( self::PROVIDER_IPINFO === $provider ) {
			return '' !== trim( (string) $this->loader->get_setting( 'ipinfo_api_key', '' ) );
		}

		if ( self::PROVIDER_MAXMIND === $provider ) {
			return '' !== trim( (string) $this->loader->get_setting( 'maxmind_account_id', '' ) )
				&& '' !== trim( (string) $this->loader->get_setting( 'maxmind_license_key', '' ) );
		}

		return false;
	}

	/**
	 * Si la geolocalización puede dar datos: hay un proveedor elegido y tiene
	 * credenciales para su API o una base local descargada (cualquiera de las
	 * dos sirve, porque cada modo cae en el otro del mismo proveedor).
	 */
	public function is_configured(): bool {
		$provider = $this->get_provider();
		if ( self::PROVIDER_NONE === $provider ) {
			return false;
		}

		return $this->has_credentials( $provider ) || $this->is_local_available( $provider );
	}

	/*──────────────────────────────────────────────
	 * Consulta
	 *──────────────────────────────────────────────*/

	/**
	 * Look up an IP address and return geo data.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return array {
	 *     @type string|null $country      Country code (ISO 3166-1 alpha-2).
	 *     @type string|null $country_name Country name.
	 *     @type int|null    $asn          ASN number (without "AS" prefix).
	 *     @type string|null $asn_name     ASN organization name.
	 *     @type string|null $source       'local' or 'api'.
	 * }
	 */
	public function lookup( string $ip ): array {
		$provider = $this->get_provider();

		// Sin proveedor o IP privada/reservada: no hay dato que buscar.
		if ( self::PROVIDER_NONE === $provider || WPS_Ip_Utils::is_private_ip( $ip ) ) {
			return self::empty_result( null );
		}

		// In-memory cache (same request).
		$memo_key = $provider . '|' . $ip;
		if ( isset( $this->cache[ $memo_key ] ) ) {
			return $this->cache[ $memo_key ];
		}

		if ( 'local' === $this->get_mode( $provider ) ) {
			$result = $this->lookup_local( $provider, $ip );
			// Fallback a la API del mismo proveedor si la base local no resolvió.
			if ( self::is_empty( $result ) ) {
				$result = $this->lookup_api( $provider, $ip );
			}
		} else {
			$result = $this->lookup_api( $provider, $ip );
			// Fallback a la base local del mismo proveedor, si existe.
			if ( self::is_empty( $result ) && $this->is_local_available( $provider ) ) {
				$result = $this->lookup_local( $provider, $ip );
			}
		}

		$this->cache[ $memo_key ] = $result;
		return $result;
	}

	/**
	 * Resultado vacío.
	 */
	private static function empty_result( ?string $source ): array {
		return array(
			'country'      => null,
			'country_name' => null,
			'asn'          => null,
			'asn_name'     => null,
			'source'       => $source,
		);
	}

	private static function is_empty( array $result ): bool {
		return null === $result['country'] && null === $result['asn'];
	}

	/**
	 * Consulta en las bases locales del proveedor.
	 */
	private function lookup_local( string $provider, string $ip ): array {
		if ( self::PROVIDER_MAXMIND === $provider ) {
			return $this->lookup_local_maxmind( $ip );
		}

		$default = self::empty_result( 'local' );

		$reader = $this->get_reader( $this->find_ipinfo_mmdb() );
		if ( null === $reader ) {
			return $default;
		}

		$record = $reader->lookup( $ip );
		if ( null === $record ) {
			return $default;
		}

		return array(
			'country'      => $record['country'] ?? ( $record['country_code'] ?? null ),
			'country_name' => $record['country_name'] ?? null,
			'asn'          => $this->parse_asn( $record['asn'] ?? null ),
			'asn_name'     => $record['as_name'] ?? ( $record['as_organization'] ?? null ),
			'source'       => 'local',
		);
	}

	/**
	 * Consulta en GeoLite2-Country y GeoLite2-ASN. Si falta una de las dos
	 * bases se devuelve lo que aporte la otra.
	 */
	private function lookup_local_maxmind( string $ip ): array {
		$country_reader = $this->get_reader( $this->existing_path( WPS_Ipdb_Maxmind::COUNTRY_FILENAME ) );
		$asn_reader     = $this->get_reader( $this->existing_path( WPS_Ipdb_Maxmind::ASN_FILENAME ) );

		$result = WPS_Ipdb_Maxmind::map_local(
			$country_reader ? $country_reader->lookup( $ip ) : null,
			$asn_reader ? $asn_reader->lookup( $ip ) : null
		);
		$result['source'] = 'local';

		return $result;
	}

	/**
	 * Consulta a la API del proveedor.
	 */
	private function lookup_api( string $provider, string $ip ): array {
		if ( ! $this->has_credentials( $provider ) ) {
			return self::empty_result( 'api' );
		}

		if ( self::PROVIDER_MAXMIND === $provider ) {
			$account = trim( (string) $this->loader->get_setting( 'maxmind_account_id', '' ) );
			$license = trim( (string) $this->loader->get_setting( 'maxmind_license_key', '' ) );

			// 401/402/403: credenciales rechazadas o servicio no habilitado en
			// la cuenta. Fallaría igual para cualquier IP, así que se pausa.
			return $this->request_api(
				'wps_geo_mm_' . md5( $ip ),
				self::MAXMIND_BACKOFF_KEY,
				self::MAXMIND_CACHE_TTL,
				sprintf( WPS_Ipdb_Maxmind::API_URL, rawurlencode( $ip ) ),
				array(
					'Accept'        => 'application/json',
					'Authorization' => WPS_Ipdb_Maxmind::auth_header( $account, $license ),
				),
				array( 401, 402, 403 ),
				array( 'WPS_Ipdb_Maxmind', 'map_api' )
			);
		}

		$api_key = trim( (string) $this->loader->get_setting( 'ipinfo_api_key', '' ) );

		return $this->request_api(
			'wps_geo_' . md5( $ip ),
			self::API_BACKOFF_KEY,
			self::IPINFO_CACHE_TTL,
			sprintf( 'https://ipinfo.io/%s?token=%s', rawurlencode( $ip ), rawurlencode( $api_key ) ),
			array( 'Accept' => 'application/json' ),
			array(),
			array( $this, 'map_ipinfo_api' )
		);
	}

	/**
	 * Consulta HTTP con cache en transients, pausa ante fallas del servicio y
	 * memoria de fallos por IP.
	 *
	 * @param string   $cache_key     Transient del resultado de esta IP.
	 * @param string   $backoff_key   Transient que pausa la API del proveedor.
	 * @param int      $cache_ttl     Duración del cache de resultados.
	 * @param string   $url           URL de la consulta.
	 * @param array    $headers       Cabeceras HTTP.
	 * @param int[]    $service_codes Códigos 4xx que indican un problema de la
	 *                                cuenta (no de la IP) y pausan la API.
	 * @param callable $mapper        Convierte la respuesta decodificada en
	 *                                country, country_name, asn y asn_name.
	 */
	private function request_api( string $cache_key, string $backoff_key, int $cache_ttl, string $url, array $headers, array $service_codes, callable $mapper ): array {
		$default = self::empty_result( 'api' );

		// Cache de resultados. Incluye los fallos recientes, guardados con los
		// campos en null.
		$cached = get_transient( $cache_key );
		if ( false !== $cached && is_array( $cached ) ) {
			$cached['source'] = 'api';
			return $cached;
		}

		// La consulta corre dentro de la petición del visitante. Si el servicio
		// está caído o agotó la cuota, cada IP nueva pagaría el timeout completo:
		// tras un error se deja de consultar por unos minutos.
		if ( get_transient( $backoff_key ) ) {
			return $default;
		}

		$response = wp_remote_get( $url, array(
			'timeout'   => self::API_TIMEOUT,
			'sslverify' => true,
			'headers'   => $headers,
		) );

		if ( is_wp_error( $response ) ) {
			// Timeout, DNS o conexión: problema del servicio, no de la IP.
			set_transient( $backoff_key, 1, self::API_BACKOFF_TTL );
			return $default;
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			if ( 429 === $code || $code >= 500 || in_array( $code, $service_codes, true ) ) {
				// Cuota agotada, cuenta rechazada o servicio caído.
				set_transient( $backoff_key, 1, self::API_BACKOFF_TTL );
			} else {
				// Error propio de esta IP: no volver a preguntar enseguida.
				$this->remember_api_failure( $cache_key );
			}
			return $default;
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			$this->remember_api_failure( $cache_key );
			return $default;
		}

		$mapped = call_user_func( $mapper, $data );
		$result = array(
			'country'      => $mapped['country'] ?? null,
			'country_name' => $mapped['country_name'] ?? null,
			'asn'          => $mapped['asn'] ?? null,
			'asn_name'     => $mapped['asn_name'] ?? null,
		);

		set_transient( $cache_key, $result, $cache_ttl );

		$result['source'] = 'api';
		return $result;
	}

	/**
	 * Mapear la respuesta de la API de ipinfo.io.
	 *
	 * @param array $data Respuesta decodificada.
	 */
	public function map_ipinfo_api( array $data ): array {
		return array(
			'country'      => $data['country'] ?? null,
			'country_name' => $data['country_name'] ?? null,
			'asn'          => $this->parse_asn( $data['asn']['asn'] ?? ( $data['org'] ?? null ) ),
			'asn_name'     => $data['asn']['name'] ?? $this->parse_org_name( $data['org'] ?? '' ),
		);
	}

	/**
	 * Recordar que una IP no pudo resolverse, para no consultarla en cada petición.
	 */
	private function remember_api_failure( string $cache_key ): void {
		set_transient(
			$cache_key,
			array(
				'country'      => null,
				'country_name' => null,
				'asn'          => null,
				'asn_name'     => null,
			),
			self::API_FAILURE_TTL
		);
	}

	/*──────────────────────────────────────────────
	 * Bases locales
	 *──────────────────────────────────────────────*/

	/**
	 * Abrir (una vez por petición) el lector de una base.
	 */
	private function get_reader( ?string $path ): ?WPS_Mmdb_Reader {
		if ( null === $path || isset( $this->failed_paths[ $path ] ) ) {
			return null;
		}

		if ( isset( $this->readers[ $path ] ) ) {
			return $this->readers[ $path ];
		}

		try {
			$this->readers[ $path ] = new WPS_Mmdb_Reader( $path );
		} catch ( \RuntimeException $e ) {
			$this->failed_paths[ $path ] = true;
			return null;
		}

		return $this->readers[ $path ];
	}

	/**
	 * Directorio de las bases locales.
	 */
	public function get_data_dir(): string {
		return $this->data_dir;
	}

	/**
	 * Ruta de un archivo del directorio de datos, si existe.
	 */
	private function existing_path( string $filename ): ?string {
		$path = $this->data_dir . $filename;
		return is_file( $path ) ? $path : null;
	}

	/**
	 * Primera base de ipinfo.io presente.
	 */
	private function find_ipinfo_mmdb(): ?string {
		foreach ( self::IPINFO_FILES as $file ) {
			$path = $this->existing_path( $file );
			if ( null !== $path ) {
				return $path;
			}
		}
		return null;
	}

	/**
	 * Bases locales de un proveedor que existen en disco. Cada proveedor sólo
	 * ve sus propios archivos: una base de MaxMind nunca se lee con el mapeo
	 * de ipinfo.io ni al revés.
	 *
	 * @return array<string, string> etiqueta => ruta.
	 */
	public function get_local_paths( ?string $provider = null ): array {
		$provider = $provider ?? $this->get_provider();
		$paths    = array();

		if ( self::PROVIDER_IPINFO === $provider ) {
			$path = $this->find_ipinfo_mmdb();
			if ( null !== $path ) {
				$paths['ipinfo Country + ASN'] = $path;
			}
		} elseif ( self::PROVIDER_MAXMIND === $provider ) {
			foreach ( WPS_Ipdb_Maxmind::editions() as $edition => $filename ) {
				$path = $this->existing_path( $filename );
				if ( null !== $path ) {
					$paths[ $edition ] = $path;
				}
			}
		}

		return $paths;
	}

	/**
	 * Ruta de la base principal del proveedor (la de países, en MaxMind).
	 */
	public function get_mmdb_path( ?string $provider = null ): ?string {
		$paths = $this->get_local_paths( $provider );
		return $paths ? reset( $paths ) : null;
	}

	/**
	 * Si el proveedor tiene alguna base local descargada.
	 */
	public function is_local_available( ?string $provider = null ): bool {
		return array() !== $this->get_local_paths( $provider );
	}

	/**
	 * Si el proveedor tiene todas sus bases locales (MaxMind usa dos).
	 */
	public function is_local_complete( ?string $provider = null ): bool {
		$provider = $provider ?? $this->get_provider();
		$count    = count( $this->get_local_paths( $provider ) );

		if ( self::PROVIDER_MAXMIND === $provider ) {
			return count( WPS_Ipdb_Maxmind::editions() ) === $count;
		}

		return $count > 0;
	}

	/**
	 * Información de las bases locales del proveedor.
	 *
	 * @return array[] Una entrada por base; vacío si no hay ninguna.
	 */
	public function get_databases_info( ?string $provider = null ): array {
		$infos = array();

		foreach ( $this->get_local_paths( $provider ) as $label => $path ) {
			try {
				$reader   = new WPS_Mmdb_Reader( $path );
				$metadata = $reader->get_metadata();
				$reader->close();
			} catch ( \RuntimeException $e ) {
				continue;
			}

			$infos[] = array(
				'label'      => $label,
				'path'       => $path,
				'file_size'  => filesize( $path ),
				'type'       => $metadata['database_type'] ?? 'unknown',
				'build_time' => (int) ( $metadata['build_epoch'] ?? 0 ),
				'ip_version' => (int) ( $metadata['ip_version'] ?? 0 ),
				'node_count' => (int) ( $metadata['node_count'] ?? 0 ),
			);
		}

		return $infos;
	}

	/*──────────────────────────────────────────────
	 * Formato de ipinfo.io
	 *──────────────────────────────────────────────*/

	/**
	 * Parse ASN value from various formats.
	 * ipinfo.io API returns "AS15169 Google LLC" in org field, or "AS15169" in asn field.
	 * MMDB returns "AS15169" in asn field.
	 *
	 * @param string|int|null $value
	 * @return int|null
	 */
	private function parse_asn( $value ): ?int {
		if ( null === $value ) {
			return null;
		}

		if ( is_int( $value ) ) {
			return $value;
		}

		$value = (string) $value;

		// "AS15169" or "AS15169 Google LLC"
		if ( preg_match( '/^AS?(\d+)/i', $value, $m ) ) {
			return (int) $m[1];
		}

		// Plain number.
		if ( ctype_digit( $value ) ) {
			return (int) $value;
		}

		return null;
	}

	/**
	 * Parse organization name from ipinfo.io "org" field.
	 * Format: "AS15169 Google LLC"
	 */
	private function parse_org_name( string $org ): ?string {
		if ( empty( $org ) ) {
			return null;
		}

		// Remove the "AS12345 " prefix.
		if ( preg_match( '/^AS?\d+\s+(.+)$/i', $org, $m ) ) {
			return $m[1];
		}

		return $org;
	}
}
