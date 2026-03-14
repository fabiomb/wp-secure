<?php
defined( 'ABSPATH' ) || exit;

/**
 * Gestión de la base de datos IP local.
 *
 * Coordina la resolución IP→País/ASN usando el modo configurado:
 * - API: consulta ipinfo.io en vivo con cache local.
 * - Local: lectura del archivo MMDB descargado.
 */
class WPS_Ipdb_Manager {

	/** @var WPS_Ipdb_Manager|null */
	private static $instance = null;

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Mmdb_Reader|null */
	private $reader = null;

	/** @var array In-memory cache of lookups for the current request. */
	private $cache = array();

	/** @var bool Whether the reader failed to load (avoid repeated attempts). */
	private $reader_failed = false;

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
		$default = array(
			'country'      => null,
			'country_name' => null,
			'asn'          => null,
			'asn_name'     => null,
			'source'       => null,
		);

		// Skip private/reserved IPs.
		if ( WPS_Ip_Utils::is_private_ip( $ip ) ) {
			return $default;
		}

		// In-memory cache (same request).
		if ( isset( $this->cache[ $ip ] ) ) {
			return $this->cache[ $ip ];
		}

		$mode   = $this->loader->get_setting( 'ipinfo_mode', 'api' );
		$result = $default;

		if ( 'local' === $mode ) {
			$result = $this->lookup_local( $ip );
			// Fallback to API if local fails.
			if ( null === $result['country'] && null === $result['asn'] ) {
				$result = $this->lookup_api( $ip );
			}
		} else {
			$result = $this->lookup_api( $ip );
		}

		$this->cache[ $ip ] = $result;
		return $result;
	}

	/**
	 * Look up using the local MMDB file.
	 */
	private function lookup_local( string $ip ): array {
		$default = array(
			'country'      => null,
			'country_name' => null,
			'asn'          => null,
			'asn_name'     => null,
			'source'       => 'local',
		);

		$reader = $this->get_reader();
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
	 * Look up using the ipinfo.io API with transient cache.
	 */
	private function lookup_api( string $ip ): array {
		$default = array(
			'country'      => null,
			'country_name' => null,
			'asn'          => null,
			'asn_name'     => null,
			'source'       => 'api',
		);

		$api_key = $this->loader->get_setting( 'ipinfo_api_key', '' );
		if ( empty( $api_key ) ) {
			return $default;
		}

		// Check transient cache first (2 hours).
		$cache_key = 'wps_geo_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached && is_array( $cached ) ) {
			$cached['source'] = 'api';
			return $cached;
		}

		// API request.
		$url = sprintf( 'https://ipinfo.io/%s?token=%s', rawurlencode( $ip ), rawurlencode( $api_key ) );

		$response = wp_remote_get( $url, array(
			'timeout'   => 5,
			'sslverify' => true,
			'headers'   => array( 'Accept' => 'application/json' ),
		) );

		if ( is_wp_error( $response ) ) {
			return $default;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $default;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return $default;
		}

		$result = array(
			'country'      => $data['country'] ?? null,
			'country_name' => $data['country_name'] ?? null,
			'asn'          => $this->parse_asn( $data['asn']['asn'] ?? ( $data['org'] ?? null ) ),
			'asn_name'     => $data['asn']['name'] ?? $this->parse_org_name( $data['org'] ?? '' ),
			'source'       => 'api',
		);

		// Cache for 2 hours.
		$to_cache = $result;
		unset( $to_cache['source'] );
		set_transient( $cache_key, $to_cache, 2 * HOUR_IN_SECONDS );

		return $result;
	}

	/**
	 * Get or initialize the MMDB reader.
	 */
	private function get_reader(): ?WPS_Mmdb_Reader {
		if ( $this->reader_failed ) {
			return null;
		}

		if ( null !== $this->reader ) {
			return $this->reader;
		}

		$mmdb_path = $this->get_mmdb_path();
		if ( ! $mmdb_path || ! is_file( $mmdb_path ) ) {
			$this->reader_failed = true;
			return null;
		}

		try {
			$this->reader = new WPS_Mmdb_Reader( $mmdb_path );
		} catch ( \RuntimeException $e ) {
			$this->reader_failed = true;
			return null;
		}

		return $this->reader;
	}

	/**
	 * Get the path to the current MMDB file.
	 */
	public function get_mmdb_path(): ?string {
		// Look for known MMDB files in the data directory.
		$data_dir = WPS_DATA_DIR;
		$files    = array(
			'country_asn.mmdb',
			'ipinfo-country-asn.mmdb',
			'asn.mmdb',
			'country.mmdb',
		);

		foreach ( $files as $file ) {
			$path = $data_dir . $file;
			if ( is_file( $path ) ) {
				return $path;
			}
		}

		return null;
	}

	/**
	 * Check if the local MMDB database is available.
	 */
	public function is_local_available(): bool {
		$path = $this->get_mmdb_path();
		return $path && is_file( $path );
	}

	/**
	 * Get info about the current MMDB database.
	 *
	 * @return array|null Info array or null if not available.
	 */
	public function get_database_info(): ?array {
		$path = $this->get_mmdb_path();
		if ( ! $path ) {
			return null;
		}

		try {
			$reader   = new WPS_Mmdb_Reader( $path );
			$metadata = $reader->get_metadata();
			$reader->close();

			return array(
				'path'       => $path,
				'file_size'  => filesize( $path ),
				'type'       => $metadata['database_type'] ?? 'unknown',
				'build_time' => (int) ( $metadata['build_epoch'] ?? 0 ),
				'ip_version' => (int) ( $metadata['ip_version'] ?? 0 ),
				'node_count' => (int) ( $metadata['node_count'] ?? 0 ),
			);
		} catch ( \RuntimeException $e ) {
			return null;
		}
	}

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
