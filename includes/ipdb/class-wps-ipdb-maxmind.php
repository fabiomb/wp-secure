<?php
defined( 'ABSPATH' ) || exit;

/**
 * Datos y formato propios de MaxMind GeoLite2.
 *
 * MaxMind publica país y ASN en dos bases separadas (GeoLite2-Country y
 * GeoLite2-ASN) con una estructura de registro distinta a la de ipinfo.io,
 * así que cada archivo se guarda con nombre propio y se lee con su propio
 * mapeo. El servicio web GeoLite (City) devuelve ambos datos juntos.
 */
class WPS_Ipdb_Maxmind {

	/** Archivo local de la base de países. */
	const COUNTRY_FILENAME = 'maxmind-country.mmdb';

	/** Archivo local de la base de ASN. */
	const ASN_FILENAME = 'maxmind-asn.mmdb';

	/** Edición de la base de países. */
	const EDITION_COUNTRY = 'GeoLite2-Country';

	/** Edición de la base de ASN. */
	const EDITION_ASN = 'GeoLite2-ASN';

	/** Descarga autenticada; responde con una redirección a un CDN. */
	const DOWNLOAD_URL = 'https://download.maxmind.com/geoip/databases/%s/download?suffix=tar.gz';

	/** Servicio web GeoLite (gratuito, 1000 consultas por día). */
	const API_URL = 'https://geolite.info/geoip/v2.1/city/%s';

	/**
	 * Ediciones que se descargan, con el archivo local de cada una.
	 *
	 * @return array<string, string> edición => nombre de archivo.
	 */
	public static function editions(): array {
		return array(
			self::EDITION_COUNTRY => self::COUNTRY_FILENAME,
			self::EDITION_ASN     => self::ASN_FILENAME,
		);
	}

	/**
	 * Cabecera HTTP Basic con Account ID y License Key.
	 */
	public static function auth_header( string $account_id, string $license_key ): string {
		return 'Basic ' . base64_encode( $account_id . ':' . $license_key ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Combinar los registros de las bases locales de país y ASN.
	 *
	 * Si falta una de las dos se devuelve lo que aporte la otra.
	 *
	 * @param array|null $country Registro de GeoLite2-Country.
	 * @param array|null $asn     Registro de GeoLite2-ASN.
	 * @return array country, country_name, asn, asn_name.
	 */
	public static function map_local( ?array $country, ?array $asn ): array {
		$result = self::map_country( $country ?? array() );

		$result['asn']      = self::to_asn( $asn['autonomous_system_number'] ?? null );
		$result['asn_name'] = self::to_string( $asn['autonomous_system_organization'] ?? null );

		return $result;
	}

	/**
	 * Mapear la respuesta JSON del servicio web GeoLite City.
	 *
	 * @param array $data Respuesta decodificada.
	 * @return array country, country_name, asn, asn_name.
	 */
	public static function map_api( array $data ): array {
		$result = self::map_country( $data );

		$traits             = is_array( $data['traits'] ?? null ) ? $data['traits'] : array();
		$result['asn']      = self::to_asn( $traits['autonomous_system_number'] ?? null );
		$result['asn_name'] = self::to_string( $traits['autonomous_system_organization'] ?? null );

		return $result;
	}

	/**
	 * País de un registro con el formato de GeoLite2: `country`, y si no está
	 * (IPs anycast, satelitales), el país donde está registrada la red.
	 */
	private static function map_country( array $record ): array {
		$country = is_array( $record['country'] ?? null ) ? $record['country'] : array();
		if ( empty( $country['iso_code'] ) && is_array( $record['registered_country'] ?? null ) ) {
			$country = $record['registered_country'];
		}

		$code = self::to_string( $country['iso_code'] ?? null );

		return array(
			'country'      => null !== $code ? strtoupper( $code ) : null,
			'country_name' => self::to_string( $country['names']['en'] ?? null ),
		);
	}

	/**
	 * @param mixed $value
	 */
	private static function to_asn( $value ): ?int {
		if ( is_int( $value ) && $value > 0 ) {
			return $value;
		}
		if ( is_string( $value ) && ctype_digit( $value ) && (int) $value > 0 ) {
			return (int) $value;
		}
		return null;
	}

	/**
	 * @param mixed $value
	 */
	private static function to_string( $value ): ?string {
		return is_string( $value ) && '' !== $value ? $value : null;
	}
}
