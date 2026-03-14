<?php
defined( 'ABSPATH' ) || exit;

/**
 * Resolución IP→País/ASN.
 *
 * Clase de alto nivel que proporciona datos de geolocalización
 * usando el gestor de IPDB configurado.
 */
class WPS_Geo {

	/** @var WPS_Geo|null */
	private static $instance = null;

	/** @var WPS_Ipdb_Manager */
	private $ipdb;

	private function __construct() {
		$this->ipdb = WPS_Ipdb_Manager::get_instance();
	}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Resolve an IP to its country code.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return string|null ISO 3166-1 alpha-2 code or null.
	 */
	public function get_country( string $ip ): ?string {
		$data = $this->ipdb->lookup( $ip );
		return $data['country'] ?? null;
	}

	/**
	 * Resolve an IP to its country name.
	 */
	public function get_country_name( string $ip ): ?string {
		$data = $this->ipdb->lookup( $ip );
		return $data['country_name'] ?? null;
	}

	/**
	 * Resolve an IP to its ASN number.
	 *
	 * @return int|null ASN number without "AS" prefix.
	 */
	public function get_asn( string $ip ): ?int {
		$data = $this->ipdb->lookup( $ip );
		return $data['asn'] ?? null;
	}

	/**
	 * Resolve an IP to its ASN name.
	 */
	public function get_asn_name( string $ip ): ?string {
		$data = $this->ipdb->lookup( $ip );
		return $data['asn_name'] ?? null;
	}

	/**
	 * Get full geo data for an IP.
	 *
	 * @return array {
	 *     @type string|null $country      Country code.
	 *     @type string|null $country_name Country name.
	 *     @type int|null    $asn          ASN number.
	 *     @type string|null $asn_name     ASN org name.
	 *     @type string|null $source       'local' or 'api'.
	 * }
	 */
	public function lookup( string $ip ): array {
		return $this->ipdb->lookup( $ip );
	}

	/**
	 * Get a list of all country codes with their names (in Spanish).
	 *
	 * @return array Associative array: code => name.
	 */
	public static function get_countries_list(): array {
		return array(
			'AF' => 'Afganistán',
			'AL' => 'Albania',
			'DZ' => 'Argelia',
			'AS' => 'Samoa Americana',
			'AD' => 'Andorra',
			'AO' => 'Angola',
			'AI' => 'Anguila',
			'AQ' => 'Antártida',
			'AG' => 'Antigua y Barbuda',
			'AR' => 'Argentina',
			'AM' => 'Armenia',
			'AW' => 'Aruba',
			'AU' => 'Australia',
			'AT' => 'Austria',
			'AZ' => 'Azerbaiyán',
			'BS' => 'Bahamas',
			'BH' => 'Baréin',
			'BD' => 'Bangladés',
			'BB' => 'Barbados',
			'BY' => 'Bielorrusia',
			'BE' => 'Bélgica',
			'BZ' => 'Belice',
			'BJ' => 'Benín',
			'BM' => 'Bermudas',
			'BT' => 'Bután',
			'BO' => 'Bolivia',
			'BA' => 'Bosnia y Herzegovina',
			'BW' => 'Botsuana',
			'BR' => 'Brasil',
			'BN' => 'Brunéi',
			'BG' => 'Bulgaria',
			'BF' => 'Burkina Faso',
			'BI' => 'Burundi',
			'CV' => 'Cabo Verde',
			'KH' => 'Camboya',
			'CM' => 'Camerún',
			'CA' => 'Canadá',
			'KY' => 'Islas Caimán',
			'CF' => 'República Centroafricana',
			'TD' => 'Chad',
			'CL' => 'Chile',
			'CN' => 'China',
			'CO' => 'Colombia',
			'KM' => 'Comoras',
			'CG' => 'Congo',
			'CD' => 'R.D. del Congo',
			'CR' => 'Costa Rica',
			'CI' => 'Costa de Marfil',
			'HR' => 'Croacia',
			'CU' => 'Cuba',
			'CW' => 'Curazao',
			'CY' => 'Chipre',
			'CZ' => 'Chequia',
			'DK' => 'Dinamarca',
			'DJ' => 'Yibuti',
			'DM' => 'Dominica',
			'DO' => 'República Dominicana',
			'EC' => 'Ecuador',
			'EG' => 'Egipto',
			'SV' => 'El Salvador',
			'GQ' => 'Guinea Ecuatorial',
			'ER' => 'Eritrea',
			'EE' => 'Estonia',
			'SZ' => 'Esuatini',
			'ET' => 'Etiopía',
			'FJ' => 'Fiyi',
			'FI' => 'Finlandia',
			'FR' => 'Francia',
			'GF' => 'Guayana Francesa',
			'PF' => 'Polinesia Francesa',
			'GA' => 'Gabón',
			'GM' => 'Gambia',
			'GE' => 'Georgia',
			'DE' => 'Alemania',
			'GH' => 'Ghana',
			'GI' => 'Gibraltar',
			'GR' => 'Grecia',
			'GL' => 'Groenlandia',
			'GD' => 'Granada',
			'GP' => 'Guadalupe',
			'GU' => 'Guam',
			'GT' => 'Guatemala',
			'GN' => 'Guinea',
			'GW' => 'Guinea-Bisáu',
			'GY' => 'Guyana',
			'HT' => 'Haití',
			'HN' => 'Honduras',
			'HK' => 'Hong Kong',
			'HU' => 'Hungría',
			'IS' => 'Islandia',
			'IN' => 'India',
			'ID' => 'Indonesia',
			'IR' => 'Irán',
			'IQ' => 'Irak',
			'IE' => 'Irlanda',
			'IL' => 'Israel',
			'IT' => 'Italia',
			'JM' => 'Jamaica',
			'JP' => 'Japón',
			'JO' => 'Jordania',
			'KZ' => 'Kazajistán',
			'KE' => 'Kenia',
			'KI' => 'Kiribati',
			'KP' => 'Corea del Norte',
			'KR' => 'Corea del Sur',
			'KW' => 'Kuwait',
			'KG' => 'Kirguistán',
			'LA' => 'Laos',
			'LV' => 'Letonia',
			'LB' => 'Líbano',
			'LS' => 'Lesoto',
			'LR' => 'Liberia',
			'LY' => 'Libia',
			'LI' => 'Liechtenstein',
			'LT' => 'Lituania',
			'LU' => 'Luxemburgo',
			'MO' => 'Macao',
			'MG' => 'Madagascar',
			'MW' => 'Malaui',
			'MY' => 'Malasia',
			'MV' => 'Maldivas',
			'ML' => 'Malí',
			'MT' => 'Malta',
			'MH' => 'Islas Marshall',
			'MQ' => 'Martinica',
			'MR' => 'Mauritania',
			'MU' => 'Mauricio',
			'MX' => 'México',
			'FM' => 'Micronesia',
			'MD' => 'Moldavia',
			'MC' => 'Mónaco',
			'MN' => 'Mongolia',
			'ME' => 'Montenegro',
			'MS' => 'Montserrat',
			'MA' => 'Marruecos',
			'MZ' => 'Mozambique',
			'MM' => 'Myanmar',
			'NA' => 'Namibia',
			'NR' => 'Nauru',
			'NP' => 'Nepal',
			'NL' => 'Países Bajos',
			'NC' => 'Nueva Caledonia',
			'NZ' => 'Nueva Zelanda',
			'NI' => 'Nicaragua',
			'NE' => 'Níger',
			'NG' => 'Nigeria',
			'MK' => 'Macedonia del Norte',
			'NO' => 'Noruega',
			'OM' => 'Omán',
			'PK' => 'Pakistán',
			'PW' => 'Palaos',
			'PS' => 'Palestina',
			'PA' => 'Panamá',
			'PG' => 'Papúa Nueva Guinea',
			'PY' => 'Paraguay',
			'PE' => 'Perú',
			'PH' => 'Filipinas',
			'PL' => 'Polonia',
			'PT' => 'Portugal',
			'PR' => 'Puerto Rico',
			'QA' => 'Catar',
			'RE' => 'Reunión',
			'RO' => 'Rumania',
			'RU' => 'Rusia',
			'RW' => 'Ruanda',
			'SA' => 'Arabia Saudita',
			'SN' => 'Senegal',
			'RS' => 'Serbia',
			'SC' => 'Seychelles',
			'SL' => 'Sierra Leona',
			'SG' => 'Singapur',
			'SK' => 'Eslovaquia',
			'SI' => 'Eslovenia',
			'SB' => 'Islas Salomón',
			'SO' => 'Somalia',
			'ZA' => 'Sudáfrica',
			'SS' => 'Sudán del Sur',
			'ES' => 'España',
			'LK' => 'Sri Lanka',
			'SD' => 'Sudán',
			'SR' => 'Surinam',
			'SE' => 'Suecia',
			'CH' => 'Suiza',
			'SY' => 'Siria',
			'TW' => 'Taiwán',
			'TJ' => 'Tayikistán',
			'TZ' => 'Tanzania',
			'TH' => 'Tailandia',
			'TL' => 'Timor Oriental',
			'TG' => 'Togo',
			'TO' => 'Tonga',
			'TT' => 'Trinidad y Tobago',
			'TN' => 'Túnez',
			'TR' => 'Turquía',
			'TM' => 'Turkmenistán',
			'TV' => 'Tuvalu',
			'UG' => 'Uganda',
			'UA' => 'Ucrania',
			'AE' => 'Emiratos Árabes Unidos',
			'GB' => 'Reino Unido',
			'US' => 'Estados Unidos',
			'UY' => 'Uruguay',
			'UZ' => 'Uzbekistán',
			'VU' => 'Vanuatu',
			'VE' => 'Venezuela',
			'VN' => 'Vietnam',
			'YE' => 'Yemen',
			'ZM' => 'Zambia',
			'ZW' => 'Zimbabue',
		);
	}

	/**
	 * Get country name by code.
	 */
	public static function country_name( string $code ): string {
		$countries = self::get_countries_list();
		return $countries[ strtoupper( $code ) ] ?? $code;
	}
}
