<?php
defined( 'ABSPATH' ) || exit;

/**
 * Verificación de crawlers legítimos por reverse DNS.
 *
 * Confirma la identidad de crawlers conocidos (Googlebot, Bingbot, etc.)
 * mediante verificación PTR + forward DNS, evitando spoofing de User-Agent.
 */
class WPS_Crawler_Verifier {

	/** @var WPS_Crawler_Verifier|null */
	private static $instance = null;

	/** Resultado: crawler legítimo verificado. */
	const RESULT_LEGITIMATE = 'legitimate';

	/** Resultado: spoofing detectado. */
	const RESULT_SPOOFED = 'spoofed';

	/** Resultado: no es un crawler conocido. */
	const RESULT_UNKNOWN = 'unknown';

	/**
	 * Definición de crawlers verificables.
	 * Cada entrada contiene: regex para UA y dominios válidos para rDNS.
	 *
	 * @var array
	 */
	private static $crawlers = array(
		'googlebot' => array(
			'ua'      => '/Googlebot|Google-InspectionTool|Storebot-Google|GoogleOther/i',
			'domains' => array( '.googlebot.com', '.google.com' ),
		),
		'bingbot' => array(
			'ua'      => '/bingbot|msnbot|BingPreview/i',
			'domains' => array( '.search.msn.com' ),
		),
		'yandexbot' => array(
			'ua'      => '/YandexBot|YandexAccessibilityBot|YandexImages|YandexVideo/i',
			'domains' => array( '.yandex.com', '.yandex.ru', '.yandex.net' ),
		),
		'baidubot' => array(
			'ua'      => '/Baiduspider/i',
			'domains' => array( '.baidu.com', '.baidu.jp' ),
		),
		'duckduckbot' => array(
			'ua'      => '/DuckDuckBot/i',
			'domains' => array( '.duckduckgo.com' ),
		),
		'applebot' => array(
			'ua'      => '/Applebot/i',
			'domains' => array( '.applebot.apple.com' ),
		),
		'facebookbot' => array(
			'ua'      => '/facebookexternalhit|Facebot/i',
			'domains' => array( '.facebook.com', '.fbcdn.net', '.fb.com', '.tfbnw.net', '.meta.com' ),
			'asns'    => array( 32934 ),
		),
		'linkedinbot' => array(
			'ua'      => '/LinkedInBot/i',
			'domains' => array( '.linkedin.com' ),
		),
	);

	/** @var string Prefijo del transient para cache rDNS. */
	private static $cache_prefix = 'wps_rdns_';

	private function __construct() {}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Verificar si una IP con un User-Agent dado es un crawler legítimo.
	 *
	 * @param string $ip         Dirección IP.
	 * @param string $user_agent User-Agent de la petición.
	 * @return string RESULT_LEGITIMATE | RESULT_SPOOFED | RESULT_UNKNOWN
	 */
	public function verify( string $ip, string $user_agent ): string {
		$crawler_id = $this->identify_crawler_ua( $user_agent );

		if ( null === $crawler_id ) {
			return self::RESULT_UNKNOWN;
		}

		// Verificar cache.
		$cached = $this->get_cache( $ip );
		if ( null !== $cached ) {
			return $cached;
		}

		// Verificar rDNS.
		$result = $this->verify_rdns( $ip, self::$crawlers[ $crawler_id ]['domains'] );

		// Fallback: verificar por ASN si rDNS falla y el crawler tiene ASNs definidos.
		if ( self::RESULT_SPOOFED === $result && ! empty( self::$crawlers[ $crawler_id ]['asns'] ) ) {
			$result = $this->verify_asn( $ip, self::$crawlers[ $crawler_id ]['asns'] );
		}

		// Cachear resultado por 24 horas.
		$this->set_cache( $ip, $result );

		return $result;
	}

	/**
	 * Identificar si un User-Agent corresponde a un crawler conocido.
	 *
	 * @return string|null ID del crawler o null.
	 */
	public function identify_crawler_ua( string $user_agent ): ?string {
		foreach ( self::$crawlers as $id => $def ) {
			if ( preg_match( $def['ua'], $user_agent ) ) {
				return $id;
			}
		}
		return null;
	}

	/**
	 * Verificar IP mediante reverse DNS (PTR) + forward DNS.
	 *
	 * Algoritmo:
	 * 1. gethostbyaddr($ip) → obtener hostname PTR
	 * 2. Verificar que el hostname termina en un dominio esperado
	 * 3. gethostbyname($hostname) → resolver hostname a IP
	 * 4. Verificar que la IP resuelta coincide con la original
	 *
	 * @param string $ip      IP a verificar.
	 * @param array  $domains Dominios esperados (con punto inicial).
	 * @return string RESULT_LEGITIMATE | RESULT_SPOOFED
	 */
	private function verify_rdns( string $ip, array $domains ): string {
		// Paso 1: Reverse DNS.
		$hostname = gethostbyaddr( $ip );
		if ( $hostname === $ip || empty( $hostname ) ) {
			return self::RESULT_SPOOFED;
		}

		// Paso 2: Verificar dominio.
		$domain_match = false;
		foreach ( $domains as $domain ) {
			if ( substr( $hostname, -strlen( $domain ) ) === $domain ) {
				$domain_match = true;
				break;
			}
		}

		if ( ! $domain_match ) {
			return self::RESULT_SPOOFED;
		}

		// Paso 3-4: Forward DNS y comparar.
		$resolved_ip = gethostbyname( $hostname );
		if ( $resolved_ip === $hostname ) {
			// gethostbyname devuelve el hostname si no puede resolver.
			return self::RESULT_SPOOFED;
		}

		if ( $resolved_ip !== $ip ) {
			return self::RESULT_SPOOFED;
		}

		return self::RESULT_LEGITIMATE;
	}

	/**
	 * Obtener resultado cacheado.
	 */
	private function get_cache( string $ip ): ?string {
		$key   = self::$cache_prefix . md5( $ip );
		$value = get_transient( $key );
		return false === $value ? null : $value;
	}

	/**
	 * Guardar resultado en cache (24 horas).
	 */
	private function set_cache( string $ip, string $result ): void {
		$key = self::$cache_prefix . md5( $ip );
		set_transient( $key, $result, DAY_IN_SECONDS );
	}

	/**
	 * Verificar IP mediante ASN como fallback cuando rDNS no es confiable.
	 *
	 * Algunos crawlers legítimos (Facebook, etc.) no siempre tienen rDNS
	 * coherente, pero sus IPs pertenecen a ASNs conocidos y verificables.
	 *
	 * @param string $ip   IP a verificar.
	 * @param array  $asns ASNs esperados del crawler.
	 * @return string RESULT_LEGITIMATE | RESULT_SPOOFED
	 */
	private function verify_asn( string $ip, array $asns ): string {
		if ( ! class_exists( 'WPS_Geo' ) ) {
			return self::RESULT_SPOOFED;
		}

		$geo = WPS_Geo::get_instance();
		$info = $geo->lookup( $ip );

		if ( ! empty( $info['asn'] ) && in_array( (int) $info['asn'], $asns, true ) ) {
			return self::RESULT_LEGITIMATE;
		}

		return self::RESULT_SPOOFED;
	}

	/**
	 * Obtener la lista de IDs de crawlers conocidos.
	 *
	 * @return array
	 */
	public static function get_known_crawler_ids(): array {
		return array_keys( self::$crawlers );
	}
}
