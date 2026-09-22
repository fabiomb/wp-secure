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
	 * Resultado: el UA es de un crawler pero no se pudo verificar (DNS caído,
	 * timeout, sin datos de ASN). No es evidencia de falsificación: la petición
	 * sigue el análisis normal, sin el bloqueo por spoofing.
	 */
	const RESULT_UNVERIFIED = 'unverified';

	/** Segundos que se recuerda un resultado no verificable antes de reintentar. */
	const UNVERIFIED_TTL = 600;

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
			'domains' => array( '.facebook.com', '.fbcdn.net', '.fb.com', '.tfbnw.net', '.meta.com', '.fbsv.net' ),
			'asns'    => array( 32934 ),
		),
		'linkedinbot' => array(
			'ua'      => '/LinkedInBot/i',
			'domains' => array( '.linkedin.com' ),
		),
	);

	/** @var string Prefijo del transient para cache rDNS. */
	private static $cache_prefix = 'wps_rdns_';

	/**
	 * Resolver DNS alternativo (tests). Objeto con métodos
	 * `ptr( string $ip ): ?array` y `forward( string $host ): ?array`, que
	 * devuelven la lista de nombres/IPs o null si la consulta falló.
	 *
	 * @var object|null
	 */
	private $resolver = null;

	/**
	 * Reemplazar el resolver DNS. Null restaura el del sistema.
	 *
	 * @param object|null $resolver
	 */
	public function set_resolver( $resolver ): void {
		$this->resolver = $resolver;
	}

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
	 * @return string RESULT_LEGITIMATE | RESULT_SPOOFED | RESULT_UNVERIFIED | RESULT_UNKNOWN
	 */
	public function verify( string $ip, string $user_agent ): string {
		$crawler_id = $this->identify_crawler_ua( $user_agent );

		if ( null === $crawler_id ) {
			return self::RESULT_UNKNOWN;
		}

		// Verificar cache.
		$cache_id = $crawler_id . '|' . $ip;
		$cached   = $this->get_cache( $cache_id );
		if ( null !== $cached ) {
			return $cached;
		}

		// Verificar rDNS.
		$result = $this->verify_rdns( $ip, self::$crawlers[ $crawler_id ]['domains'] );

		// Fallback: verificar por ASN si rDNS no confirma y el crawler tiene ASNs definidos.
		if ( self::RESULT_LEGITIMATE !== $result && ! empty( self::$crawlers[ $crawler_id ]['asns'] ) ) {
			$by_asn = $this->verify_asn( $ip, self::$crawlers[ $crawler_id ]['asns'] );

			if ( self::RESULT_LEGITIMATE === $by_asn ) {
				$result = self::RESULT_LEGITIMATE;
			} elseif ( self::RESULT_UNVERIFIED === $by_asn ) {
				// Sin datos de ASN no se puede condenar lo que el DNS no confirmó.
				$result = self::RESULT_UNVERIFIED;
			}
			// ASN ajeno: se mantiene el veredicto del DNS (spoofed o unverified).
		}

		// Un resultado firme se recuerda 24 horas; uno no verificable, unos
		// minutos, para reintentar sin consultar el DNS en cada petición.
		$ttl = ( self::RESULT_UNVERIFIED === $result ) ? self::UNVERIFIED_TTL : DAY_IN_SECONDS;
		$this->set_cache( $cache_id, $result, $ttl );

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
				// Evitar falsos positivos: algunos navegadores reales (p. ej.
				// webviews in-app de iOS) anexan tokens de bots de previsualización
				// social ("facebookexternalhit", "Facebot", "Twitterbot") al final
				// de un User-Agent de navegador completo. Esos tokens NO implican
				// que la petición sea del bot. Si el UA contiene la firma de un
				// navegador interactivo real, no lo tratamos como crawler.
				if ( 'facebookbot' === $id && $this->is_interactive_browser_ua( $user_agent ) ) {
					continue;
				}
				return $id;
			}
		}
		return null;
	}

	/**
	 * Detectar si un User-Agent corresponde a un navegador interactivo real.
	 *
	 * Los bots de previsualización social legítimos (facebookexternalhit, Facebot,
	 * Twitterbot) nunca emiten el token de versión de Safari ("Version/x.y Safari/")
	 * ni los marcadores de webview de iOS ("Mobile/xxxxx ... Safari"). Googlebot y
	 * otros crawlers tampoco emiten "Version/", por lo que esta comprobación no los
	 * afecta.
	 *
	 * @param string $user_agent User-Agent de la petición.
	 * @return bool true si parece un navegador interactivo real.
	 */
	private function is_interactive_browser_ua( string $user_agent ): bool {
		// Firma de Safari de escritorio/iOS: "Version/9.0.1 ... Safari/601.2.4".
		if ( preg_match( '#\bVersion/\d[\d.]*\s+(Mobile/\S+\s+)?Safari/#i', $user_agent ) ) {
			return true;
		}

		// Webviews/navegadores in-app de iOS basados en otros motores.
		if ( preg_match( '#\b(CriOS|FxiOS|EdgiOS|GSA)/\d#i', $user_agent ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Verificar IP mediante reverse DNS (PTR) + forward DNS.
	 *
	 * Algoritmo:
	 * 1. PTR de la IP → nombres de host.
	 * 2. Alguno debe terminar en un dominio esperado del crawler.
	 * 3. Ese nombre se resuelve (A y AAAA) y debe incluir la IP original.
	 *
	 * Distingue "el DNS dice que no" (spoofed) de "el DNS no respondió"
	 * (unverified). Tratar un timeout como falsificación bloqueaba a Googlebot
	 * real y cacheaba el veredicto 24 horas. La resolución directa consulta
	 * también AAAA: Googlebot rastrea por IPv6 y `gethostbyname()` sólo
	 * devolvía IPv4, así que nunca coincidía.
	 *
	 * @param string $ip      IP a verificar.
	 * @param array  $domains Dominios esperados (con punto inicial).
	 * @return string RESULT_LEGITIMATE | RESULT_SPOOFED | RESULT_UNVERIFIED
	 */
	private function verify_rdns( string $ip, array $domains ): string {
		$ip_bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $ip_bin ) {
			return self::RESULT_SPOOFED;
		}

		// Paso 1: Reverse DNS.
		$hostnames = $this->lookup_ptr( $ip );
		if ( null === $hostnames ) {
			return self::RESULT_UNVERIFIED;
		}

		$saw_failure = false;

		foreach ( $hostnames as $hostname ) {
			$hostname = strtolower( rtrim( $hostname, '.' ) );

			// Paso 2: Verificar dominio.
			if ( ! self::hostname_in_domains( $hostname, $domains ) ) {
				continue;
			}

			// Paso 3: Forward DNS y comparar.
			$resolved = $this->lookup_forward( $hostname );
			if ( null === $resolved ) {
				$saw_failure = true;
				continue;
			}

			foreach ( $resolved as $resolved_ip ) {
				if ( @inet_pton( $resolved_ip ) === $ip_bin ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					return self::RESULT_LEGITIMATE;
				}
			}
		}

		return $saw_failure ? self::RESULT_UNVERIFIED : self::RESULT_SPOOFED;
	}

	/**
	 * ¿El host pertenece a alguno de los dominios (".dominio.tld")?
	 */
	private static function hostname_in_domains( string $hostname, array $domains ): bool {
		foreach ( $domains as $domain ) {
			if ( substr( $hostname, -strlen( $domain ) ) === $domain ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Nombres PTR de una IP. Lista vacía si no tiene PTR; null si el DNS falló.
	 *
	 * @return string[]|null
	 */
	private function lookup_ptr( string $ip ): ?array {
		if ( $this->resolver ) {
			return $this->resolver->ptr( $ip );
		}

		$arpa = self::arpa_name( $ip );
		if ( null === $arpa || ! function_exists( 'dns_get_record' ) ) {
			return null;
		}

		// dns_get_record() devuelve array vacío ante NXDOMAIN o sin datos, y
		// false (con warning) ante un error del servidor o un timeout.
		$records = @dns_get_record( $arpa, DNS_PTR ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $records ) {
			return null;
		}

		return array_values( array_filter( array_column( $records, 'target' ) ) );
	}

	/**
	 * IPs (A y AAAA) de un nombre de host. Lista vacía si no resuelve; null si
	 * el DNS falló.
	 *
	 * @return string[]|null
	 */
	private function lookup_forward( string $hostname ): ?array {
		if ( $this->resolver ) {
			return $this->resolver->forward( $hostname );
		}

		if ( ! function_exists( 'dns_get_record' ) ) {
			return null;
		}

		$records = @dns_get_record( $hostname, DNS_A | DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $records ) {
			return null;
		}

		$ips = array();
		foreach ( $records as $record ) {
			if ( ! empty( $record['ip'] ) ) {
				$ips[] = $record['ip'];
			} elseif ( ! empty( $record['ipv6'] ) ) {
				$ips[] = $record['ipv6'];
			}
		}

		return $ips;
	}

	/**
	 * Nombre de la zona inversa para una IP (in-addr.arpa / ip6.arpa).
	 */
	public static function arpa_name( string $ip ): ?string {
		$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $packed ) {
			return null;
		}

		if ( 4 === strlen( $packed ) ) {
			return implode( '.', array_reverse( explode( '.', $ip ) ) ) . '.in-addr.arpa';
		}

		$nibbles = str_split( bin2hex( $packed ) );
		return implode( '.', array_reverse( $nibbles ) ) . '.ip6.arpa';
	}

	/**
	 * Obtener resultado cacheado.
	 */
	private function get_cache( string $cache_id ): ?string {
		$key   = self::$cache_prefix . md5( $cache_id );
		$value = get_transient( $key );
		return false === $value ? null : $value;
	}

	/**
	 * Guardar resultado en cache.
	 */
	private function set_cache( string $cache_id, string $result, int $ttl ): void {
		$key = self::$cache_prefix . md5( $cache_id );
		set_transient( $key, $result, $ttl );
	}

	/**
	 * Verificar IP mediante ASN como fallback cuando rDNS no es confiable.
	 *
	 * Algunos crawlers legítimos (Facebook, etc.) no siempre tienen rDNS
	 * coherente, pero sus IPs pertenecen a ASNs conocidos y verificables.
	 *
	 * @param string $ip   IP a verificar.
	 * @param array  $asns ASNs esperados del crawler.
	 * @return string RESULT_LEGITIMATE | RESULT_SPOOFED | RESULT_UNVERIFIED
	 */
	private function verify_asn( string $ip, array $asns ): string {
		if ( ! class_exists( 'WPS_Geo' ) ) {
			return self::RESULT_UNVERIFIED;
		}

		$info = WPS_Geo::get_instance()->lookup( $ip );

		// Sin base local ni API configurada no hay dato de ASN.
		if ( empty( $info['asn'] ) ) {
			return self::RESULT_UNVERIFIED;
		}

		if ( in_array( (int) $info['asn'], $asns, true ) ) {
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
