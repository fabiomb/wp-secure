<?php
defined( 'ABSPATH' ) || exit;

/**
 * Configuración de CDN/Proxy para detección correcta de IP real.
 *
 * Resuelve la IP real del visitante de forma segura, verificando
 * que los headers de proxy solo se confíen cuando REMOTE_ADDR
 * proviene de un proxy/CDN conocido o configurado.
 */
class WPS_Proxy_Config {

	/** @var WPS_Proxy_Config|null */
	private static $instance = null;

	/** @var WPS_Loader|null */
	private $loader;

	/**
	 * Rangos IP de CDNs conocidos.
	 *
	 * @var array
	 */
	private static $cdn_ranges = array(
		'cloudflare' => array(
			// IPv6. Cloudflare alcanza el origen por IPv6 siempre que el
			// servidor tenga registro AAAA. Sin estos rangos la petición no se
			// reconoce como del CDN, get_real_ip() devuelve la IP del edge y
			// todo el tráfico del sitio colapsa en un puñado de direcciones:
			// el rate limiter las bloquea y el sitio se cae para todos.
			'2400:cb00::/32',
			'2606:4700::/32',
			'2803:f800::/32',
			'2405:b500::/32',
			'2405:8100::/32',
			'2a06:98c0::/29',
			'2c0f:f248::/32',
			// IPv4.
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'172.64.0.0/13',
			'131.0.72.0/22',
		),
		'sucuri' => array(
			'192.88.134.0/23',
			'185.93.228.0/22',
			'66.248.200.0/22',
			'208.109.0.0/22',
		),
	);

	/**
	 * Headers de IP real por CDN.
	 *
	 * @var array
	 */
	private static $cdn_headers = array(
		'cloudflare' => 'HTTP_CF_CONNECTING_IP',
		'sucuri'     => 'HTTP_X_SUCURI_CLIENTIP',
	);

	private function __construct() {}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Inyectar loader.
	 */
	public function set_loader( WPS_Loader $loader ): void {
		$this->loader = $loader;
	}

	/**
	 * Resolver la IP real del visitante de forma segura.
	 *
	 * Flujo:
	 * 1. Leer REMOTE_ADDR
	 * 2. Verificar si REMOTE_ADDR es un proxy confiable (configurado o CDN auto-detect)
	 * 3. Si confiable → leer el header apropiado
	 * 4. Si no confiable → usar REMOTE_ADDR directamente
	 *
	 * @return string IP del visitante real.
	 */
	public function get_real_ip(): string {
		$remote_addr = WPS_Ip_Utils::strip_port( $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0' );

		$proxy_mode = $this->get_setting( 'proxy_mode', 'auto' );

		// Modo none: siempre usar REMOTE_ADDR.
		if ( 'none' === $proxy_mode ) {
			return $remote_addr;
		}

		// Modo auto: detectar CDN por headers + rangos.
		if ( 'auto' === $proxy_mode ) {
			$cdn = $this->detect_cdn( $remote_addr );
			if ( $cdn ) {
				$header = self::$cdn_headers[ $cdn ] ?? null;
				if ( $header && ! empty( $_SERVER[ $header ] ) ) {
					$ip = $this->extract_ip( $_SERVER[ $header ] );
					if ( $ip ) {
						return $ip;
					}
				}
			}

			// Auto: también probar headers genéricos si REMOTE_ADDR es privada
			// (load balancer local). Se exige que sea una IP privada *válida*:
			// un REMOTE_ADDR ausente o malformado no es evidencia de que haya
			// un proxy delante, y tomarlo como tal habilitaría a falsificar la
			// IP de origen con un header.
			if ( WPS_Ip_Utils::is_valid_ip( $remote_addr ) && WPS_Ip_Utils::is_private_ip( $remote_addr ) ) {
				return $this->extract_from_generic_headers( $remote_addr );
			}

			return $remote_addr;
		}

		// Modos específicos: cloudflare, sucuri.
		if ( isset( self::$cdn_headers[ $proxy_mode ] ) ) {
			if ( $this->is_in_cdn_range( $remote_addr, $proxy_mode ) ) {
				$header = self::$cdn_headers[ $proxy_mode ];
				if ( ! empty( $_SERVER[ $header ] ) ) {
					$ip = $this->extract_ip( $_SERVER[ $header ] );
					if ( $ip ) {
						return $ip;
					}
				}
			}
			return $remote_addr;
		}

		// Modo custom: verificar contra lista configurada de proxies.
		if ( 'custom' === $proxy_mode ) {
			if ( $this->is_trusted_custom_proxy( $remote_addr ) ) {
				return $this->extract_from_configured_header( $remote_addr );
			}
			return $remote_addr;
		}

		return $remote_addr;
	}

	/**
	 * Autodetectar CDN verificando REMOTE_ADDR contra rangos conocidos.
	 *
	 * @return string|null Nombre del CDN detectado o null.
	 */
	public function detect_cdn( string $remote_addr ): ?string {
		// Primero verificar por headers específicos + rango.
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && $this->is_in_cdn_range( $remote_addr, 'cloudflare' ) ) {
			return 'cloudflare';
		}

		if ( ! empty( $_SERVER['HTTP_X_SUCURI_CLIENTIP'] ) && $this->is_in_cdn_range( $remote_addr, 'sucuri' ) ) {
			return 'sucuri';
		}

		return null;
	}

	/**
	 * Verificar si una IP está en los rangos de un CDN.
	 */
	public function is_in_cdn_range( string $ip, string $cdn ): bool {
		$ranges = self::$cdn_ranges[ $cdn ] ?? array();
		foreach ( $ranges as $cidr ) {
			if ( WPS_Ip_Utils::ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Verificar si una IP está en la lista de proxies confiables configurados.
	 */
	private function is_trusted_custom_proxy( string $ip ): bool {
		$trusted_raw = $this->get_setting( 'proxy_trusted_ips', '' );
		if ( empty( $trusted_raw ) ) {
			return false;
		}

		$trusted = array_filter( array_map( 'trim', explode( "\n", $trusted_raw ) ) );
		foreach ( $trusted as $entry ) {
			if ( false !== strpos( $entry, '/' ) ) {
				if ( WPS_Ip_Utils::ip_in_cidr( $ip, $entry ) ) {
					return true;
				}
			} elseif ( $entry === $ip ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Extraer IP del header configurado cuando se usa modo custom.
	 */
	private function extract_from_configured_header( string $fallback ): string {
		$header = $this->get_setting( 'proxy_header', 'HTTP_X_FORWARDED_FOR' );

		// Mapear nombres legibles a claves $_SERVER.
		$header_map = array(
			'CF-Connecting-IP'  => 'HTTP_CF_CONNECTING_IP',
			'X-Real-IP'        => 'HTTP_X_REAL_IP',
			'X-Forwarded-For'  => 'HTTP_X_FORWARDED_FOR',
			'X-Sucuri-ClientIP' => 'HTTP_X_SUCURI_CLIENTIP',
		);

		$server_key = $header_map[ $header ] ?? $header;

		if ( ! empty( $_SERVER[ $server_key ] ) ) {
			// X-Forwarded-For es una cadena de saltos que el cliente puede
			// prefijar; el resto de los headers llevan un único valor puesto
			// por el proxy.
			$from_closest_hop = ( 'HTTP_X_FORWARDED_FOR' === $server_key );

			$ip = $this->extract_ip( $_SERVER[ $server_key ], $from_closest_hop );
			if ( $ip ) {
				return $ip;
			}
		}

		return $fallback;
	}

	/**
	 * Extraer IP de headers genéricos (X-Forwarded-For, X-Real-IP).
	 *
	 * X-Forwarded-For tiene prioridad porque es el único header cuya cadena
	 * permite descartar los valores que inyecta el propio cliente: el proxy
	 * agrega la IP de la conexión al final, así que el salto de la derecha es
	 * el único que no controla el visitante. X-Real-IP se usa sólo como
	 * respaldo, ya que un cliente puede enviarlo y el proxy podría no
	 * sobrescribirlo.
	 */
	private function extract_from_generic_headers( string $fallback ): string {
		// X-Forwarded-For: usar el salto más cercano al proxy (derecha).
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip = $this->extract_ip( $_SERVER['HTTP_X_FORWARDED_FOR'], true );
			if ( $ip ) {
				return $ip;
			}
		}

		// X-Real-IP.
		if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
			$ip = $this->extract_ip( $_SERVER['HTTP_X_REAL_IP'] );
			if ( $ip ) {
				return $ip;
			}
		}

		return $fallback;
	}

	/**
	 * Extraer una IP pública válida de un valor de header.
	 *
	 * @param string $header_value Valor crudo del header.
	 * @param bool   $from_closest_hop Recorrer la cadena de derecha a izquierda,
	 *                                 para headers que el cliente puede prefijar.
	 */
	private function extract_ip( string $header_value, bool $from_closest_hop = false ): ?string {
		$parts = explode( ',', $header_value );

		if ( $from_closest_hop ) {
			$parts = array_reverse( $parts );
		}

		foreach ( $parts as $part ) {
			$ip = WPS_Ip_Utils::strip_port( trim( $part ) );
			if ( WPS_Ip_Utils::is_valid_ip( $ip ) && ! WPS_Ip_Utils::is_private_ip( $ip ) ) {
				return $ip;
			}
		}
		return null;
	}

	/**
	 * Helper para leer settings (funciona con o sin loader, para Layer 0).
	 */
	private function get_setting( string $key, $default = null ) {
		if ( $this->loader ) {
			return $this->loader->get_setting( $key, $default );
		}
		return $default;
	}
}
