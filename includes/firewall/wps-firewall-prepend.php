<?php
/**
 * WP Seguro — Capa 0: Firewall PHP (auto_prepend_file).
 *
 * Este archivo se ejecuta ANTES de cualquier otro script PHP gracias
 * a la directiva auto_prepend_file en .htaccess o .user.ini.
 *
 * NO carga WordPress ni conecta a base de datos.
 * Trabaja exclusivamente con un archivo de IPs bloqueadas en disco.
 *
 * Flujo:
 * 1. Obtener la IP del visitante.
 * 2. Comprobar si está en la whitelist local.
 * 3. Comprobar si está bloqueada (IPs individuales, CIDRs).
 * 4. Si bloqueada → 403 + log mínimo → die().
 * 5. Si no → no hacer nada, PHP continúa con el script original.
 *
 * @package WP_Secure
 */

// Evitar doble carga.
if ( defined( 'WPS_FIREWALL_LOADED' ) ) {
	return;
}
define( 'WPS_FIREWALL_LOADED', true );

/**
 * Clase contenedora del firewall de Capa 0.
 * Estática, sin dependencias externas.
 */
final class WPS_Firewall_Prepend {

	/**
	 * Ruta al archivo de datos de bloqueo.
	 * Se configura automáticamente desde la ubicación de este archivo.
	 *
	 * @var string
	 */
	private static $data_file = '';

	/**
	 * Ejecutar el firewall.
	 */
	public static function run(): void {
		// Calcular ruta al data file (fuera del directorio del plugin para sobrevivir updates).
		self::$data_file = self::resolve_data_dir() . 'wps-blocked-ips.php';

		// Si el data file no existe, no hay nada que bloquear.
		if ( ! is_file( self::$data_file ) ) {
			return;
		}

		$ip = self::get_client_ip();
		if ( ! $ip ) {
			return;
		}

		// Cargar datos de bloqueo.
		$data = self::load_data();
		if ( ! $data ) {
			return;
		}

		// Whitelist check.
		if ( self::is_whitelisted( $ip, $data ) ) {
			return;
		}

		// Block check.
		if ( self::is_blocked( $ip, $data ) ) {
			self::block_response( $ip );
		}
	}

	/**
	 * Resolver la ruta al directorio de datos wps-data/.
	 *
	 * Este archivo vive en: wp-content/plugins/wp-secure/includes/firewall/
	 * El directorio de datos está en: wp-content/wps-data/
	 * Se sube 4 niveles para llegar a wp-content.
	 */
	private static function resolve_data_dir(): string {
		return dirname( __DIR__, 4 ) . '/wps-data/';
	}

	/**
	 * Obtener la IP del cliente.
	 *
	 * Solo usa REMOTE_ADDR por seguridad. La detección de proxies
	 * se configura en la Capa 1/2 donde hay acceso a la configuración.
	 */
	private static function get_client_ip(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
		// Validar que sea una IP real.
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}
		return '';
	}

	/**
	 * Cargar el archivo de datos serializado.
	 *
	 * Estructura esperada del archivo:
	 * <?php return array(
	 *     'ips'       => array( '1.2.3.4' => 1, '5.6.7.8' => 1, ... ),
	 *     'cidrs'     => array( '10.0.0.0/8', '192.168.0.0/16', ... ),
	 *     'whitelist' => array( '127.0.0.1' => 1, ... ),
	 *     'updated'   => 1700000000,
	 * );
	 *
	 * @return array|null
	 */
	private static function load_data(): ?array {
		// Cargar solo si es un archivo PHP válido.
		$data = @include self::$data_file;

		if ( ! is_array( $data ) ) {
			return null;
		}

		return $data;
	}

	/**
	 * Comprobar si la IP está en whitelist.
	 */
	private static function is_whitelisted( string $ip, array $data ): bool {
		if ( empty( $data['whitelist'] ) ) {
			return false;
		}

		return isset( $data['whitelist'][ $ip ] );
	}

	/**
	 * Comprobar si la IP está bloqueada.
	 */
	private static function is_blocked( string $ip, array $data ): bool {
		// 1. Verificar IP individual (O(1) lookup en array).
		if ( ! empty( $data['ips'] ) && isset( $data['ips'][ $ip ] ) ) {
			return true;
		}

		// 2. Verificar CIDRs.
		if ( ! empty( $data['cidrs'] ) ) {
			foreach ( $data['cidrs'] as $cidr ) {
				if ( self::ip_in_cidr( $ip, $cidr ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Verificar si una IP está dentro de un rango CIDR.
	 * Implementación standalone sin dependencias.
	 */
	private static function ip_in_cidr( string $ip, string $cidr ): bool {
		if ( strpos( $cidr, '/' ) === false ) {
			return $ip === $cidr;
		}

		list( $subnet, $bits ) = explode( '/', $cidr, 2 );
		$bits = (int) $bits;

		$ip_bin     = inet_pton( $ip );
		$subnet_bin = inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		// Asegurar misma familia (IPv4 vs IPv6).
		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		// Construir máscara de red.
		$total_bits = strlen( $ip_bin ) * 8;
		if ( $bits > $total_bits || $bits < 0 ) {
			return false;
		}

		$mask = str_repeat( "\xff", intdiv( $bits, 8 ) );
		$remaining = $bits % 8;
		if ( $remaining > 0 ) {
			$mask .= chr( 0xff << ( 8 - $remaining ) & 0xff );
		}
		$mask = str_pad( $mask, strlen( $ip_bin ), "\x00" );

		return ( $ip_bin & $mask ) === ( $subnet_bin & $mask );
	}

	/**
	 * Enviar respuesta de bloqueo y terminar.
	 */
	private static function block_response( string $ip ): void {
		// Log mínimo a archivo (sin DB).
		self::log_block( $ip );

		// Respuesta HTTP 403.
		if ( ! headers_sent() ) {
			header( 'HTTP/1.1 403 Forbidden' );
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Connection: close' );
			header( 'Cache-Control: no-store, no-cache, must-revalidate' );
		}

		echo 'Access denied.';
		exit;
	}

	/**
	 * Log mínimo del bloqueo. Escribe en un archivo de texto simple.
	 */
	private static function log_block( string $ip ): void {
		$log_file = dirname( self::$data_file ) . '/wps-firewall.log';

		// No intentar crear el archivo si el directorio no es escribible.
		$dir = dirname( $log_file );
		if ( ! is_writable( $dir ) ) {
			return;
		}

		$line = sprintf(
			"[%s] BLOCKED %s %s %s\n",
			gmdate( 'Y-m-d H:i:s' ),
			$ip,
			isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '-',
			isset( $_SERVER['REQUEST_URI'] ) ? substr( $_SERVER['REQUEST_URI'], 0, 200 ) : '-'
		);

		// Append mode, suppress errors.
		@file_put_contents( $log_file, $line, FILE_APPEND | LOCK_EX );
	}
}

// Ejecutar inmediatamente.
WPS_Firewall_Prepend::run();
