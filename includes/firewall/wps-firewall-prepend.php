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
 * 0. Si el script pedido está en una carpeta sin PHP (uploads) → 403.
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

	/** Nombre del log. Es .php para que, pedido por web, no muestre nada. */
	const LOG_FILE = 'wps-firewall-log.php';

	/** Copia rotada del log. */
	const LOG_ROTATED = 'wps-firewall-log.1.php';

	/** Primera línea del log: corta la ejecución si se lo pide por web. */
	const LOG_GUARD = "<?php exit; ?>\n";

	/** Tamaño a partir del cual se rota el log. */
	const LOG_MAX_BYTES = 1048576;

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

		// Cargar datos de bloqueo.
		$data = self::load_data();
		if ( ! $data ) {
			return;
		}

		// PHP en la carpeta de subidas: nunca, ni para IPs en whitelist.
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
		if ( self::is_denied_script( $script, $data ) ) {
			self::block_response( self::get_client_ip(), 'DENIED_PHP' );
		}

		$ip = self::get_client_ip();
		if ( ! $ip ) {
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
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( $_SERVER['REMOTE_ADDR'] ) : '';
		// Eliminar puerto si viene en formato IPv4:puerto (exactamente un colon).
		if ( 1 === substr_count( $ip, ':' ) ) {
			$ip = (string) strstr( $ip, ':', true );
		}
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
	 *     'ips'             => array( '1.2.3.4' => 0, '5.6.7.8' => 1700000900, ... ),
	 *     'cidrs'           => array( '10.0.0.0/8' => 0, ... ),
	 *     'whitelist'       => array( '127.0.0.1' => 1, ... ),
	 *     'whitelist_cidrs' => array( '203.0.113.0/24', ... ),
	 *     'updated'         => 1700000000,
	 * );
	 *
	 * El valor de cada IP o CIDR bloqueado es el timestamp de vencimiento, o
	 * 0 si es permanente. Archivos de versiones anteriores (valor 1 en `ips`,
	 * lista plana en `cidrs`) se interpretan como bloqueos permanentes.
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
	 * ¿El script está dentro de una carpeta donde no se ejecuta PHP?
	 *
	 * Es lo que hace efectivo el bloqueo de PHP en uploads en nginx, que no
	 * lee .htaccess. Se resuelve la ruta real para que un enlace simbólico o
	 * un `..` no la esquiven.
	 */
	private static function is_denied_script( string $script, array $data ): bool {
		if ( empty( $data['deny_php_dirs'] ) || '' === $script ) {
			return false;
		}

		$real   = realpath( $script );
		$script = str_replace( '\\', '/', false !== $real ? $real : $script );

		foreach ( (array) $data['deny_php_dirs'] as $dir ) {
			$dir = rtrim( str_replace( '\\', '/', (string) $dir ), '/' ) . '/';
			if ( '/' !== $dir && 0 === strncasecmp( $script, $dir, strlen( $dir ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Comprobar si la IP está en whitelist.
	 */
	private static function is_whitelisted( string $ip, array $data ): bool {
		if ( ! empty( $data['whitelist'] ) && isset( $data['whitelist'][ $ip ] ) ) {
			return true;
		}

		if ( ! empty( $data['whitelist_cidrs'] ) ) {
			foreach ( $data['whitelist_cidrs'] as $cidr ) {
				if ( self::ip_in_cidr( $ip, (string) $cidr ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Comprobar si la IP está bloqueada.
	 */
	private static function is_blocked( string $ip, array $data ): bool {
		$now = time();

		// 1. Verificar IP individual (O(1) lookup en array).
		if ( ! empty( $data['ips'] ) && isset( $data['ips'][ $ip ] )
			&& self::is_active( (int) $data['ips'][ $ip ], $now ) ) {
			return true;
		}

		// 2. Verificar CIDRs.
		if ( ! empty( $data['cidrs'] ) ) {
			foreach ( $data['cidrs'] as $key => $value ) {
				// Formato anterior: lista plana de CIDRs, todos permanentes.
				$cidr    = is_int( $key ) ? (string) $value : (string) $key;
				$expires = is_int( $key ) ? 0 : (int) $value;

				if ( self::is_active( $expires, $now ) && self::ip_in_cidr( $ip, $cidr ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * ¿Sigue vigente un bloqueo con este vencimiento?
	 *
	 * 0 es permanente; 1 es el valor que usaban las versiones anteriores para
	 * marcar una IP y también se toma como permanente.
	 */
	private static function is_active( int $expires, int $now ): bool {
		return $expires <= 1 || $expires > $now;
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
	private static function block_response( string $ip, string $reason = 'BLOCKED' ): void {
		// Log mínimo a archivo (sin DB).
		self::log_block( $ip, $reason );

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
	private static function log_block( string $ip, string $reason = 'BLOCKED' ): void {
		$dir = dirname( self::$data_file );

		// No intentar crear el archivo si el directorio no es escribible.
		if ( ! is_writable( $dir ) ) {
			return;
		}

		$log_file = $dir . '/' . self::LOG_FILE;

		// Rotar por tamaño: se conserva sólo la copia anterior.
		if ( is_file( $log_file ) && filesize( $log_file ) > self::LOG_MAX_BYTES ) {
			@rename( $log_file, $dir . '/' . self::LOG_ROTATED );
		}

		$line = sprintf(
			"[%s] %s %s %s %s\n",
			gmdate( 'Y-m-d H:i:s' ),
			$reason,
			'' !== $ip ? $ip : '-',
			self::clean_log_value( isset( $_SERVER['REQUEST_METHOD'] ) ? (string) $_SERVER['REQUEST_METHOD'] : '-', 10 ),
			self::clean_log_value( isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '-', 200 )
		);

		// El log es un archivo PHP: la primera línea corta la ejecución.
		if ( ! is_file( $log_file ) ) {
			$line = self::LOG_GUARD . $line;
		}

		// Append mode, suppress errors.
		@file_put_contents( $log_file, $line, FILE_APPEND | LOCK_EX );
	}

	/**
	 * Limpiar un valor que controla el visitante antes de escribirlo al log.
	 *
	 * Sin caracteres de control (un salto de línea inventaría entradas) ni
	 * `<`/`>`: el log es un archivo PHP y no puede contener etiquetas.
	 */
	private static function clean_log_value( string $value, int $max_length ): string {
		$value = substr( $value, 0, $max_length );
		$value = str_replace( array( '<', '>' ), array( '%3C', '%3E' ), $value );

		return (string) preg_replace( '/[\x00-\x20\x7F]/', '?', $value );
	}
}

// Ejecutar inmediatamente.
WPS_Firewall_Prepend::run();
