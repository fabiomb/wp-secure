<?php
defined( 'ABSPATH' ) || exit;

/**
 * Escalada de bloqueos de IP a rango.
 *
 * Un atacante con un rango de un proveedor de hosting rota de IP en cada
 * bloqueo: cada una cae, pero la siguiente del mismo /24 ya está atacando.
 * Si varias IPs del mismo /24 (IPv4) o /48 (IPv6) reciben un bloqueo
 * automático en poco tiempo, se bloquea el rango completo por un tiempo.
 *
 * Nunca se bloquea un rango que contenga al propio servidor, una entrada de
 * la whitelist o una red desde la que un usuario ya inició sesión: el
 * bloqueo de rango no puede dejar afuera al administrador.
 */
class WPS_Range_Escalation {

	const BLOCK_TYPE = 'auto_range';

	/** Filas recientes que se revisan como máximo. */
	const MAX_ROWS = 2000;

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Blocker */
	private $blocker;

	public function __construct( WPS_Loader $loader, WPS_Blocker $blocker ) {
		$this->loader  = $loader;
		$this->blocker = $blocker;
	}

	public function enabled(): bool {
		return (bool) $this->loader->get_setting( 'range_escalation_enabled', true );
	}

	/**
	 * @return array{threshold: int, window: int, minutes: int}
	 */
	public function thresholds(): array {
		return array(
			'threshold' => max( 2, (int) $this->loader->get_setting( 'range_escalation_threshold', 3 ) ),
			'window'    => max( 5, (int) $this->loader->get_setting( 'range_escalation_window', 60 ) ),
			'minutes'   => max( 15, (int) $this->loader->get_setting( 'range_escalation_minutes', 1440 ) ),
		);
	}

	/**
	 * Rango al que escala una IP: /24 en IPv4, /48 en IPv6.
	 */
	public static function range_for( string $ip ): ?string {
		return WPS_Ip_Utils::is_valid_ip( $ip ) ? WPS_Ip_Utils::get_network( $ip ) : null;
	}

	/**
	 * Revisar el rango de una IP recién bloqueada y bloquearlo si corresponde.
	 *
	 * @return int|null ID del bloqueo del rango, o null si no se escaló.
	 */
	public function maybe_escalate( string $ip ): ?int {
		if ( ! $this->enabled() ) {
			return null;
		}

		$range = self::range_for( $ip );
		if ( null === $range ) {
			return null;
		}

		// Con un prefijo IPv6 de /48 cada cliente ya es el rango entero.
		if ( WPS_Ip_Utils::is_ipv6( $ip ) && $this->blocker->ipv6_prefix() <= 48 ) {
			return null;
		}

		$limits    = $this->thresholds();
		$offenders = self::count_offenders( $this->recent_rows( $range, $limits['window'] ), $range );

		if ( $offenders < $limits['threshold'] || $this->range_blocked( $range ) || null !== $this->protection( $range ) ) {
			return null;
		}

		$reason = sprintf(
			/* translators: 1: number of blocked clients, 2: range, 3: minutes */
			__( 'Escalada a rango: %1$d clientes de %2$s bloqueados en %3$d min', 'wp-secure' ),
			$offenders,
			$range,
			$limits['window']
		);

		$id = $this->blocker->block_cidr( $range, self::BLOCK_TYPE, $reason, $limits['minutes'] );
		if ( ! $id ) {
			return null;
		}

		WPS_Logger::get_instance()->event( WPS_Event_Types::IP_BLOCKED, array(
			'ip_address' => $ip,
			'details'    => array(
				'block_type' => self::BLOCK_TYPE,
				'reason'     => $reason,
				'network'    => $range,
				'offenders'  => $offenders,
				'duration'   => $limits['minutes'] . ' min',
			),
		) );

		return (int) $id;
	}

	/**
	 * Clientes distintos del rango entre las filas de bloqueos: IPs o redes
	 * (en IPv6 el cliente es una red, por defecto /64).
	 *
	 * @param array[] $rows Filas con ip_address y cidr.
	 */
	public static function count_offenders( array $rows, string $range ): int {
		$clients = array();

		foreach ( $rows as $row ) {
			$client = ! empty( $row['ip_address'] ) ? (string) $row['ip_address'] : (string) ( $row['cidr'] ?? '' );
			if ( '' === $client ) {
				continue;
			}

			$address = strtok( $client, '/' );
			if ( false !== $address && WPS_Ip_Utils::ip_in_cidr( $address, $range ) ) {
				$clients[ $client ] = true;
			}
		}

		return count( $clients );
	}

	/**
	 * ¿Se superponen dos rangos o IPs?
	 */
	public static function overlaps( string $a, string $b ): bool {
		$a_address = (string) strtok( $a, '/' );
		$b_address = (string) strtok( $b, '/' );
		$a_cidr    = false === strpos( $a, '/' ) ? $a . ( WPS_Ip_Utils::is_ipv6( $a ) ? '/128' : '/32' ) : $a;
		$b_cidr    = false === strpos( $b, '/' ) ? $b . ( WPS_Ip_Utils::is_ipv6( $b ) ? '/128' : '/32' ) : $b;

		return WPS_Ip_Utils::ip_in_cidr( $a_address, $b_cidr ) || WPS_Ip_Utils::ip_in_cidr( $b_address, $a_cidr );
	}

	/**
	 * Por qué no se puede bloquear un rango, o null si se puede.
	 */
	public function protection( string $range ): ?string {
		if ( $this->blocker->network_contains_server( $range ) ) {
			return 'server';
		}

		foreach ( $this->whitelist_entries() as $entry ) {
			if ( '' !== $entry && self::overlaps( $entry, $range ) ) {
				return 'whitelist';
			}
		}

		foreach ( $this->known_login_networks() as $network ) {
			if ( self::overlaps( $network, $range ) ) {
				return 'known_login';
			}
		}

		return null;
	}

	/*──────────────────────────────────────────────
	 * Datos (se reemplazan en los tests)
	 *──────────────────────────────────────────────*/

	/**
	 * Bloqueos automáticos recientes que pueden caer en el rango.
	 *
	 * Los que un administrador levantó a mano (inactivos sin vencer) no
	 * cuentan: fueron falsos positivos.
	 */
	protected function recent_rows( string $range, int $window_minutes ): array {
		$table = WPS_Db_Schema::table( 'blocked_ips' );
		$sql   = "SELECT ip_address, cidr FROM {$table}
			WHERE block_type LIKE 'auto\\_%%' AND block_type <> %s
			AND blocked_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)
			AND ( is_active = 1 OR ( expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP() ) )";
		$args  = array( self::BLOCK_TYPE, $window_minutes );

		// En IPv4 el /24 es un prefijo de texto: filtra en la consulta.
		if ( WPS_Ip_Utils::is_ipv4( (string) strtok( $range, '/' ) ) ) {
			$octets = explode( '.', (string) strtok( $range, '/' ) );
			$sql   .= ' AND ip_address LIKE %s';
			$args[] = implode( '.', array_slice( $octets, 0, 3 ) ) . '.%';
		}

		$sql   .= ' ORDER BY id DESC LIMIT %d';
		$args[] = self::MAX_ROWS;

		return WPS_Db::get_instance()->get_results( $sql, ...$args );
	}

	protected function range_blocked( string $range ): bool {
		$table = WPS_Db_Schema::table( 'blocked_ips' );

		return (bool) WPS_Db::get_instance()->get_var(
			"SELECT COUNT(*) FROM {$table} WHERE cidr = %s AND is_active = 1 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
			$range
		);
	}

	/**
	 * @return string[] IPs y rangos de la whitelist global.
	 */
	protected function whitelist_entries(): array {
		$entries = array();
		foreach ( WPS_Whitelist::get_instance()->get_all( 'global' ) as $row ) {
			$entries[] = ! empty( $row['cidr'] ) ? (string) $row['cidr'] : (string) ( $row['ip_address'] ?? '' );
		}
		return $entries;
	}

	/**
	 * Redes desde las que algún usuario ya inició sesión.
	 *
	 * @return string[]
	 */
	protected function known_login_networks(): array {
		global $wpdb;

		$networks = array();
		$meta_key = class_exists( 'WPS_Known_Clients' ) ? WPS_Known_Clients::META_KEY : 'wps_known_login_keys';
		$values   = $wpdb->get_col( $wpdb->prepare( "SELECT meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s", $meta_key ) );

		foreach ( (array) $values as $value ) {
			$known = maybe_unserialize( $value );
			if ( is_array( $known ) ) {
				$networks = array_merge( $networks, array_map( 'strval', array_keys( $known ) ) );
			}
		}

		return array_values( array_unique( $networks ) );
	}
}
