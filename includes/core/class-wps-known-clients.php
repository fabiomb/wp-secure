<?php
defined( 'ABSPATH' ) || exit;

/**
 * Redes desde las que cada usuario inició sesión con éxito.
 *
 * Se identifican con la clave de cliente (en IPv6, el prefijo configurado) y
 * se guardan en user meta, no en la tabla de intentos, que se purga a los
 * pocos días. Las usan el aviso de login desde una red nueva y el límite de
 * intentos por cuenta, que deja entrar al dueño desde sus redes habituales
 * aunque la cuenta esté bajo ataque.
 */
class WPS_Known_Clients {

	/** User meta con las redes conocidas: clave de cliente => último uso. */
	const META_KEY = 'wps_known_login_keys';

	/** Redes recordadas por usuario (se descartan las más viejas). */
	const MAX = 20;

	/**
	 * Registrar un login exitoso.
	 *
	 * @return array{0: bool, 1: bool} [la red era nueva, el usuario tenía historial].
	 */
	public static function record( int $user_id, string $ip ): array {
		if ( $user_id <= 0 || ! WPS_Ip_Utils::is_valid_ip( $ip ) ) {
			return array( false, false );
		}

		$key   = WPS_Blocker::get_instance()->client_key( $ip );
		$known = self::all( $user_id );

		$is_new      = ! isset( $known[ $key ] );
		$had_history = ! empty( $known );

		$known[ $key ] = time();
		arsort( $known );
		update_user_meta( $user_id, self::META_KEY, array_slice( $known, 0, self::MAX, true ) );

		return array( $is_new, $had_history );
	}

	/**
	 * ¿El usuario ya inició sesión alguna vez desde la red de esta IP?
	 */
	public static function is_known( int $user_id, string $ip ): bool {
		if ( $user_id <= 0 || ! WPS_Ip_Utils::is_valid_ip( $ip ) ) {
			return false;
		}

		return isset( self::all( $user_id )[ WPS_Blocker::get_instance()->client_key( $ip ) ] );
	}

	/**
	 * @return array<string, int>
	 */
	private static function all( int $user_id ): array {
		$known = get_user_meta( $user_id, self::META_KEY, true );
		return is_array( $known ) ? $known : array();
	}
}
