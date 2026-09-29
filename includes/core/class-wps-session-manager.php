<?php
defined( 'ABSPATH' ) || exit;

/**
 * Sesiones activas de los usuarios.
 *
 * WordPress guarda las sesiones de cada usuario en el meta `session_tokens`,
 * indexadas por el hash del token (el "verificador"). Con eso se pueden
 * listar y cerrar una por una, sin conocer el token de la cookie.
 *
 * Además permite limitar las sesiones simultáneas de los administradores: al
 * iniciar una sesión nueva se cierran las más viejas que excedan el límite.
 */
class WPS_Session_Manager {

	/** Meta donde WordPress guarda las sesiones. */
	const META_KEY = 'session_tokens';

	/**
	 * Sesiones vigentes de todos los usuarios.
	 *
	 * @return array[] Filas con user_id, verifier, ip, ua, login, expiration.
	 */
	public static function all(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT user_id, meta_value FROM {$wpdb->usermeta} WHERE meta_key = %s", self::META_KEY ),
			ARRAY_A
		);

		$sessions = array();
		foreach ( (array) $rows as $row ) {
			foreach ( self::parse( (int) $row['user_id'], maybe_unserialize( $row['meta_value'] ) ) as $session ) {
				$sessions[] = $session;
			}
		}

		usort( $sessions, function ( $a, $b ) {
			return $b['login'] <=> $a['login'];
		} );

		return $sessions;
	}

	/**
	 * Sesiones vigentes de un usuario, de la más nueva a la más vieja.
	 */
	public static function for_user( int $user_id ): array {
		$sessions = self::parse( $user_id, get_user_meta( $user_id, self::META_KEY, true ) );

		usort( $sessions, function ( $a, $b ) {
			return $b['login'] <=> $a['login'];
		} );

		return $sessions;
	}

	/**
	 * Cerrar una sesión de un usuario.
	 *
	 * @param string $verifier Hash del token (clave en `session_tokens`).
	 */
	public static function destroy( int $user_id, string $verifier ): bool {
		$tokens = get_user_meta( $user_id, self::META_KEY, true );
		if ( ! is_array( $tokens ) || ! isset( $tokens[ $verifier ] ) ) {
			return false;
		}

		unset( $tokens[ $verifier ] );
		update_user_meta( $user_id, self::META_KEY, $tokens );

		return true;
	}

	/**
	 * Cerrar todas las sesiones de un usuario.
	 */
	public static function destroy_all( int $user_id ): void {
		if ( class_exists( 'WP_Session_Tokens' ) ) {
			WP_Session_Tokens::get_instance( $user_id )->destroy_all();
			return;
		}

		update_user_meta( $user_id, self::META_KEY, array() );
	}

	/**
	 * Cerrar las sesiones más viejas que excedan el límite.
	 *
	 * Se llama al iniciar sesión: la sesión nueva ya está guardada y es la
	 * más reciente, así que nunca se cierra.
	 *
	 * @return int Sesiones cerradas.
	 */
	public static function enforce_limit( int $user_id, int $max ): int {
		if ( $max <= 0 ) {
			return 0;
		}

		$closed = 0;
		foreach ( array_slice( self::for_user( $user_id ), $max ) as $session ) {
			if ( self::destroy( $user_id, $session['verifier'] ) ) {
				$closed++;
			}
		}

		return $closed;
	}

	/**
	 * Hash del token de la sesión actual, para marcarla en el listado.
	 */
	public static function current_verifier(): string {
		$token = function_exists( 'wp_get_session_token' ) ? wp_get_session_token() : '';

		return '' !== $token ? hash( 'sha256', $token ) : '';
	}

	/**
	 * @param mixed $tokens Valor de `session_tokens`.
	 * @return array[]
	 */
	private static function parse( int $user_id, $tokens ): array {
		if ( ! is_array( $tokens ) ) {
			return array();
		}

		$now      = time();
		$sessions = array();

		foreach ( $tokens as $verifier => $data ) {
			if ( ! is_array( $data ) || (int) ( $data['expiration'] ?? 0 ) < $now ) {
				continue;
			}

			$sessions[] = array(
				'user_id'    => $user_id,
				'verifier'   => (string) $verifier,
				'ip'         => (string) ( $data['ip'] ?? '' ),
				'ua'         => (string) ( $data['ua'] ?? '' ),
				'login'      => (int) ( $data['login'] ?? 0 ),
				'expiration' => (int) $data['expiration'],
			);
		}

		return $sessions;
	}
}
