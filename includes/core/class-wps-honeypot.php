<?php
defined( 'ABSPATH' ) || exit;

/**
 * Rutas trampa (honeypot).
 *
 * Rutas que ningún visitante legítimo pide (`/.env`, copias de wp-config,
 * `/.git/`) pero que todo scanner automatizado prueba. Pedir una bloquea la IP
 * de inmediato y por más tiempo que un bloqueo común: la señal es inequívoca.
 *
 * Corre en la Capa 1 (antes de que WordPress procese la ruta) para peticiones
 * sin cookie de sesión, y en la Capa 2 con los permisos reales del usuario:
 * un administrador logueado nunca se bloquea a sí mismo, y una cookie falsa
 * no alcanza para esquivar la trampa.
 */
class WPS_Honeypot {

	/** Rutas por defecto. Un `*` final abarca todo lo que haya debajo. */
	const DEFAULT_PATHS = "/.env\n/.env.*\n/.git/*\n/.svn/*\n/.aws/*\n/.ssh/*\n/wp-config.php.bak\n/wp-config.php.old\n/wp-config.php.save\n/wp-config.php.orig\n/wp-config.php~\n/wp-config.bak\n/phpinfo.php\n/vendor/phpunit/*";

	/** Duración por defecto del bloqueo, en minutos (24 h). */
	const DEFAULT_BLOCK_MINUTES = 1440;

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Revisar la petición y bloquear si pide una ruta trampa.
	 *
	 * El llamador ya descartó whitelist, servidor y usuarios de confianza.
	 */
	public function check( WPS_Request $request ): void {
		if ( ! $this->loader->get_setting( 'honeypot_enabled', true ) ) {
			return;
		}

		$path = (string) wp_parse_url( $request->uri(), PHP_URL_PATH );
		$trap = self::match( $path, (string) $this->loader->get_setting( 'honeypot_paths', self::DEFAULT_PATHS ) );

		if ( null === $trap ) {
			return;
		}

		$ip      = $request->ip();
		$minutes = (int) $this->loader->get_setting( 'honeypot_block_minutes', self::DEFAULT_BLOCK_MINUTES );

		WPS_Logger::get_instance()->event_immediate( WPS_Event_Types::HONEYPOT_TRIGGERED, array(
			'ip_address'  => $ip,
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array( 'trap' => $trap ),
		) );

		$blocker = WPS_Blocker::get_instance();
		$blocker->block_offender( $ip, 'auto_honeypot', sprintf( 'Ruta trampa: %s', $trap ), $minutes > 0 ? $minutes : self::DEFAULT_BLOCK_MINUTES );
		$blocker->send_block_response( 'Acceso denegado' );
	}

	/**
	 * ¿La ruta coincide con alguna trampa?
	 *
	 * Se compara el final de la ruta, sin distinguir mayúsculas, para que
	 * funcione con WordPress instalado en un subdirectorio. Una trampa que
	 * termina en `*` coincide con cualquier ruta que contenga su prefijo.
	 *
	 * @param string $path  Ruta pedida, sin query string.
	 * @param string $traps Trampas, una por línea.
	 * @return string|null La trampa que coincidió.
	 */
	public static function match( string $path, string $traps ): ?string {
		$path = strtolower( rawurldecode( $path ) );
		if ( '' === $path ) {
			return null;
		}

		foreach ( preg_split( '/\r\n|\r|\n/', $traps ) as $trap ) {
			$trap = strtolower( trim( $trap ) );
			if ( '' === $trap || '/' === $trap || '/*' === $trap ) {
				continue;
			}

			if ( '*' === substr( $trap, -1 ) ) {
				if ( false !== strpos( $path, substr( $trap, 0, -1 ) ) ) {
					return $trap;
				}
				continue;
			}

			if ( substr( $path, -strlen( $trap ) ) === $trap ) {
				return $trap;
			}
		}

		return null;
	}
}
