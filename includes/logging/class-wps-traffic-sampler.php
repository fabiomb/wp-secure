<?php
defined( 'ABSPATH' ) || exit;

/**
 * Qué peticiones se guardan en el log de tráfico y con qué peso.
 *
 * El log hace un INSERT por petición: en un sitio con mucho tráfico es la
 * escritura más frecuente del plugin. Con muestreo se guarda una de cada N
 * peticiones con peso N, así los totales del dashboard (SUM del peso) siguen
 * siendo una estimación sin sesgo. Las peticiones relevantes para seguridad
 * (errores 4xx/5xx y métodos distintos de GET/HEAD, como un POST a
 * wp-login.php) se guardan siempre, con peso 1.
 */
class WPS_Traffic_Sampler {

	const MODE_FULL     = 'full';
	const MODE_SAMPLED  = 'sampled';
	const MODE_RELEVANT = 'relevant';
	const MODE_OFF      = 'off';

	const DEFAULT_RATE = 10;

	/**
	 * Modo configurado, normalizado.
	 */
	public static function mode( WPS_Loader $loader ): string {
		$mode = (string) $loader->get_setting( 'traffic_log_mode', self::MODE_FULL );
		return in_array( $mode, array( self::MODE_SAMPLED, self::MODE_RELEVANT, self::MODE_OFF ), true ) ? $mode : self::MODE_FULL;
	}

	/**
	 * Tasa de muestreo configurada (1 de cada N).
	 */
	public static function rate( WPS_Loader $loader ): int {
		return max( 2, min( 1000, (int) $loader->get_setting( 'traffic_sample_rate', self::DEFAULT_RATE ) ) );
	}

	/**
	 * ¿La petición importa para seguridad y se guarda siempre?
	 */
	public static function is_relevant( string $method, ?int $status ): bool {
		return ! in_array( strtoupper( $method ), array( 'GET', 'HEAD' ), true ) || ( null !== $status && $status >= 400 );
	}

	/**
	 * Peso con el que se guarda la petición; 0 = no se guarda.
	 *
	 * @param int $draw Número al azar entre 1 y $rate (se inyecta en los tests).
	 */
	public static function weight( string $mode, int $rate, string $method, ?int $status, int $draw ): int {
		switch ( $mode ) {
			case self::MODE_OFF:
				return 0;

			case self::MODE_RELEVANT:
				return self::is_relevant( $method, $status ) ? 1 : 0;

			case self::MODE_SAMPLED:
				if ( self::is_relevant( $method, $status ) ) {
					return 1;
				}
				return 1 === $draw ? $rate : 0;
		}

		return 1;
	}

	/**
	 * Peso para la petición actual según la configuración.
	 */
	public static function weight_for( WPS_Loader $loader, string $method, ?int $status ): int {
		$mode = self::mode( $loader );
		$rate = self::rate( $loader );

		return self::weight( $mode, $rate, $method, $status, self::MODE_SAMPLED === $mode ? mt_rand( 1, $rate ) : 1 );
	}

	/**
	 * Aclaración para mostrar junto a los totales, o '' con el registro completo.
	 */
	public static function note( WPS_Loader $loader ): string {
		switch ( self::mode( $loader ) ) {
			case self::MODE_SAMPLED:
				/* translators: %d: sample rate */
				return sprintf( __( 'Registro con muestreo (1 de cada %d, más todos los errores y POST): los totales son estimaciones y las IPs únicas, un mínimo.', 'wp-secure' ), self::rate( $loader ) );
			case self::MODE_RELEVANT:
				return __( 'Sólo se registran errores y peticiones distintas de GET/HEAD: los totales cuentan sólo esas peticiones.', 'wp-secure' );
			case self::MODE_OFF:
				return __( 'El registro de tráfico está desactivado.', 'wp-secure' );
		}
		return '';
	}
}
