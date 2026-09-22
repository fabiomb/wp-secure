<?php
defined( 'ABSPATH' ) || exit;

/**
 * Motor de evaluación de riesgos.
 *
 * Asigna puntuación a cada petición basándose en múltiples factores
 * (IP, User-Agent, tipo de petición, historial) y aplica la acción
 * correspondiente según los umbrales configurados.
 *
 * Umbrales:
 *   0-30  → Sin acción
 *  31-50  → Log como sospechoso
 *  51-80  → Rate limiting estricto
 *  81-100 → Bloqueo temporal
 *  >100   → Bloqueo inmediato
 *
 * Modos de operación (ajuste `risk_engine_mode`):
 *   off     → no se evalúa nada; comportamiento y costo idénticos a no tenerlo.
 *   shadow  → puntúa y registra qué habría hecho, sin bloquear nunca.
 *   enforce → puntúa y aplica la acción correspondiente.
 *
 * El default es `off` a propósito. Los puntajes de esta tabla nunca corrieron
 * contra tráfico real, así que activarlos de golpe en un sitio en producción
 * empezaría a bloquear visitantes con umbrales que nadie calibró. El camino
 * previsto es: encender `shadow`, mirar los eventos registrados durante unos
 * días, y recién entonces pasar a `enforce`.
 */
class WPS_Rules_Engine {

	/** Modo apagado: el motor no evalúa. */
	const MODE_OFF = 'off';

	/** Modo sombra: evalúa y registra, sin bloquear. */
	const MODE_SHADOW = 'shadow';

	/** Modo activo: evalúa y aplica la acción. */
	const MODE_ENFORCE = 'enforce';

	/** @var WPS_Rules_Engine|null */
	private static $instance = null;

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Logger */
	private $logger;

	/** @var WPS_Blocker */
	private $blocker;

	/**
	 * Puntuaciones por factor.
	 *
	 * @var array
	 */
	private static $scores = array(
		'datacenter_ip'       => 10,
		'risky_country'       => 15,
		'empty_ua'            => 20,
		'tool_ua'             => 25,
		'high_rate'           => 20,
		'suspicious_path'     => 30,
		'login_fail'          => 15,
		'xmlrpc_access'       => 20,
		'sqli_pattern'        => 50,
		'xss_pattern'         => 40,
		'traversal_pattern'   => 40,
		'nonexistent_user'    => 25,
		'multiple_404'        => 5,
	);

	/**
	 * Umbrales de acción.
	 *
	 * @var array
	 */
	private static $thresholds = array(
		'log'          => 31,
		'strict_rate'  => 51,
		'temp_block'   => 81,
		'hard_block'   => 101,
	);

	/**
	 * Patrones de User-Agent de herramientas.
	 *
	 * @var array
	 */
	private static $tool_ua_patterns = array(
		'/\bcurl\b/i',
		'/\bwget\b/i',
		'/\bpython-requests?\b/i',
		'/\bhttp-client\b/i',
		'/\bgo-http-client\b/i',
		'/\bnode-fetch\b/i',
		'/\baxios\b/i',
		'/\bpostman\b/i',
		'/\binsomnia\b/i',
		'/\blibwww-perl\b/i',
		'/\bjava\//i',
	);

	/**
	 * Rutas sospechosas (no cubiertas por otros detectores).
	 *
	 * @var array
	 */
	private static $suspicious_paths = array(
		'/\/wp-admin\/install\.php\b/i',
		'/\/wp-admin\/setup-config\.php\b/i',
		'/\/xmlrpc\.php\b/i',
		'/\/wp-trackback\.php\b/i',
		'/\/wp-cron\.php\b.*\?/i',
	);

	private function __construct( WPS_Loader $loader ) {
		$this->loader  = $loader;
		$this->logger  = WPS_Logger::get_instance();
		$this->blocker = WPS_Blocker::get_instance();
	}

	/**
	 * @param WPS_Loader|null $loader Requerido en la primera llamada.
	 */
	public static function get_instance( WPS_Loader $loader = null ): self {
		if ( null === self::$instance ) {
			if ( null === $loader ) {
				$loader = WPS_Loader::get_instance();
			}
			self::$instance = new self( $loader );
		}
		return self::$instance;
	}

	/*──────────────────────────────────────────────
	 * Modo de operación
	 *──────────────────────────────────────────────*/

	/**
	 * Modo configurado, normalizado.
	 */
	public function mode(): string {
		$mode = (string) $this->loader->get_setting( 'risk_engine_mode', self::MODE_OFF );

		$valid = array( self::MODE_OFF, self::MODE_SHADOW, self::MODE_ENFORCE );

		return in_array( $mode, $valid, true ) ? $mode : self::MODE_OFF;
	}

	/**
	 * ¿El motor evalúa peticiones?
	 */
	public function is_enabled(): bool {
		return self::MODE_OFF !== $this->mode();
	}

	/**
	 * ¿El motor aplica las acciones que decide?
	 */
	public function is_enforcing(): bool {
		return self::MODE_ENFORCE === $this->mode();
	}

	/**
	 * Acción que corresponde a un puntaje.
	 *
	 * @return string none|log|strict_rate|temp_block|hard_block
	 */
	public function action_for_score( int $score ): string {
		if ( $score >= self::$thresholds['hard_block'] ) {
			return 'hard_block';
		}
		if ( $score >= self::$thresholds['temp_block'] ) {
			return 'temp_block';
		}
		if ( $score >= self::$thresholds['strict_rate'] ) {
			return 'strict_rate';
		}
		if ( $score >= self::$thresholds['log'] ) {
			return 'log';
		}

		return 'none';
	}

	/**
	 * Evaluar una petición y retornar la puntuación de riesgo.
	 *
	 * @param WPS_Request $request Petición a evaluar.
	 * @param array       $context Contexto adicional de otros detectores.
	 *                             Claves opcionales: sqli, xss, traversal,
	 *                             login_fails, is_404, country_code.
	 * @return int Puntuación de riesgo.
	 */
	public function evaluate( WPS_Request $request, array $context = array() ): int {
		return $this->assess( $request, $context )['score'];
	}

	/**
	 * Evaluar una petición y devolver el detalle completo.
	 *
	 * Los factores se devuelven además del puntaje para poder registrarlos: sin
	 * saber *qué* sumó, un puntaje suelto en el log no sirve para calibrar los
	 * umbrales.
	 *
	 * @param WPS_Request $request Petición a evaluar.
	 * @param array       $context Contexto adicional de otros detectores.
	 * @return array{score:int, factors:string[], action:string}
	 */
	public function assess( WPS_Request $request, array $context = array() ): array {
		$score   = 0;
		$factors = array();

		$ip         = $request->ip();
		$user_agent = $request->user_agent();
		$uri        = $request->uri();

		// 1. User-Agent vacío.
		if ( empty( $user_agent ) ) {
			$score += self::$scores['empty_ua'];
			$factors[] = 'empty_ua';
		}

		// 2. User-Agent de herramienta.
		if ( $user_agent ) {
			foreach ( self::$tool_ua_patterns as $pattern ) {
				if ( preg_match( $pattern, $user_agent ) ) {
					$score += self::$scores['tool_ua'];
					$factors[] = 'tool_ua';
					break;
				}
			}
		}

		// 3. Ruta sospechosa.
		foreach ( self::$suspicious_paths as $pattern ) {
			if ( preg_match( $pattern, $uri ) ) {
				$score += self::$scores['suspicious_path'];
				$factors[] = 'suspicious_path';
				break;
			}
		}

		// 4. Acceso a xmlrpc.php.
		if ( 'xmlrpc' === $request->visitor_type() ) {
			$score += self::$scores['xmlrpc_access'];
			$factors[] = 'xmlrpc_access';
		}

		// 5. Detecciones de otros módulos (desde contexto).
		if ( ! empty( $context['sqli'] ) ) {
			$score += self::$scores['sqli_pattern'];
			$factors[] = 'sqli_pattern';
		}
		if ( ! empty( $context['xss'] ) ) {
			$score += self::$scores['xss_pattern'];
			$factors[] = 'xss_pattern';
		}
		if ( ! empty( $context['traversal'] ) ) {
			$score += self::$scores['traversal_pattern'];
			$factors[] = 'traversal_pattern';
		}

		// 6. Fallos de login acumulados.
		if ( ! empty( $context['login_fails'] ) ) {
			$fails = (int) $context['login_fails'];
			$score += $fails * self::$scores['login_fail'];
			$factors[] = 'login_fail:' . $fails;
		}

		// 7. Errores 404 acumulados.
		if ( ! empty( $context['count_404'] ) ) {
			$count_404 = (int) $context['count_404'];
			$score += $count_404 * self::$scores['multiple_404'];
			$factors[] = '404:' . $count_404;
		}

		// 8. País de alto riesgo.
		if ( ! empty( $context['country_code'] ) ) {
			$risky = $this->loader->get_setting( 'risky_countries', '' );
			if ( $risky ) {
				$risky_list = array_map( 'trim', explode( ',', $risky ) );
				if ( in_array( strtoupper( $context['country_code'] ), $risky_list, true ) ) {
					$score += self::$scores['risky_country'];
					$factors[] = 'risky_country:' . $context['country_code'];
				}
			}
		}

		// 9. Tasa de peticiones elevada.
		$rate_limiter = WPS_Rate_Limiter::get_instance( $this->loader );
		$page_count   = $rate_limiter->get_count( $ip, 'pages' );
		$page_limit   = (int) $this->loader->get_setting( 'rate_pages_per_min', 60 );
		if ( $page_limit > 0 && $page_count > ( $page_limit * 0.7 ) ) {
			$score += self::$scores['high_rate'];
			$factors[] = 'high_rate:' . $page_count;
		}

		// 10. Usuario inexistente en intento de login.
		if ( ! empty( $context['nonexistent_user'] ) ) {
			$score += self::$scores['nonexistent_user'];
			$factors[] = 'nonexistent_user';
		}

		return array(
			'score'   => $score,
			'factors' => $factors,
			'action'  => $this->action_for_score( $score ),
		);
	}

	/**
	 * Evaluar y aplicar acción según el score.
	 *
	 * @param WPS_Request $request Petición a evaluar.
	 * @param array       $context Contexto adicional.
	 */
	public function evaluate_and_act( WPS_Request $request, array $context = array() ): void {
		if ( ! $this->is_enabled() ) {
			return;
		}

		$ip         = $request->ip();
		$assessment = $this->assess( $request, $context );
		$score      = $assessment['score'];
		$action     = $assessment['action'];

		if ( 'none' === $action ) {
			return;
		}

		$enforcing = $this->is_enforcing();

		$details = array(
			'score'    => $score,
			'action'   => $action,
			'factors'  => implode( ', ', $assessment['factors'] ),
			'enforced' => $enforcing,
		);

		$event_type = 'log' === $action ? WPS_Event_Types::RISK_LOW
			: ( 'strict_rate' === $action ? WPS_Event_Types::RISK_MEDIUM : WPS_Event_Types::RISK_HIGH );

		$event_data = array(
			'ip_address'  => $ip,
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => $details,
		);

		// En modo sombra se registra qué habría pasado y se corta acá.
		if ( ! $enforcing ) {
			$this->logger->event( $event_type, $event_data );
			return;
		}

		// Las acciones sin bloqueo no necesitan escritura inmediata.
		if ( 'log' === $action || 'strict_rate' === $action ) {
			$this->logger->event( $event_type, $event_data );
			return;
		}

		$this->logger->event_immediate( $event_type, $event_data );

		$minutes = 'hard_block' === $action
			? null
			: (int) $this->loader->get_setting( 'rate_block_minutes', 15 );

		$this->blocker->block_offender(
			$ip,
			'auto_risk',
			sprintf( 'Puntuación de riesgo elevada: %d (%s)', $score, implode( ', ', $assessment['factors'] ) ),
			$minutes
		);

		$this->blocker->send_block_response(
			'hard_block' === $action ? 'Acceso denegado' : 'Acceso denegado temporalmente'
		);
	}

	/**
	 * Obtener los umbrales actuales.
	 *
	 * @return array
	 */
	public function get_thresholds(): array {
		return self::$thresholds;
	}

	/**
	 * Obtener la tabla de puntuaciones.
	 *
	 * @return array
	 */
	public function get_score_table(): array {
		return self::$scores;
	}
}
