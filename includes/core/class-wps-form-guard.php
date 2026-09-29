<?php
defined( 'ABSPATH' ) || exit;

/**
 * Campo trampa y tiempo mínimo en los formularios de login y comentarios.
 *
 * Frena bots sin captcha ni servicios externos:
 * - Un campo oculto que un humano no ve ni completa; los bots completan todo.
 * - La hora de carga del formulario, firmada: enviar antes de un mínimo de
 *   segundos delata un envío automático.
 *
 * Un envío sin los campos del plugin (un bot que postea directo, o un
 * formulario cacheado desde antes de activar la función) no se rechaza: en
 * comentarios va a la cola de spam, y en el login se deja pasar, porque los
 * formularios de login de temas y plugins no siempre usan los hooks estándar.
 */
class WPS_Form_Guard {

	/** Campo trampa. Nombre sin significado para que el navegador no lo autocomplete. */
	const HONEYPOT_FIELD = 'wps_fg_hp';

	/** Campo con la hora de carga firmada. */
	const TIME_FIELD = 'wps_fg_ts';

	/** Resultados de la evaluación de un envío. */
	const OK        = 'ok';
	const HONEYPOT  = 'honeypot';
	const TOO_FAST  = 'too_fast';
	const MISSING   = 'missing';

	/** @var WPS_Loader */
	private $loader;

	/** @var bool Si el comentario en curso debe ir a spam. */
	private $comment_to_spam = false;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		if ( ! $this->loader->get_setting( 'form_guard_enabled', true ) ) {
			return;
		}

		// Login: wp-login.php y wp_login_form().
		add_action( 'login_form', array( $this, 'print_fields' ) );
		add_filter( 'login_form_middle', array( $this, 'append_fields' ) );
		add_filter( 'authenticate', array( $this, 'check_login' ), 25, 3 );

		// Comentarios.
		add_action( 'comment_form', array( $this, 'print_fields' ) );
		add_filter( 'preprocess_comment', array( $this, 'check_comment' ) );
		add_filter( 'pre_comment_approved', array( $this, 'maybe_mark_spam' ), 99 );
	}

	/*──────────────────────────────────────────────
	 * Campos
	 *──────────────────────────────────────────────*/

	/**
	 * HTML de los campos: la trampa, oculta a la vista y a lectores de
	 * pantalla, y la hora de carga firmada.
	 */
	public static function fields_html( int $now ): string {
		return '<div aria-hidden="true" style="position:absolute!important;left:-9999px!important;top:auto!important;width:1px!important;height:1px!important;overflow:hidden!important;">'
			. '<label for="' . self::HONEYPOT_FIELD . '">No completar</label>'
			. '<input type="text" name="' . self::HONEYPOT_FIELD . '" id="' . self::HONEYPOT_FIELD . '" value="" tabindex="-1" autocomplete="off" />'
			. '</div>'
			. '<input type="hidden" name="' . self::TIME_FIELD . '" value="' . self::create_token( $now ) . '" />';
	}

	public function print_fields(): void {
		echo self::fields_html( time() ); // phpcs:ignore WordPress.Security.EscapeOutput -- HTML propio, sin datos externos.
	}

	/**
	 * @param string $content HTML intermedio de wp_login_form().
	 */
	public function append_fields( $content ): string {
		return (string) $content . self::fields_html( time() );
	}

	/**
	 * Token con la hora de carga: "timestamp.firma".
	 */
	public static function create_token( int $now ): string {
		return $now . '.' . self::sign( (string) $now );
	}

	private static function sign( string $value ): string {
		return substr( hash_hmac( 'sha256', $value, wp_salt( 'nonce' ) ), 0, 20 );
	}

	/*──────────────────────────────────────────────
	 * Evaluación
	 *──────────────────────────────────────────────*/

	/**
	 * Evaluar un envío.
	 *
	 * Un token con firma inválida cuenta como ausente: no prueba que el
	 * formulario se haya cargado.
	 *
	 * @param array $post        Datos enviados.
	 * @param int   $min_seconds Tiempo mínimo entre la carga y el envío (0 = sin mínimo).
	 * @param int   $now         Hora actual.
	 * @return string Uno de OK, HONEYPOT, TOO_FAST o MISSING.
	 */
	public static function assess( array $post, int $min_seconds, int $now ): string {
		if ( isset( $post[ self::HONEYPOT_FIELD ] ) && '' !== trim( (string) $post[ self::HONEYPOT_FIELD ] ) ) {
			return self::HONEYPOT;
		}

		$token = isset( $post[ self::TIME_FIELD ] ) ? (string) $post[ self::TIME_FIELD ] : '';
		if ( ! preg_match( '/^(\d{9,11})\.([a-f0-9]{20})$/', $token, $parts )
			|| ! hash_equals( self::sign( $parts[1] ), $parts[2] ) ) {
			return self::MISSING;
		}

		if ( $min_seconds > 0 && $now - (int) $parts[1] < $min_seconds ) {
			return self::TOO_FAST;
		}

		return self::OK;
	}

	/*──────────────────────────────────────────────
	 * Login
	 *──────────────────────────────────────────────*/

	/**
	 * Rechazar el login si lo envió un bot desde wp-login.php.
	 *
	 * @param WP_User|WP_Error|null $user
	 * @param string                $username
	 * @param string                $password
	 * @return WP_User|WP_Error|null
	 */
	public function check_login( $user, $username = '', $password = '' ) {
		$request = WPS_Request::get_instance();

		if ( 'POST' !== $request->method() || 'login' !== $request->visitor_type() || $this->is_exempt( $request ) ) {
			return $user;
		}

		$result = self::assess(
			$_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			(int) $this->loader->get_setting( 'form_guard_login_min_seconds', 0 ),
			time()
		);

		if ( self::HONEYPOT !== $result && self::TOO_FAST !== $result ) {
			return $user;
		}

		$this->log( $request, 'login', $result );

		return new \WP_Error( 'wps_blocked', WPS_Login_Detector::denied_message() );
	}

	/*──────────────────────────────────────────────
	 * Comentarios
	 *──────────────────────────────────────────────*/

	/**
	 * Rechazar el comentario de un bot, o mandarlo a spam si no trae los
	 * campos del plugin.
	 *
	 * @param array $commentdata Datos del comentario.
	 * @return array
	 */
	public function check_comment( $commentdata ) {
		$request = WPS_Request::get_instance();

		if ( is_user_logged_in() || $this->is_exempt( $request ) ) {
			return $commentdata;
		}

		// Trackbacks y pingbacks no vienen de un formulario.
		if ( ! empty( $commentdata['comment_type'] ) && in_array( $commentdata['comment_type'], array( 'trackback', 'pingback' ), true ) ) {
			return $commentdata;
		}

		$result = self::assess(
			$_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			(int) $this->loader->get_setting( 'form_guard_comment_min_seconds', 3 ),
			time()
		);

		if ( self::OK === $result ) {
			return $commentdata;
		}

		$this->log( $request, 'comment', $result );

		if ( self::MISSING === $result ) {
			$this->comment_to_spam = true;
			return $commentdata;
		}

		wp_die(
			esc_html__( 'No se pudo publicar el comentario. Volvé a la página e intentalo de nuevo.', 'wp-secure' ),
			esc_html__( 'Comentario rechazado', 'wp-secure' ),
			array( 'response' => 403, 'back_link' => true )
		);
	}

	/**
	 * @param int|string|WP_Error $approved Estado de aprobación.
	 * @return int|string|WP_Error
	 */
	public function maybe_mark_spam( $approved ) {
		if ( $this->comment_to_spam && ! is_wp_error( $approved ) ) {
			return 'spam';
		}
		return $approved;
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	/**
	 * Exentos: el propio servidor, la whitelist, y todo mientras el bloqueo
	 * esté suspendido (Modo Inseguro o WPS_DISABLE_BLOCKING).
	 */
	private function is_exempt( WPS_Request $request ): bool {
		$ip = $request->ip();

		return WPS_Blocker::blocking_disabled()
			|| WPS_Ip_Utils::is_server_ip( $ip )
			|| WPS_Whitelist::get_instance()->is_whitelisted( $ip );
	}

	private function log( WPS_Request $request, string $form, string $result ): void {
		WPS_Logger::get_instance()->event( WPS_Event_Types::FORM_BOT_BLOCKED, array(
			'ip_address'  => $request->ip(),
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array(
				'form'   => $form,
				'reason' => $result,
				'action' => self::MISSING === $result ? 'spam' : 'rejected',
			),
		) );
	}
}
