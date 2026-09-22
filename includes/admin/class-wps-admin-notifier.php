<?php
defined( 'ABSPATH' ) || exit;

/**
 * Notificaciones por email.
 *
 * Envía notificaciones al administrador según la configuración:
 * - Bloqueos automáticos
 * - Login desde IP nueva
 * - Cambios de configuración
 * - Resumen diario de seguridad
 */
class WPS_Admin_Notifier {

	/** @var WPS_Admin_Notifier|null */
	private static $instance = null;

	/** @var WPS_Loader */
	private $loader;

	/** User meta con las redes desde las que el usuario ya inició sesión. */
	const KNOWN_LOGIN_META = 'wps_known_login_keys';

	/** Cantidad de redes recordadas por usuario (se descartan las más viejas). */
	const KNOWN_LOGIN_MAX = 20;

	private function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	public static function get_instance( WPS_Loader $loader = null ): self {
		if ( null === self::$instance ) {
			self::$instance = new self( $loader );
		}
		return self::$instance;
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		add_action( 'wps_daily_maintenance', array( $this, 'send_daily_summary' ) );
	}

	/**
	 * Notificar un bloqueo automático.
	 */
	public function notify_auto_block( string $ip, string $block_type, string $reason ): void {
		if ( ! $this->loader->get_setting( 'notify_auto_blocks', false ) ) {
			return;
		}

		$subject = sprintf(
			/* translators: %s: IP address */
			__( '[WP Seguro] IP bloqueada: %s', 'wp-secure' ),
			$ip
		);

		$body = sprintf(
			/* translators: 1: IP, 2: block type, 3: reason, 4: site name */
			__( "Se ha bloqueado automáticamente una IP en %4\$s.\n\nIP: %1\$s\nTipo: %2\$s\nRazón: %3\$s\nFecha: %5\$s", 'wp-secure' ),
			$ip,
			$block_type,
			$reason,
			get_bloginfo( 'name' ),
			wp_date( 'Y-m-d H:i:s' )
		);

		$this->send( $subject, $body );
	}

	/**
	 * Registrar un login exitoso y avisar si viene de una red desconocida.
	 *
	 * Sólo aplica a administradores (`manage_options`): en un sitio con miles
	 * de clientes o alumnos, avisar por cada uno inundaría el correo.
	 *
	 * La red se identifica con la clave de cliente (en IPv6, el prefijo
	 * configurado), para no avisar en cada rotación de dirección. Las redes
	 * conocidas se guardan en user meta y no en la tabla de intentos, que se
	 * purga a los pocos días. Se registran aunque el aviso esté desactivado,
	 * para que activarlo más tarde no dispare un mail por cada red ya usada.
	 *
	 * El primer login de un usuario sin historial no avisa: al instalar el
	 * plugin, o para una cuenta nueva, toda red sería «nueva».
	 *
	 * @param WP_User $user Usuario que inició sesión.
	 * @param string  $ip   IP del visitante.
	 * @return bool Si se envió el aviso.
	 */
	public function track_login( $user, string $ip ): bool {
		if ( empty( $user->ID ) || ! WPS_Ip_Utils::is_valid_ip( $ip ) || ! user_can( $user, 'manage_options' ) ) {
			return false;
		}

		$key   = WPS_Blocker::get_instance()->client_key( $ip );
		$known = get_user_meta( $user->ID, self::KNOWN_LOGIN_META, true );
		$known = is_array( $known ) ? $known : array();

		$is_new      = ! isset( $known[ $key ] );
		$had_history = ! empty( $known );

		$known[ $key ] = time();
		arsort( $known );
		update_user_meta( $user->ID, self::KNOWN_LOGIN_META, array_slice( $known, 0, self::KNOWN_LOGIN_MAX, true ) );

		if ( ! $is_new || ! $had_history ) {
			return false;
		}

		return $this->notify_new_login_ip( $user->user_login, $ip );
	}

	/**
	 * Notificar login desde IP nueva.
	 *
	 * @return bool Si se envió el aviso.
	 */
	public function notify_new_login_ip( string $username, string $ip ): bool {
		if ( ! $this->loader->get_setting( 'notify_new_login_ip', true ) ) {
			return false;
		}

		$subject = sprintf(
			/* translators: %s: username */
			__( '[WP Seguro] Login desde IP nueva: %s', 'wp-secure' ),
			$username
		);

		$geo_info = '';
		if ( ! WPS_Ip_Utils::is_private_ip( $ip ) && class_exists( 'WPS_Geo' ) ) {
			$geo  = WPS_Geo::get_instance();
			$data = $geo->lookup( $ip );
			if ( ! empty( $data['country'] ) ) {
				$geo_info = sprintf( "\n%s: %s (%s)", __( 'País', 'wp-secure' ), WPS_Geo::country_name( $data['country'] ), $data['country'] );
			}
			if ( ! empty( $data['asn'] ) ) {
				$geo_info .= sprintf( "\n%s: AS%s %s", __( 'ASN', 'wp-secure' ), $data['asn'], $data['asn_name'] ?? '' );
			}
		}

		$body = sprintf(
			/* translators: 1: username, 2: IP, 3: site name, 4: date, 5: geo info */
			__( "Se detectó un login desde una IP no registrada anteriormente en %3\$s.\n\nUsuario: %1\$s\nIP: %2\$s%5\$s\nFecha: %4\$s\n\nSi no reconoces esta actividad, revisa la seguridad de tu sitio.", 'wp-secure' ),
			$username,
			$ip,
			get_bloginfo( 'name' ),
			wp_date( 'Y-m-d H:i:s' ),
			$geo_info
		);

		return $this->send( $subject, $body );
	}

	/**
	 * Notificar cambios de configuración.
	 */
	public function notify_settings_change( int $user_id ): void {
		if ( ! $this->loader->get_setting( 'notify_settings_change', true ) ) {
			return;
		}

		$user = get_userdata( $user_id );
		$name = $user ? $user->display_name : __( 'Desconocido', 'wp-secure' );

		$subject = __( '[WP Seguro] Configuración modificada', 'wp-secure' );

		$body = sprintf(
			/* translators: 1: user name, 2: site name, 3: date */
			__( "La configuración de WP Seguro ha sido modificada en %2\$s.\n\nUsuario: %1\$s\nFecha: %3\$s", 'wp-secure' ),
			$name,
			get_bloginfo( 'name' ),
			wp_date( 'Y-m-d H:i:s' )
		);

		$this->send( $subject, $body );
	}

	/**
	 * Enviar resumen diario de seguridad.
	 */
	public function send_daily_summary(): void {
		if ( ! $this->loader->get_setting( 'notify_daily_summary', true ) ) {
			error_log( '[WP Seguro] Resumen diario desactivado en configuración.' );
			return;
		}

		error_log( '[WP Seguro] Generando resumen diario de seguridad...' );

		$db            = WPS_Db::get_instance();
		$traffic_table = WPS_Db_Schema::table( 'traffic_log' );
		$events_table  = WPS_Db_Schema::table( 'security_events' );
		$blocked_table = WPS_Db_Schema::table( 'blocked_ips' );

		$total_requests = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$traffic_table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)"
		);
		$unique_ips = (int) $db->get_var(
			"SELECT COUNT(DISTINCT ip_address) FROM {$traffic_table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)"
		);
		$blocked_events = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$events_table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR) AND severity IN ('warning','critical')"
		);
		$critical_events = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$events_table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR) AND severity = 'critical'"
		);
		$active_blocks = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$blocked_table} WHERE is_active = 1"
		);
		$new_blocks = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$blocked_table} WHERE is_active = 1 AND blocked_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)"
		);

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[WP Seguro] Resumen diario — %s', 'wp-secure' ),
			get_bloginfo( 'name' )
		);

		$body  = sprintf( __( "Resumen de seguridad de las últimas 24 horas para %s\n", 'wp-secure' ), get_bloginfo( 'name' ) );
		$body .= str_repeat( '─', 40 ) . "\n\n";
		$body .= sprintf( __( "Peticiones totales: %s\n", 'wp-secure' ), number_format_i18n( $total_requests ) );
		$body .= sprintf( __( "IPs únicas: %s\n", 'wp-secure' ), number_format_i18n( $unique_ips ) );
		$body .= sprintf( __( "Eventos de bloqueo: %s\n", 'wp-secure' ), number_format_i18n( $blocked_events ) );
		$body .= sprintf( __( "Eventos críticos: %s\n", 'wp-secure' ), number_format_i18n( $critical_events ) );
		$body .= sprintf( __( "Bloqueos activos: %s\n", 'wp-secure' ), number_format_i18n( $active_blocks ) );
		$body .= sprintf( __( "Nuevos bloqueos (24h): %s\n", 'wp-secure' ), number_format_i18n( $new_blocks ) );
		$body .= "\n" . str_repeat( '─', 40 ) . "\n";
		$body .= sprintf( __( "Fecha: %s\n", 'wp-secure' ), wp_date( 'Y-m-d H:i:s' ) );
		$body .= sprintf( __( "Panel: %s\n", 'wp-secure' ), admin_url( 'admin.php?page=wp-secure' ) );

		$this->send( $subject, $body );
	}

	/**
	 * Enviar email.
	 */
	private function send( string $subject, string $body ): bool {
		$to = $this->loader->get_setting( 'notify_email', '' );
		if ( empty( $to ) ) {
			$to = get_option( 'admin_email' );
		}

		if ( empty( $to ) ) {
			error_log( '[WP Seguro] Notificación no enviada: no hay email de destino configurado.' );
			return false;
		}

		$headers = array( 'Content-Type: text/plain; charset=UTF-8' );

		$result = wp_mail( $to, $subject, $body, $headers );

		if ( $result ) {
			error_log( sprintf( '[WP Seguro] Email enviado a %s: %s', $to, $subject ) );
		} else {
			error_log( sprintf( '[WP Seguro] Error al enviar email a %s: %s', $to, $subject ) );
		}

		return $result;
	}
}
