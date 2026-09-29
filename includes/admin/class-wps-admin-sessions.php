<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página de sesiones activas: listar y cerrar sesiones de cualquier usuario.
 */
class WPS_Admin_Sessions {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		$message  = $this->handle_actions();
		$sessions = WPS_Session_Manager::all();
		$current  = WPS_Session_Manager::current_verifier();
		$base_url = admin_url( 'admin.php?page=wp-secure-sessions' );
		$max      = (int) $this->loader->get_setting( 'admin_max_sessions', 0 );
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Sesiones activas', 'wp-secure' ); ?></h1>

			<?php if ( $message ) : ?>
				<div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible">
					<p><?php echo esc_html( $message['text'] ); ?></p>
				</div>
			<?php endif; ?>

			<p class="description">
				<?php esc_html_e( 'Sesiones iniciadas y todavía vigentes. Cerrar una sesión desconecta a esa persona en ese dispositivo; si alguien entró con una contraseña robada, cerrá sus sesiones y cambiá la contraseña.', 'wp-secure' ); ?>
				<?php if ( $max > 0 ) : ?>
					<?php
					printf(
						/* translators: %d: max sessions */
						esc_html__( 'Los administradores pueden tener hasta %d sesiones simultáneas.', 'wp-secure' ),
						(int) $max
					);
					?>
				<?php endif; ?>
			</p>

			<table class="widefat striped wps-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Usuario', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'IP', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Navegador', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Inicio', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Vence', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( ! $sessions ) : ?>
					<tr><td colspan="6"><?php esc_html_e( 'No hay sesiones activas.', 'wp-secure' ); ?></td></tr>
				<?php endif; ?>
				<?php foreach ( $sessions as $session ) : ?>
					<?php
					$user       = get_userdata( $session['user_id'] );
					$is_current = $current && hash_equals( $current, $session['verifier'] );
					?>
					<tr>
						<td>
							<strong><?php echo esc_html( $user ? $user->user_login : '#' . $session['user_id'] ); ?></strong>
							<?php if ( $user && ! empty( $user->roles ) ) : ?>
								<br><small><?php echo esc_html( implode( ', ', (array) $user->roles ) ); ?></small>
							<?php endif; ?>
						</td>
						<td><code><?php echo esc_html( $session['ip'] ); ?></code></td>
						<td><small><?php echo esc_html( mb_strimwidth( $session['ua'], 0, 70, '…' ) ); ?></small></td>
						<td><?php echo esc_html( wp_date( 'Y-m-d H:i', $session['login'] ) ); ?></td>
						<td><?php echo esc_html( wp_date( 'Y-m-d H:i', $session['expiration'] ) ); ?></td>
						<td>
							<?php if ( $is_current ) : ?>
								<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Esta sesión', 'wp-secure' ); ?></span>
							<?php else : ?>
								<a class="button button-small" data-wps-confirm="<?php esc_attr_e( '¿Cerrar esta sesión?', 'wp-secure' ); ?>"
								   href="<?php echo esc_url( wp_nonce_url( add_query_arg( array( 'wps_action' => 'destroy', 'user_id' => $session['user_id'], 'session' => $session['verifier'] ), $base_url ), 'wps_destroy_session_' . $session['verifier'] ) ); ?>">
									<?php esc_html_e( 'Cerrar', 'wp-secure' ); ?>
								</a>
							<?php endif; ?>
							<a class="button button-small" data-wps-confirm="<?php esc_attr_e( '¿Cerrar todas las sesiones de este usuario?', 'wp-secure' ); ?>"
							   href="<?php echo esc_url( wp_nonce_url( add_query_arg( array( 'wps_action' => 'destroy_all', 'user_id' => $session['user_id'] ), $base_url ), 'wps_destroy_all_sessions_' . $session['user_id'] ) ); ?>">
								<?php esc_html_e( 'Cerrar todas del usuario', 'wp-secure' ); ?>
							</a>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * Procesar cierre de sesiones.
	 */
	private function handle_actions(): ?array {
		$action  = isset( $_GET['wps_action'] ) ? sanitize_key( wp_unslash( $_GET['wps_action'] ) ) : '';
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;

		if ( ! $user_id || ! current_user_can( 'manage_options' ) ) {
			return null;
		}

		$nonce = sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) );

		if ( 'destroy' === $action ) {
			$verifier = preg_replace( '/[^a-f0-9]/', '', (string) wp_unslash( $_GET['session'] ?? '' ) );
			if ( ! wp_verify_nonce( $nonce, 'wps_destroy_session_' . $verifier ) ) {
				return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
			}

			$current = WPS_Session_Manager::current_verifier();
			if ( $current && hash_equals( $current, $verifier ) ) {
				return array( 'type' => 'error', 'text' => __( 'No se puede cerrar la sesión actual desde acá.', 'wp-secure' ) );
			}

			if ( WPS_Session_Manager::destroy( $user_id, $verifier ) ) {
				$this->log( $user_id, 'session_destroyed' );
				return array( 'type' => 'success', 'text' => __( 'Sesión cerrada.', 'wp-secure' ) );
			}
			return array( 'type' => 'error', 'text' => __( 'La sesión ya no existe.', 'wp-secure' ) );
		}

		if ( 'destroy_all' === $action ) {
			if ( ! wp_verify_nonce( $nonce, 'wps_destroy_all_sessions_' . $user_id ) ) {
				return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
			}

			WPS_Session_Manager::destroy_all( $user_id );
			$this->log( $user_id, 'all_sessions_destroyed' );

			if ( get_current_user_id() === $user_id ) {
				// Incluye la sesión actual: la página ya se está mostrando,
				// pero el próximo clic pide iniciar sesión de nuevo.
				return array( 'type' => 'warning', 'text' => __( 'Se cerraron todas tus sesiones, incluida esta. Vas a tener que iniciar sesión de nuevo.', 'wp-secure' ) );
			}

			return array( 'type' => 'success', 'text' => __( 'Se cerraron todas las sesiones del usuario.', 'wp-secure' ) );
		}

		return null;
	}

	private function log( int $user_id, string $action ): void {
		$user = get_userdata( $user_id );

		WPS_Logger::get_instance()->event( WPS_Event_Types::SETTINGS_CHANGED, array(
			'ip_address' => WPS_Request::get_instance()->ip(),
			'wp_user_id' => get_current_user_id(),
			'details'    => array(
				'action' => $action,
				'user'   => $user ? $user->user_login : (string) $user_id,
			),
		), WPS_Event_Types::SEVERITY_INFO );
	}
}
