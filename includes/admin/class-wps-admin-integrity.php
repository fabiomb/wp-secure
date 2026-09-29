<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página del monitor de integridad: cambios detectados y aceptación.
 */
class WPS_Admin_Integrity {

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_File_Integrity */
	private $integrity;

	public function __construct( WPS_Loader $loader ) {
		$this->loader    = $loader;
		$this->integrity = new WPS_File_Integrity( $loader );
	}

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		$message = $this->handle_actions();
		$summary = $this->integrity->summary();
		$changes = $this->integrity->changes();
		$labels  = array(
			'modified' => __( 'Modificado', 'wp-secure' ),
			'added'    => __( 'Nuevo', 'wp-secure' ),
			'deleted'  => __( 'Eliminado', 'wp-secure' ),
		);
		$areas = array_unique( array_column( $changes, 'area' ) );
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Integridad de archivos', 'wp-secure' ); ?></h1>

			<?php if ( $message ) : ?>
				<div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible">
					<p><?php echo esc_html( $message['text'] ); ?></p>
				</div>
			<?php endif; ?>

			<?php if ( ! $this->loader->get_setting( 'integrity_enabled', true ) ) : ?>
				<div class="notice notice-warning"><p><?php esc_html_e( 'El monitor de integridad está desactivado en Configuración → Firewall Avanzado.', 'wp-secure' ); ?></p></div>
			<?php endif; ?>

			<p class="description">
				<?php esc_html_e( 'Se comparan los archivos de código del núcleo, los plugins, los temas y wp-content contra una referencia tomada en el primer escaneo. Las actualizaciones toman una referencia nueva automáticamente, así que un cambio que aparece acá no vino de una actualización.', 'wp-secure' ); ?>
			</p>

			<table class="widefat" style="max-width:640px;margin:16px 0;">
				<tbody>
					<tr><th><?php esc_html_e( 'Archivos vigilados', 'wp-secure' ); ?></th><td><?php echo esc_html( number_format_i18n( $summary['files'] ) ); ?></td></tr>
					<tr><th><?php esc_html_e( 'Cambios sin revisar', 'wp-secure' ); ?></th><td><strong><?php echo esc_html( number_format_i18n( $summary['changes'] ) ); ?></strong></td></tr>
					<tr><th><?php esc_html_e( 'Último escaneo completo', 'wp-secure' ); ?></th><td>
						<?php echo $summary['last_scan'] ? esc_html( wp_date( 'Y-m-d H:i', $summary['last_scan'] ) ) : esc_html__( 'Nunca', 'wp-secure' ); ?>
						<?php if ( $summary['in_progress'] ) : ?>
							— <em><?php esc_html_e( 'escaneo en curso', 'wp-secure' ); ?></em>
						<?php endif; ?>
					</td></tr>
				</tbody>
			</table>

			<form method="post" style="display:inline-block;margin-right:8px;">
				<?php wp_nonce_field( 'wps_integrity', 'wps_integrity_nonce' ); ?>
				<input type="hidden" name="wps_action" value="scan" />
				<?php submit_button( $summary['in_progress'] ? __( 'Continuar escaneo', 'wp-secure' ) : __( 'Escanear ahora', 'wp-secure' ), 'secondary', 'submit', false ); ?>
			</form>

			<?php if ( $changes ) : ?>
				<form method="post" style="display:inline-block;">
					<?php wp_nonce_field( 'wps_integrity', 'wps_integrity_nonce' ); ?>
					<input type="hidden" name="wps_action" value="accept" />
					<input type="hidden" name="wps_area" value="" />
					<?php submit_button( __( 'Aceptar todos los cambios', 'wp-secure' ), 'secondary', 'submit', false, array( 'data-wps-confirm' => __( '¿Aceptar todos los cambios como la nueva referencia? Hacelo sólo si los revisaste.', 'wp-secure' ) ) ); ?>
				</form>

				<?php foreach ( $areas as $area ) : ?>
					<h2 style="margin-top:24px;">
						<?php echo esc_html( $area ); ?>
						<form method="post" style="display:inline-block;margin-left:8px;">
							<?php wp_nonce_field( 'wps_integrity', 'wps_integrity_nonce' ); ?>
							<input type="hidden" name="wps_action" value="accept" />
							<input type="hidden" name="wps_area" value="<?php echo esc_attr( $area ); ?>" />
							<?php submit_button( __( 'Aceptar los de esta área', 'wp-secure' ), 'small', 'submit', false ); ?>
						</form>
					</h2>
					<table class="widefat striped wps-table">
						<thead><tr>
							<th><?php esc_html_e( 'Archivo', 'wp-secure' ); ?></th>
							<th style="width:120px;"><?php esc_html_e( 'Estado', 'wp-secure' ); ?></th>
							<th style="width:160px;"><?php esc_html_e( 'Detectado', 'wp-secure' ); ?></th>
						</tr></thead>
						<tbody>
						<?php foreach ( $changes as $change ) : ?>
							<?php if ( $change['area'] !== $area ) { continue; } ?>
							<tr>
								<td><code><?php echo esc_html( $change['path'] ); ?></code></td>
								<td><span class="wps-badge <?php echo 'deleted' === $change['status'] ? 'wps-badge-info' : 'wps-badge-danger'; ?>"><?php echo esc_html( $labels[ $change['status'] ] ?? $change['status'] ); ?></span></td>
								<td><?php echo $change['detected_at'] ? esc_html( wp_date( 'Y-m-d H:i', strtotime( $change['detected_at'] . ' UTC' ) ) ) : '—'; ?></td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endforeach; ?>
			<?php else : ?>
				<p><?php esc_html_e( 'No hay cambios sin revisar.', 'wp-secure' ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Procesar escaneo y aceptación de cambios.
	 */
	private function handle_actions(): ?array {
		if ( ! isset( $_POST['wps_action'] ) || ! current_user_can( 'manage_options' ) ) {
			return null;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_integrity_nonce'] ?? '' ) ), 'wps_integrity' ) ) {
			return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
		}

		$action = sanitize_key( wp_unslash( $_POST['wps_action'] ) );

		if ( 'scan' === $action ) {
			$result = $this->integrity->run();
			if ( ! $result['done'] ) {
				return array( 'type' => 'info', 'text' => __( 'El escaneo sigue en segundo plano; volvé a esta página en unos minutos.', 'wp-secure' ) );
			}
			return array(
				'type' => $result['changes'] ? 'warning' : 'success',
				'text' => $result['changes']
					/* translators: %d: number of changes */
					? sprintf( __( 'Escaneo completo: %d cambios nuevos.', 'wp-secure' ), count( $result['changes'] ) )
					: __( 'Escaneo completo: sin cambios nuevos.', 'wp-secure' ),
			);
		}

		if ( 'accept' === $action ) {
			$area     = sanitize_text_field( wp_unslash( $_POST['wps_area'] ?? '' ) );
			$accepted = $this->integrity->accept( '' === $area ? null : $area );

			WPS_Logger::get_instance()->event( WPS_Event_Types::SETTINGS_CHANGED, array(
				'wp_user_id' => get_current_user_id(),
				'details'    => array( 'action' => 'integrity_accepted', 'area' => '' === $area ? 'all' : $area, 'files' => $accepted ),
			), WPS_Event_Types::SEVERITY_INFO );

			/* translators: %d: number of files */
			return array( 'type' => 'success', 'text' => sprintf( __( 'Se aceptaron %d cambios como la nueva referencia.', 'wp-secure' ), $accepted ) );
		}

		return null;
	}
}
