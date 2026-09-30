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

	/** @var WPS_Uploads_Guard */
	private $uploads;

	public function __construct( WPS_Loader $loader ) {
		$this->loader    = $loader;
		$this->integrity = new WPS_File_Integrity( $loader );
		$this->uploads   = new WPS_Uploads_Guard( $loader );
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

			<?php $this->render_uploads(); ?>
		</div>
		<?php
	}

	/**
	 * Sección de archivos PHP en la carpeta de subidas.
	 */
	private function render_uploads(): void {
		$state    = $this->uploads->state();
		$pending  = $this->uploads->pending();
		$enabled  = (bool) $this->loader->get_setting( 'uploads_block_php', false );
		$settings = admin_url( 'admin.php?page=wp-secure-settings' );
		$labels   = array(
			'php'    => __( 'Ejecutable PHP', 'wp-secure' ),
			'config' => __( 'Configuración que habilita PHP', 'wp-secure' ),
		);
		?>
		<h2 id="wps-uploads" style="margin-top:32px;"><?php esc_html_e( 'PHP en la carpeta de subidas', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'La carpeta de subidas sólo debería tener medios. Se buscan archivos que el servidor podría ejecutar (también con doble extensión, como foto.php.jpg) y .htaccess o .user.ini que habiliten PHP. A diferencia del monitor de integridad, lo que ya estaba también se informa.', 'wp-secure' ); ?>
		</p>

		<table class="widefat" style="max-width:640px;margin:16px 0;">
			<tbody>
				<tr><th><?php esc_html_e( 'Bloqueo de ejecución', 'wp-secure' ); ?></th><td>
					<?php if ( ! $enabled ) : ?>
						<?php esc_html_e( 'Desactivado.', 'wp-secure' ); ?>
						<a href="<?php echo esc_url( $settings ); ?>"><?php esc_html_e( 'Activarlo en Configuración → Firewall Avanzado', 'wp-secure' ); ?></a>
					<?php elseif ( ! WPS_Uploads_Guard::has_rules() ) : ?>
						<strong><?php esc_html_e( 'Activado, pero no se pudo escribir uploads/.htaccess (revisá los permisos).', 'wp-secure' ); ?></strong>
					<?php else : ?>
						<?php esc_html_e( 'Activo (reglas en uploads/.htaccess).', 'wp-secure' ); ?>
					<?php endif; ?>
					<?php if ( $enabled && ! WPS_Uploads_Guard::server_reads_htaccess() ) : ?>
						<br><em><?php esc_html_e( 'El servidor no parece ser Apache ni LiteSpeed, así que .htaccess no tiene efecto: el bloqueo depende de la Capa 0 o de una regla de nginx (ver la documentación).', 'wp-secure' ); ?></em>
					<?php endif; ?>
				</td></tr>
				<tr><th><?php esc_html_e( 'Archivos sin revisar', 'wp-secure' ); ?></th><td><strong><?php echo esc_html( number_format_i18n( count( $pending ) ) ); ?></strong></td></tr>
				<tr><th><?php esc_html_e( 'Última búsqueda', 'wp-secure' ); ?></th><td>
					<?php echo $state['scanned_at'] ? esc_html( wp_date( 'Y-m-d H:i', $state['scanned_at'] ) ) : esc_html__( 'Nunca', 'wp-secure' ); ?>
					<?php if ( $state['truncated'] ) : ?>
						— <em><?php echo esc_html( sprintf( /* translators: %d: max files */ __( 'se listan los primeros %d', 'wp-secure' ), WPS_Uploads_Guard::MAX_FILES ) ); ?></em>
					<?php endif; ?>
				</td></tr>
			</tbody>
		</table>

		<form method="post" style="display:inline-block;margin-right:8px;">
			<?php wp_nonce_field( 'wps_integrity', 'wps_integrity_nonce' ); ?>
			<input type="hidden" name="wps_action" value="uploads_scan" />
			<?php submit_button( __( 'Buscar ahora', 'wp-secure' ), 'secondary', 'submit', false ); ?>
		</form>

		<?php if ( $pending ) : ?>
			<form method="post" style="display:inline-block;">
				<?php wp_nonce_field( 'wps_integrity', 'wps_integrity_nonce' ); ?>
				<input type="hidden" name="wps_action" value="uploads_review" />
				<?php submit_button( __( 'Marcar como revisados', 'wp-secure' ), 'secondary', 'submit', false, array( 'data-wps-confirm' => __( '¿Marcar estos archivos como revisados? Si cambian, se vuelven a avisar. Hacelo sólo si sabés qué son.', 'wp-secure' ) ) ); ?>
			</form>

			<table class="widefat striped wps-table" style="margin-top:16px;">
				<thead><tr>
					<th><?php esc_html_e( 'Archivo', 'wp-secure' ); ?></th>
					<th style="width:240px;"><?php esc_html_e( 'Motivo', 'wp-secure' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $pending as $path => $file ) : ?>
					<tr>
						<td><code><?php echo esc_html( $path ); ?></code></td>
						<td><span class="wps-badge wps-badge-danger"><?php echo esc_html( $labels[ $file['reason'] ] ?? $file['reason'] ); ?></span></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php else : ?>
			<p><?php esc_html_e( 'No hay archivos ejecutables sin revisar.', 'wp-secure' ); ?></p>
		<?php endif; ?>
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

		if ( 'uploads_scan' === $action ) {
			$this->uploads->scan();
			$pending = count( $this->uploads->pending() );

			return array(
				'type' => $pending ? 'warning' : 'success',
				'text' => $pending
					/* translators: %d: number of files */
					? sprintf( __( 'Hay %d archivos ejecutables sin revisar en la carpeta de subidas.', 'wp-secure' ), $pending )
					: __( 'No hay archivos ejecutables sin revisar en la carpeta de subidas.', 'wp-secure' ),
			);
		}

		if ( 'uploads_review' === $action ) {
			$reviewed = $this->uploads->review();

			WPS_Logger::get_instance()->event( WPS_Event_Types::SETTINGS_CHANGED, array(
				'wp_user_id' => get_current_user_id(),
				'details'    => array( 'action' => 'uploads_php_reviewed', 'files' => $reviewed ),
			), WPS_Event_Types::SEVERITY_INFO );

			/* translators: %d: number of files */
			return array( 'type' => 'success', 'text' => sprintf( __( 'Se marcaron %d archivos como revisados.', 'wp-secure' ), $reviewed ) );
		}

		return null;
	}
}
