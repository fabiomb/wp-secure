<?php
defined( 'ABSPATH' ) || exit;

/**
 * Panel de gestión de la base de datos IP.
 *
 * Muestra el estado de la base de datos MMDB, permite descargar/actualizar
 * y cambiar entre modo API y modo local.
 */
class WPS_Admin_Ipdb {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		$manager = WPS_Ipdb_Manager::get_instance();
		$updater = WPS_Ipdb_Updater::get_instance();
		$message = $this->handle_actions();

		$mode          = $this->loader->get_setting( 'ipinfo_mode', 'api' );
		$api_key       = $this->loader->get_setting( 'ipinfo_api_key', '' );
		$has_api_key   = ! empty( $api_key );
		$is_local      = $manager->is_local_available();
		$db_info       = $manager->get_database_info();
		$last_update   = $updater->get_last_update();
		$needs_update  = $updater->needs_update();
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Base de Datos IP', 'wp-secure' ); ?></h1>

			<?php if ( $message ) : ?>
				<div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible">
					<p><?php echo esc_html( $message['text'] ); ?></p>
				</div>
			<?php endif; ?>

			<!-- Estado General -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Estado', 'wp-secure' ); ?></h2>
				<div class="wps-cards-row">
					<div class="wps-card wps-card-status <?php echo $has_api_key ? 'wps-card-ok' : 'wps-card-error'; ?>">
						<h3><?php esc_html_e( 'API Key', 'wp-secure' ); ?></h3>
						<p>
							<?php if ( $has_api_key ) : ?>
								<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Configurada', 'wp-secure' ); ?></span>
							<?php else : ?>
								<span class="wps-badge wps-badge-error"><?php esc_html_e( 'No configurada', 'wp-secure' ); ?></span>
								<br><small>
									<?php
									printf(
										/* translators: %s: settings URL */
										esc_html__( 'Configúrala en %s', 'wp-secure' ),
										'<a href="' . esc_url( admin_url( 'admin.php?page=wp-secure-settings#wps-section-api' ) ) . '">' .
										esc_html__( 'Configuración', 'wp-secure' ) . '</a>'
									);
									?>
								</small>
							<?php endif; ?>
						</p>
					</div>

					<div class="wps-card wps-card-status">
						<h3><?php esc_html_e( 'Modo Activo', 'wp-secure' ); ?></h3>
						<p>
							<span class="wps-badge wps-badge-info">
								<?php echo 'local' === $mode ? esc_html__( 'Base de datos local (MMDB)', 'wp-secure' ) : esc_html__( 'API en línea', 'wp-secure' ); ?>
							</span>
						</p>
					</div>

					<div class="wps-card wps-card-status <?php echo $is_local ? 'wps-card-ok' : 'wps-card-pending'; ?>">
						<h3><?php esc_html_e( 'Base de Datos Local', 'wp-secure' ); ?></h3>
						<p>
							<?php if ( $is_local ) : ?>
								<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Disponible', 'wp-secure' ); ?></span>
							<?php else : ?>
								<span class="wps-badge wps-badge-pending"><?php esc_html_e( 'No descargada', 'wp-secure' ); ?></span>
							<?php endif; ?>
						</p>
					</div>
				</div>
			</div>

			<!-- Información de la Base de Datos -->
			<?php if ( $db_info ) : ?>
			<div class="wps-section">
				<h2><?php esc_html_e( 'Información de la Base de Datos', 'wp-secure' ); ?></h2>
				<table class="wps-table widefat striped">
					<tbody>
						<tr>
							<th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
							<td><?php echo esc_html( $db_info['type'] ); ?></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Versión IP', 'wp-secure' ); ?></th>
							<td><?php echo esc_html( 'IPv' . $db_info['ip_version'] ); ?></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Tamaño', 'wp-secure' ); ?></th>
							<td><?php echo esc_html( size_format( $db_info['file_size'] ) ); ?></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Compilada', 'wp-secure' ); ?></th>
							<td>
								<?php
								if ( $db_info['build_time'] > 0 ) {
									echo esc_html( wp_date( 'j M Y, H:i', $db_info['build_time'] ) );
								} else {
									esc_html_e( 'Desconocido', 'wp-secure' );
								}
								?>
							</td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Nodos', 'wp-secure' ); ?></th>
							<td><?php echo esc_html( number_format_i18n( $db_info['node_count'] ) ); ?></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Última descarga', 'wp-secure' ); ?></th>
							<td>
								<?php
								if ( $last_update > 0 ) {
									echo esc_html( wp_date( 'j M Y, H:i', $last_update ) );
									if ( $needs_update ) {
										echo ' <span class="wps-badge wps-badge-warning">' . esc_html__( 'Actualización recomendada', 'wp-secure' ) . '</span>';
									}
								} else {
									esc_html_e( 'Nunca', 'wp-secure' );
								}
								?>
							</td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Ruta', 'wp-secure' ); ?></th>
							<td><code><?php echo esc_html( $db_info['path'] ); ?></code></td>
						</tr>
					</tbody>
				</table>
			</div>
			<?php endif; ?>

			<!-- Acciones -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></h2>

				<?php if ( ! $has_api_key ) : ?>
					<div class="wps-notice wps-notice-warning">
						<p><?php esc_html_e( 'Necesitas configurar una API key de ipinfo.io para descargar la base de datos.', 'wp-secure' ); ?></p>
						<p>
							<a href="https://ipinfo.io/signup" target="_blank" rel="noopener noreferrer" class="button">
								<?php esc_html_e( 'Obtener API key gratuita', 'wp-secure' ); ?>
							</a>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-settings#wps-section-api' ) ); ?>" class="button">
								<?php esc_html_e( 'Configurar API key', 'wp-secure' ); ?>
							</a>
						</p>
					</div>
				<?php else : ?>
					<div class="notice notice-info inline" style="margin:0 0 12px;padding:10px 14px;">
						<p>
							<strong><?php esc_html_e( 'Requisito previo:', 'wp-secure' ); ?></strong>
							<?php esc_html_e( 'La descarga del archivo MMDB requiere activar "Database Downloads" en tu cuenta de ipinfo.io. Sin ese paso el servidor devuelve error 401 aunque la API key sea correcta.', 'wp-secure' ); ?>
						</p>
						<ol style="margin:6px 0 0 18px;">
							<li>
								<?php
								printf(
									/* translators: %s: link to ipinfo.io account */
									esc_html__( 'Inicia sesión en %s y ve a Account → Data Downloads.', 'wp-secure' ),
									'<a href="https://ipinfo.io/account/data-downloads" target="_blank" rel="noopener noreferrer">ipinfo.io</a>'
								);
								?>
							</li>
							<li><?php esc_html_e( 'Activa la descarga de "Country + ASN Database" (country_asn.mmdb) en el panel.', 'wp-secure' ); ?></li>
							<li><?php esc_html_e( 'Usa la misma API key que tienes configurada arriba y pulsa "Descargar".', 'wp-secure' ); ?></li>
						</ol>
					</div>

					<form method="post" style="display:inline-block; margin-right: 10px;">
						<?php wp_nonce_field( 'wps_ipdb_download', 'wps_ipdb_nonce' ); ?>
						<input type="hidden" name="wps_action" value="download_mmdb" />
						<button type="submit" class="button button-primary" id="wps-download-mmdb">
							<span class="dashicons dashicons-download" style="margin-top: 4px;"></span>
							<?php $is_local ? esc_html_e( 'Actualizar Base de Datos', 'wp-secure' ) : esc_html_e( 'Descargar Base de Datos', 'wp-secure' ); ?>
						</button>
					</form>
					<p class="description" style="margin-top: 10px;">
						<?php esc_html_e( 'Se descargará la base de datos Country+ASN de ipinfo.io (~25 MB). El proceso puede tardar unos minutos.', 'wp-secure' ); ?>
					</p>
				<?php endif; ?>
			</div>

			<!-- Test de Lookup -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Probar Lookup', 'wp-secure' ); ?></h2>
				<form method="post">
					<?php wp_nonce_field( 'wps_ipdb_test', 'wps_ipdb_test_nonce' ); ?>
					<input type="hidden" name="wps_action" value="test_lookup" />
					<p>
						<input type="text" name="wps_test_ip" class="regular-text"
							   placeholder="<?php esc_attr_e( 'Ingresa una IP para probar', 'wp-secure' ); ?>"
							   value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_POST['wps_test_ip'] ?? '' ) ) ); ?>" />
						<?php submit_button( __( 'Probar', 'wp-secure' ), 'secondary', 'submit', false ); ?>
					</p>
				</form>

				<?php $this->render_test_result(); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Procesar acciones del formulario.
	 */
	private function handle_actions(): ?array {
		if ( ! isset( $_POST['wps_action'] ) ) {
			return null;
		}

		$action = sanitize_text_field( wp_unslash( $_POST['wps_action'] ) );

		if ( 'download_mmdb' === $action ) {
			if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_ipdb_nonce'] ?? '' ) ), 'wps_ipdb_download' ) ) {
				return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
			}

			$updater = WPS_Ipdb_Updater::get_instance();
			$result  = $updater->download();

			return array(
				'type' => $result['success'] ? 'success' : 'error',
				'text' => $result['message'],
			);
		}

		return null;
	}

	/**
	 * Renderizar resultado de test de lookup.
	 */
	private function render_test_result(): void {
		if ( ! isset( $_POST['wps_action'] ) || 'test_lookup' !== $_POST['wps_action'] ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_ipdb_test_nonce'] ?? '' ) ), 'wps_ipdb_test' ) ) {
			return;
		}

		$ip = sanitize_text_field( wp_unslash( $_POST['wps_test_ip'] ?? '' ) );
		if ( empty( $ip ) || ! WPS_Ip_Utils::is_valid_ip( $ip ) ) {
			echo '<div class="wps-notice wps-notice-warning"><p>' . esc_html__( 'IP no válida.', 'wp-secure' ) . '</p></div>';
			return;
		}

		$geo = WPS_Geo::get_instance();
		$data = $geo->lookup( $ip );

		echo '<div class="wps-test-result">';
		echo '<table class="wps-table widefat" style="max-width: 500px;">';
		echo '<tbody>';
		echo '<tr><th>' . esc_html__( 'IP', 'wp-secure' ) . '</th><td><code>' . esc_html( $ip ) . '</code></td></tr>';
		echo '<tr><th>' . esc_html__( 'País', 'wp-secure' ) . '</th><td>' . esc_html( $data['country'] ? $data['country'] . ' — ' . WPS_Geo::country_name( $data['country'] ) : '—' ) . '</td></tr>';
		echo '<tr><th>' . esc_html__( 'ASN', 'wp-secure' ) . '</th><td>' . esc_html( $data['asn'] ? 'AS' . $data['asn'] : '—' ) . '</td></tr>';
		echo '<tr><th>' . esc_html__( 'Organización', 'wp-secure' ) . '</th><td>' . esc_html( $data['asn_name'] ?? '—' ) . '</td></tr>';
		echo '<tr><th>' . esc_html__( 'Fuente', 'wp-secure' ) . '</th><td>' . esc_html( $data['source'] ?? '—' ) . '</td></tr>';
		echo '</tbody></table>';
		echo '</div>';
	}
}
