<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página de geolocalización.
 *
 * Muestra el proveedor activo (ninguno, ipinfo.io o MaxMind GeoLite2), qué
 * se pierde sin geolocalización, el estado de cada proveedor, la descarga de
 * las bases locales y una prueba de consulta. El proveedor se elige en
 * Configuración → Geolocalización.
 */
class WPS_Admin_Ipdb {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/*──────────────────────────────────────────────
	 * Piezas compartidas con otras páginas
	 *──────────────────────────────────────────────*/

	/**
	 * Estado resumido de la geolocalización, para insignias.
	 *
	 * @return array{badge: string, label: string}
	 */
	public static function status(): array {
		$manager  = WPS_Ipdb_Manager::get_instance();
		$provider = $manager->get_provider();

		if ( WPS_Ipdb_Manager::PROVIDER_NONE === $provider ) {
			return array(
				'badge' => 'info',
				'label' => __( 'Desactivada (opcional)', 'wp-secure' ),
			);
		}

		$name = WPS_Ipdb_Manager::providers()[ $provider ];

		if ( 'local' === $manager->get_mode( $provider ) ) {
			if ( $manager->is_local_complete( $provider ) ) {
				return array( 'badge' => 'ok', 'label' => $name . ' · ' . __( 'base local', 'wp-secure' ) );
			}
			if ( $manager->has_credentials( $provider ) ) {
				return array( 'badge' => 'pending', 'label' => $name . ' · ' . __( 'falta descargar la base', 'wp-secure' ) );
			}
		} elseif ( $manager->has_credentials( $provider ) ) {
			return array( 'badge' => 'ok', 'label' => $name . ' · ' . __( 'API en línea', 'wp-secure' ) );
		}

		if ( $manager->is_configured() ) {
			// Modo elegido sin datos, pero el otro modo del proveedor responde.
			return array( 'badge' => 'pending', 'label' => $name . ' · ' . __( 'configuración parcial', 'wp-secure' ) );
		}

		return array( 'badge' => 'warning', 'label' => $name . ' · ' . __( 'faltan credenciales', 'wp-secure' ) );
	}

	/**
	 * Explicación de que la geolocalización es opcional y qué se pierde sin ella.
	 */
	public static function render_optional_explanation(): void {
		?>
		<div class="wps-notice wps-notice-info" style="margin:12px 0;">
			<p><strong><?php esc_html_e( 'La geolocalización es opcional: WP Seguro funciona completo sin ella.', 'wp-secure' ); ?></strong></p>
			<p><?php esc_html_e( 'Sin un proveedor configurado sólo se pierde lo que depende de saber el país o la red (ASN) de una IP:', 'wp-secure' ); ?></p>
			<ul style="list-style:disc;margin-left:20px;">
				<li><?php esc_html_e( 'Bloqueo por país y por ASN.', 'wp-secure' ); ?></li>
				<li><?php esc_html_e( 'País y ASN en el tráfico en vivo, los eventos y las notificaciones.', 'wp-secure' ); ?></li>
				<li><?php esc_html_e( 'Los "países de alto riesgo" del motor de riesgo y las reglas personalizadas con condición de país.', 'wp-secure' ); ?></li>
				<li><?php esc_html_e( 'La verificación por ASN de crawlers sin DNS inverso confiable (se siguen verificando por rDNS).', 'wp-secure' ); ?></li>
			</ul>
			<p><?php esc_html_e( 'Todo lo demás funciona igual: el firewall (capas 0 y 1), la protección de login y XML-RPC, el rate limiting, los detectores de ataques, las rutas trampa, las reglas por IP y URL, la whitelist y el control de integridad de archivos.', 'wp-secure' ); ?></p>
		</div>
		<?php
	}

	/**
	 * Aviso en las páginas de bloqueo por país/ASN cuando no hay geolocalización.
	 */
	public static function render_geo_required_notice(): void {
		if ( WPS_Ipdb_Manager::get_instance()->is_configured() ) {
			return;
		}
		?>
		<div class="wps-notice wps-notice-info" style="margin-top:15px;">
			<p>
				<?php
				printf(
					/* translators: %s: link to the geolocation page */
					esc_html__( 'Los bloqueos por país y ASN sólo se aplican con la geolocalización activa, que es opcional. Configurala en %s.', 'wp-secure' ),
					'<a href="' . esc_url( admin_url( 'admin.php?page=wp-secure-ipdb' ) ) . '">' . esc_html__( 'Geolocalización', 'wp-secure' ) . '</a>'
				);
				?>
			</p>
		</div>
		<?php
	}

	/**
	 * Avisos al terminar el wizard (parámetros `wizard` y `wps_geo` de la URL).
	 */
	public static function render_wizard_notices(): void {
		if ( 'done' === ( $_GET['wizard'] ?? '' ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Configuración inicial completa. Podés ajustar todo después desde Configuración.', 'wp-secure' ) . '</p></div>';
		}

		$geo = sanitize_key( wp_unslash( $_GET['wps_geo'] ?? '' ) ); // phpcs:ignore WordPress.Security.NonceVerification

		if ( 'incomplete' === $geo ) {
			echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__( 'El proveedor de geolocalización quedó elegido pero faltan sus credenciales, así que todavía no resuelve IPs. Completalas en Configuración → Geolocalización.', 'wp-secure' ) . '</p></div>';
		} elseif ( 'download' === $geo ) {
			echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__( 'Elegiste la base de datos local: descargala ahora con el botón "Descargar Base de Datos". Hasta entonces el plugin funciona igual, sin datos de país ni ASN.', 'wp-secure' ) . '</p></div>';
		}
	}

	/*──────────────────────────────────────────────
	 * Página
	 *──────────────────────────────────────────────*/

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		$manager  = WPS_Ipdb_Manager::get_instance();
		$updater  = WPS_Ipdb_Updater::get_instance();
		$message  = $this->handle_actions();
		$provider = $manager->get_provider();
		$status   = self::status();
		$names    = WPS_Ipdb_Manager::providers();
		$settings = admin_url( 'admin.php?page=wp-secure-settings#wps-section-api' );
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Geolocalización', 'wp-secure' ); ?></h1>

			<?php self::render_wizard_notices(); ?>

			<?php if ( $message ) : ?>
				<div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible">
					<p><?php echo esc_html( $message['text'] ); ?></p>
				</div>
			<?php endif; ?>

			<!-- Estado General -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Estado', 'wp-secure' ); ?></h2>
				<div class="wps-cards-row">
					<div class="wps-card wps-card-status">
						<h3><?php esc_html_e( 'Proveedor activo', 'wp-secure' ); ?></h3>
						<p>
							<span class="wps-badge wps-badge-<?php echo esc_attr( $status['badge'] ); ?>"><?php echo esc_html( $status['label'] ); ?></span>
							<br><small>
								<?php
								printf(
									/* translators: %s: settings URL */
									esc_html__( 'Se elige en %s', 'wp-secure' ),
									'<a href="' . esc_url( $settings ) . '">' . esc_html__( 'Configuración → Geolocalización', 'wp-secure' ) . '</a>'
								);
								?>
							</small>
						</p>
					</div>

					<?php if ( WPS_Ipdb_Manager::PROVIDER_NONE !== $provider ) : ?>
						<div class="wps-card wps-card-status">
							<h3><?php esc_html_e( 'Modo', 'wp-secure' ); ?></h3>
							<p>
								<span class="wps-badge wps-badge-info">
									<?php echo 'local' === $manager->get_mode( $provider ) ? esc_html__( 'Base de datos local (MMDB)', 'wp-secure' ) : esc_html__( 'API en línea', 'wp-secure' ); ?>
								</span>
							</p>
						</div>
					<?php endif; ?>
				</div>

				<?php self::render_optional_explanation(); ?>
			</div>

			<!-- Estado por proveedor -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Proveedores', 'wp-secure' ); ?></h2>
				<table class="wps-table widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Proveedor', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Credenciales', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Base local', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Última descarga', 'wp-secure' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( array( WPS_Ipdb_Manager::PROVIDER_IPINFO, WPS_Ipdb_Manager::PROVIDER_MAXMIND ) as $id ) : ?>
							<?php $last = $updater->get_last_update( $id ); ?>
							<tr>
								<td>
									<?php echo esc_html( $names[ $id ] ); ?>
									<?php if ( $id === $provider ) : ?>
										<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Activo', 'wp-secure' ); ?></span>
									<?php endif; ?>
								</td>
								<td>
									<?php if ( $manager->has_credentials( $id ) ) : ?>
										<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Configuradas', 'wp-secure' ); ?></span>
									<?php else : ?>
										<span class="wps-badge wps-badge-info"><?php esc_html_e( 'Sin configurar', 'wp-secure' ); ?></span>
									<?php endif; ?>
								</td>
								<td>
									<?php if ( $manager->is_local_complete( $id ) ) : ?>
										<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Disponible', 'wp-secure' ); ?></span>
									<?php elseif ( $manager->is_local_available( $id ) ) : ?>
										<span class="wps-badge wps-badge-pending"><?php esc_html_e( 'Incompleta', 'wp-secure' ); ?></span>
									<?php else : ?>
										<span class="wps-badge wps-badge-info"><?php esc_html_e( 'No descargada', 'wp-secure' ); ?></span>
									<?php endif; ?>
								</td>
								<td>
									<?php
									if ( $last > 0 ) {
										echo esc_html( wp_date( 'j M Y, H:i', $last ) );
										if ( $id === $provider && $updater->needs_update( $id ) ) {
											echo ' <span class="wps-badge wps-badge-warning">' . esc_html__( 'Actualización recomendada', 'wp-secure' ) . '</span>';
										}
									} else {
										esc_html_e( 'Nunca', 'wp-secure' );
									}
									?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>

			<?php
			if ( WPS_Ipdb_Manager::PROVIDER_NONE !== $provider ) {
				$this->render_databases_info( $manager->get_databases_info( $provider ) );
				$this->render_download( $provider, $manager, $settings );
			}
			?>

			<!-- Test de Lookup -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Probar Lookup', 'wp-secure' ); ?></h2>
				<?php if ( ! $manager->is_configured() ) : ?>
					<p class="description"><?php esc_html_e( 'Sin un proveedor configurado la consulta devuelve campos vacíos.', 'wp-secure' ); ?></p>
				<?php endif; ?>
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
	 * Información de las bases locales del proveedor activo.
	 *
	 * @param array[] $infos Resultado de WPS_Ipdb_Manager::get_databases_info().
	 */
	private function render_databases_info( array $infos ): void {
		if ( empty( $infos ) ) {
			return;
		}
		?>
		<div class="wps-section">
			<h2><?php esc_html_e( 'Bases de datos locales', 'wp-secure' ); ?></h2>
			<?php foreach ( $infos as $db_info ) : ?>
				<h3><?php echo esc_html( $db_info['label'] ); ?></h3>
				<table class="wps-table widefat striped" style="margin-bottom:12px;">
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
							<th><?php esc_html_e( 'Ruta', 'wp-secure' ); ?></th>
							<td><code><?php echo esc_html( $db_info['path'] ); ?></code></td>
						</tr>
					</tbody>
				</table>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Descarga/actualización de la base local del proveedor activo.
	 */
	private function render_download( string $provider, WPS_Ipdb_Manager $manager, string $settings ): void {
		$is_maxmind = WPS_Ipdb_Manager::PROVIDER_MAXMIND === $provider;
		$is_local   = $manager->is_local_complete( $provider );
		?>
		<div class="wps-section">
			<h2><?php esc_html_e( 'Base de datos local', 'wp-secure' ); ?></h2>

			<?php if ( 'local' !== $manager->get_mode( $provider ) ) : ?>
				<p class="description"><?php esc_html_e( 'El proveedor está en modo API. La base local es opcional: si existe, se usa cuando la API no responde.', 'wp-secure' ); ?></p>
			<?php endif; ?>

			<?php if ( ! $manager->has_credentials( $provider ) ) : ?>
				<div class="wps-notice wps-notice-warning">
					<p>
						<?php
						echo $is_maxmind
							? esc_html__( 'Para descargar las bases de MaxMind necesitás el Account ID y una License Key de una cuenta GeoLite2 (gratuita).', 'wp-secure' )
							: esc_html__( 'Necesitas configurar una API key de ipinfo.io para descargar la base de datos.', 'wp-secure' );
						?>
					</p>
					<p>
						<?php if ( $is_maxmind ) : ?>
							<a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener noreferrer" class="button">
								<?php esc_html_e( 'Crear cuenta GeoLite2', 'wp-secure' ); ?>
							</a>
						<?php else : ?>
							<a href="https://ipinfo.io/signup" target="_blank" rel="noopener noreferrer" class="button">
								<?php esc_html_e( 'Obtener API key gratuita', 'wp-secure' ); ?>
							</a>
						<?php endif; ?>
						<a href="<?php echo esc_url( $settings ); ?>" class="button">
							<?php esc_html_e( 'Configurar credenciales', 'wp-secure' ); ?>
						</a>
					</p>
				</div>
			<?php elseif ( $is_maxmind ) : ?>
				<p class="description" style="margin-bottom:12px;">
					<?php esc_html_e( 'Se descargarán GeoLite2-Country y GeoLite2-ASN de MaxMind (unos 15 MB en total). El mantenimiento diario las actualiza una vez por semana mientras el modo sea local.', 'wp-secure' ); ?>
				</p>
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
						<li><?php esc_html_e( 'Usa la misma API key que tienes configurada y pulsa "Descargar".', 'wp-secure' ); ?></li>
					</ol>
				</div>
			<?php endif; ?>

			<?php if ( $manager->has_credentials( $provider ) ) : ?>
				<form method="post" style="display:inline-block; margin-right: 10px;">
					<?php wp_nonce_field( 'wps_ipdb_download', 'wps_ipdb_nonce' ); ?>
					<input type="hidden" name="wps_action" value="download_mmdb" />
					<button type="submit" class="button button-primary" id="wps-download-mmdb">
						<span class="dashicons dashicons-download" style="margin-top: 4px;"></span>
						<?php $is_local ? esc_html_e( 'Actualizar Base de Datos', 'wp-secure' ) : esc_html_e( 'Descargar Base de Datos', 'wp-secure' ); ?>
					</button>
				</form>
				<?php if ( ! $is_maxmind ) : ?>
					<p class="description" style="margin-top: 10px;">
						<?php esc_html_e( 'Se descargará la base de datos Country+ASN de ipinfo.io (~25 MB). El proceso puede tardar unos minutos.', 'wp-secure' ); ?>
					</p>
				<?php endif; ?>
			<?php endif; ?>
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

			// Siempre sobre el proveedor activo.
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
