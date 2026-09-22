<?php
defined( 'ABSPATH' ) || exit;

/**
 * Dashboard / Resumen general.
 *
 * Incluye tarjetas de estadísticas, gráficas de actividad (Chart.js),
 * top 10 IPs bloqueadas, top 10 países por tráfico, y últimos eventos.
 */
class WPS_Admin_Dashboard {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Renderizar la página del dashboard.
	 */
	public function render(): void {
		$stats  = $this->get_stats();
		$hourly = $this->get_hourly_activity();
		$top_ips      = $this->get_top_blocked_ips();
		$top_countries = $this->get_top_countries();
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Dashboard', 'wp-secure' ); ?></h1>

			<!-- Estado del sistema -->
			<div class="wps-cards-row">
				<?php $this->render_status_card(); ?>
			</div>

			<!-- Estadísticas 24h -->
			<div class="wps-cards-row">
				<?php $this->render_stat_card(
					__( 'Peticiones (24h)', 'wp-secure' ),
					$stats['total_requests'],
					'dashicons-visibility'
				); ?>
				<?php $this->render_stat_card(
					__( 'Bloqueadas (24h)', 'wp-secure' ),
					$stats['blocked_requests'],
					'dashicons-shield',
					'wps-card-danger'
				); ?>
				<?php $this->render_stat_card(
					__( 'IPs Únicas (24h)', 'wp-secure' ),
					$stats['unique_ips'],
					'dashicons-networking'
				); ?>
				<?php $this->render_stat_card(
					__( 'Eventos Críticos (24h)', 'wp-secure' ),
					$stats['critical_events'],
					'dashicons-warning',
					$stats['critical_events'] > 0 ? 'wps-card-danger' : ''
				); ?>
				<?php $this->render_stat_card(
					__( 'Bloqueos Totales', 'wp-secure' ),
					$stats['total_blocks'],
					'dashicons-lock'
				); ?>
			</div>

			<!-- Gráficas -->
			<div class="wps-cards-row">
				<!-- Actividad 24h -->
				<div class="wps-card wps-card-wide" style="display:block;">
					<h3><span class="dashicons dashicons-chart-area"></span> <?php esc_html_e( 'Actividad últimas 24 horas', 'wp-secure' ); ?></h3>
					<div style="position:relative;height:250px;">
						<canvas id="wps-chart-hourly"></canvas>
					</div>
				</div>
			</div>

			<div class="wps-cards-row">
				<!-- Top 10 IPs bloqueadas -->
				<div class="wps-card" style="flex:1 1 48%;display:block;min-width:300px;">
					<h3><span class="dashicons dashicons-shield"></span> <?php esc_html_e( 'Top 10 IPs Bloqueadas', 'wp-secure' ); ?></h3>
					<?php if ( empty( $top_ips ) ) : ?>
						<p class="wps-no-data"><?php esc_html_e( 'Sin bloqueos recientes.', 'wp-secure' ); ?></p>
					<?php else : ?>
						<table class="wps-table widefat striped" style="margin-top:8px;">
							<thead>
								<tr>
									<th><?php esc_html_e( 'IP', 'wp-secure' ); ?></th>
									<th><?php esc_html_e( 'Hits', 'wp-secure' ); ?></th>
									<th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
								</tr>
							</thead>
							<tbody>
							<?php foreach ( $top_ips as $row ) : ?>
								<tr>
									<td>
										<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-traffic&ip=' . urlencode( $row['ip_address'] ) ) ); ?>">
											<code><?php echo esc_html( $row['ip_address'] ); ?></code>
										</a>
									</td>
									<td><?php echo esc_html( number_format_i18n( $row['hit_count'] ) ); ?></td>
									<td><code><?php echo esc_html( $row['block_type'] ); ?></code></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
				</div>

				<!-- Top 10 Países -->
				<div class="wps-card" style="flex:1 1 48%;display:block;min-width:300px;">
					<h3><span class="dashicons dashicons-admin-site-alt3"></span> <?php esc_html_e( 'Top 10 Países por Tráfico', 'wp-secure' ); ?></h3>
					<?php if ( empty( $top_countries ) ) : ?>
						<p class="wps-no-data"><?php esc_html_e( 'Sin datos de geolocalización.', 'wp-secure' ); ?></p>
					<?php else : ?>
						<div style="position:relative;height:220px;">
							<canvas id="wps-chart-countries"></canvas>
						</div>
					<?php endif; ?>
				</div>
			</div>

			<!-- Últimos eventos de seguridad -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Últimos Eventos de Seguridad', 'wp-secure' ); ?></h2>
				<?php $this->render_recent_events(); ?>
			</div>

			<!-- Info del sistema -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Información del Sistema', 'wp-secure' ); ?></h2>
				<?php $this->render_system_info(); ?>
			</div>
		</div>

		<!-- Chart.js data -->
		<script>
		window.wpsChartData = {
			hourly: {
				labels: <?php echo wp_json_encode( array_column( $hourly, 'label' ) ); ?>,
				requests: <?php echo wp_json_encode( array_map( 'intval', array_column( $hourly, 'requests' ) ) ); ?>,
				blocks: <?php echo wp_json_encode( array_map( 'intval', array_column( $hourly, 'blocks' ) ) ); ?>
			},
			countries: {
				labels: <?php echo wp_json_encode( array_column( $top_countries, 'country_name' ) ); ?>,
				values: <?php echo wp_json_encode( array_map( 'intval', array_column( $top_countries, 'count' ) ) ); ?>
			}
		};
		</script>
		<?php
	}

	/**
	 * Renderizar el widget del dashboard de WordPress.
	 */
	public function render_widget(): void {
		$stats  = $this->get_stats();
		$hourly = $this->get_hourly_activity();
		$db     = WPS_Db::get_instance();
		$blocked_table = WPS_Db_Schema::table( 'blocked_ips' );
		$active_blocks = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$blocked_table} WHERE is_active = 1"
		);
		?>
		<div class="wps-widget">
			<div class="wps-widget-stats">
				<div class="wps-widget-stat">
					<span class="wps-widget-stat-number"><?php echo esc_html( number_format_i18n( $stats['total_requests'] ) ); ?></span>
					<span class="wps-widget-stat-label"><?php esc_html_e( 'Peticiones (24h)', 'wp-secure' ); ?></span>
				</div>
				<div class="wps-widget-stat">
					<span class="wps-widget-stat-number wps-widget-stat-danger"><?php echo esc_html( number_format_i18n( $stats['blocked_requests'] ) ); ?></span>
					<span class="wps-widget-stat-label"><?php esc_html_e( 'Bloqueadas (24h)', 'wp-secure' ); ?></span>
				</div>
				<div class="wps-widget-stat">
					<span class="wps-widget-stat-number"><?php echo esc_html( number_format_i18n( $stats['unique_ips'] ) ); ?></span>
					<span class="wps-widget-stat-label"><?php esc_html_e( 'IPs Únicas (24h)', 'wp-secure' ); ?></span>
				</div>
				<div class="wps-widget-stat">
					<span class="wps-widget-stat-number <?php echo $stats['critical_events'] > 0 ? 'wps-widget-stat-danger' : ''; ?>"><?php echo esc_html( number_format_i18n( $stats['critical_events'] ) ); ?></span>
					<span class="wps-widget-stat-label"><?php esc_html_e( 'Eventos Críticos', 'wp-secure' ); ?></span>
				</div>
				<div class="wps-widget-stat">
					<span class="wps-widget-stat-number"><?php echo esc_html( number_format_i18n( $active_blocks ) ); ?></span>
					<span class="wps-widget-stat-label"><?php esc_html_e( 'Bloqueos Activos', 'wp-secure' ); ?></span>
				</div>
			</div>

			<!-- Gráfico de actividad 24h -->
			<div class="wps-widget-chart">
				<canvas id="wps-widget-chart-hourly" height="120"></canvas>
			</div>

			<div class="wps-widget-links">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure' ) ); ?>"><?php esc_html_e( 'Dashboard', 'wp-secure' ); ?></a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-traffic' ) ); ?>"><?php esc_html_e( 'Tráfico en Vivo', 'wp-secure' ); ?></a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-events' ) ); ?>"><?php esc_html_e( 'Eventos', 'wp-secure' ); ?></a>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-blocks' ) ); ?>"><?php esc_html_e( 'Bloqueos', 'wp-secure' ); ?></a>
			</div>
		</div>

		<script>
		window.wpsWidgetChartData = {
			labels: <?php echo wp_json_encode( array_column( $hourly, 'label' ) ); ?>,
			requests: <?php echo wp_json_encode( array_map( 'intval', array_column( $hourly, 'requests' ) ) ); ?>,
			blocks: <?php echo wp_json_encode( array_map( 'intval', array_column( $hourly, 'blocks' ) ) ); ?>
		};
		</script>
		<?php
	}

	/**
	 * Obtener estadísticas de las últimas 24 horas.
	 */
	private function get_stats(): array {
		$db = WPS_Db::get_instance();

		$traffic_table = WPS_Db_Schema::table( 'traffic_log' );
		$events_table  = WPS_Db_Schema::table( 'security_events' );
		$blocked_table = WPS_Db_Schema::table( 'blocked_ips' );

		$total_requests = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$traffic_table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)"
		);

		$unique_ips = (int) $db->get_var(
			"SELECT COUNT(DISTINCT ip_address) FROM {$traffic_table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)"
		);

		$blocked_requests = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$events_table}
			 WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)
			 AND event_type IN ('login_blocked','xmlrpc_blocked','sqli_detected','xss_detected','traversal_detected','rate_limited','scanner_detected','country_blocked','asn_blocked','ip_blocked')"
		);

		$critical_events = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$events_table}
			 WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR) AND severity = 'critical'"
		);

		$total_blocks = WPS_Blocker::get_instance()->count_total_blocks();

		return array(
			'total_requests'   => $total_requests,
			'unique_ips'       => $unique_ips,
			'blocked_requests' => $blocked_requests,
			'critical_events'  => $critical_events,
			'total_blocks'     => $total_blocks,
		);
	}

	/**
	 * Obtener actividad por hora (últimas 24h).
	 */
	private function get_hourly_activity(): array {
		$db            = WPS_Db::get_instance();
		$traffic_table = WPS_Db_Schema::table( 'traffic_log' );
		$events_table  = WPS_Db_Schema::table( 'security_events' );

		// Peticiones por hora.
		$requests_raw = $db->get_results(
			"SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS hour_slot, COUNT(*) AS cnt
			 FROM {$traffic_table}
			 WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)
			 GROUP BY hour_slot ORDER BY hour_slot ASC"
		);

		// Bloqueos por hora.
		$blocks_raw = $db->get_results(
			"SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS hour_slot, COUNT(*) AS cnt
			 FROM {$events_table}
			 WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)
			 AND severity IN ('warning','critical')
			 GROUP BY hour_slot ORDER BY hour_slot ASC"
		);

		// Indexar por slot.
		$req_map   = array();
		$block_map = array();
		foreach ( $requests_raw as $r ) {
			$req_map[ $r['hour_slot'] ] = (int) $r['cnt'];
		}
		foreach ( $blocks_raw as $r ) {
			$block_map[ $r['hour_slot'] ] = (int) $r['cnt'];
		}

		// Generar las 24 horas.
		$result = array();
		for ( $i = 23; $i >= 0; $i-- ) {
			$slot = gmdate( 'Y-m-d H:00', strtotime( "-{$i} hours" ) );
			$result[] = array(
				'label'    => gmdate( 'H:00', strtotime( "-{$i} hours" ) ),
				'requests' => $req_map[ $slot ] ?? 0,
				'blocks'   => $block_map[ $slot ] ?? 0,
			);
		}

		return $result;
	}

	/**
	 * Top 10 IPs bloqueadas (activas, por hits).
	 */
	private function get_top_blocked_ips(): array {
		$db    = WPS_Db::get_instance();
		$table = WPS_Db_Schema::table( 'blocked_ips' );

		return $db->get_results(
			"SELECT ip_address, hit_count, block_type FROM {$table}
			 WHERE is_active = 1 AND ip_address IS NOT NULL
			 ORDER BY hit_count DESC LIMIT 10"
		);
	}

	/**
	 * Top 10 países por tráfico (últimas 24h).
	 */
	private function get_top_countries(): array {
		$db    = WPS_Db::get_instance();
		$table = WPS_Db_Schema::table( 'traffic_log' );

		$raw = $db->get_results(
			"SELECT country_code, COUNT(*) AS cnt FROM {$table}
			 WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)
			 AND country_code IS NOT NULL AND country_code != ''
			 GROUP BY country_code ORDER BY cnt DESC LIMIT 10"
		);

		$result = array();
		foreach ( $raw as $row ) {
			$result[] = array(
				'country_code' => $row['country_code'],
				'country_name' => WPS_Geo::country_name( $row['country_code'] ),
				'count'        => $row['cnt'],
			);
		}

		return $result;
	}

	/**
	 * Tarjeta de estado del sistema.
	 */
	private function render_status_card(): void {
		$unsafe_mode = (bool) get_option( 'wps_unsafe_mode', false );
		$tables_ok = WPS_Db_Schema::tables_exist();
		$ipdb      = WPS_Ipdb_Manager::get_instance();
		$has_mmdb  = $ipdb->is_local_available();
		$mode      = $this->loader->get_setting( 'ipinfo_mode', 'api' );
		$api_key   = $this->loader->get_setting( 'ipinfo_api_key', '' );
		$has_api   = ! empty( $api_key );

		// IPDB status.
		if ( 'local' === $mode && $has_mmdb ) {
			$ipdb_badge = 'ok';
			$ipdb_label = __( 'MMDB local', 'wp-secure' );
		} elseif ( 'api' === $mode && $has_api ) {
			$ipdb_badge = 'ok';
			$ipdb_label = __( 'API en línea', 'wp-secure' );
		} elseif ( $has_api ) {
			$ipdb_badge = 'pending';
			$ipdb_label = __( 'API configurada', 'wp-secure' );
		} else {
			$ipdb_badge = 'pending';
			$ipdb_label = __( 'No configurada', 'wp-secure' );
		}

		// Layer 0/1 status.
		$layer0_ok = $this->loader->get_setting( 'firewall_layer0_enabled', false ) && is_file( WPS_DATA_DIR . 'wps-blocked-ips.php' );
		$layer1_ok = is_file( WPMU_PLUGIN_DIR . '/wps-firewall-muplugin.php' );

		// Geo blocks.
		$blocker           = WPS_Blocker::get_instance();
		$blocked_countries = count( $blocker->get_blocked_countries() );
		$blocked_asns      = count( $blocker->get_blocked_asns() );
		?>
		<div class="wps-card wps-card-wide <?php echo $unsafe_mode ? 'wps-card-danger' : ''; ?>">
			<h3>
				<span class="dashicons dashicons-shield-alt"></span>
				<?php esc_html_e( 'Estado del Sistema', 'wp-secure' ); ?>
				<?php if ( $unsafe_mode ) : ?>
					<span class="wps-badge wps-badge-danger" style="margin-left:8px;font-size:11px;">
						<?php esc_html_e( 'MODO INSEGURO', 'wp-secure' ); ?>
					</span>
				<?php endif; ?>
			</h3>
			<table class="wps-status-table">
				<tr>
					<td><?php esc_html_e( 'Plugin', 'wp-secure' ); ?></td>
					<td>
						<?php
						// Usar get_plugin_data() para leer la versión real del archivo principal,
						// evitando mostrar la constante WPS_VERSION que puede estar contaminada
						// por un MU-plugin desactualizado que la definió primero.
						$plugin_data    = get_plugin_data( WPS_PLUGIN_FILE, false, false );
						$plugin_version = ! empty( $plugin_data['Version'] ) ? $plugin_data['Version'] : WPS_VERSION;
						?>
						<span class="wps-badge wps-badge-ok"><?php echo esc_html( 'v' . $plugin_version ); ?></span>
					</td>
				</tr>
				<tr>
					<td><?php esc_html_e( 'Modo Inseguro', 'wp-secure' ); ?></td>
					<td>
						<?php if ( $unsafe_mode ) : ?>
							<span class="wps-badge wps-badge-danger"><?php esc_html_e( 'Activo — Solo detecta', 'wp-secure' ); ?></span>
						<?php else : ?>
							<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Inactivo — Bloqueo normal', 'wp-secure' ); ?></span>
						<?php endif; ?>
						<button type="button"
							class="button button-small wps-unsafe-toggle-btn"
							data-nonce="<?php echo esc_attr( wp_create_nonce( 'wps_admin_nonce' ) ); ?>"
							style="margin-left:8px;">
							<?php echo $unsafe_mode
								? esc_html__( 'Desactivar', 'wp-secure' )
								: esc_html__( 'Activar Modo Inseguro', 'wp-secure' ); ?>
						</button>
					</td>
				</tr>
				<tr>
					<td><?php esc_html_e( 'Base de Datos', 'wp-secure' ); ?></td>
					<td>
						<?php if ( $tables_ok ) : ?>
							<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'OK', 'wp-secure' ); ?></span>
						<?php else : ?>
							<span class="wps-badge wps-badge-error"><?php esc_html_e( 'Error', 'wp-secure' ); ?></span>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<td><?php esc_html_e( 'Firewall Capa 0', 'wp-secure' ); ?></td>
					<td>
						<?php if ( $layer0_ok ) : ?>
							<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Activo', 'wp-secure' ); ?></span>
						<?php else : ?>
							<span class="wps-badge wps-badge-pending"><?php esc_html_e( 'No instalado', 'wp-secure' ); ?></span>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<td><?php esc_html_e( 'Firewall Capa 1', 'wp-secure' ); ?></td>
					<td>
						<?php if ( $layer1_ok ) : ?>
							<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Activo', 'wp-secure' ); ?></span>
						<?php else : ?>
							<span class="wps-badge wps-badge-pending"><?php esc_html_e( 'No instalado', 'wp-secure' ); ?></span>
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<td><?php esc_html_e( 'Base de Datos IP', 'wp-secure' ); ?></td>
					<td><span class="wps-badge wps-badge-<?php echo esc_attr( $ipdb_badge ); ?>"><?php echo esc_html( $ipdb_label ); ?></span></td>
				</tr>
				<?php if ( $blocked_countries > 0 || $blocked_asns > 0 ) : ?>
				<tr>
					<td><?php esc_html_e( 'Bloqueos Geo', 'wp-secure' ); ?></td>
					<td>
						<?php if ( $blocked_countries > 0 ) : ?>
							<span class="wps-badge wps-badge-warning">
								<?php echo esc_html( sprintf( _n( '%d país', '%d países', $blocked_countries, 'wp-secure' ), $blocked_countries ) ); ?>
							</span>
						<?php endif; ?>
						<?php if ( $blocked_asns > 0 ) : ?>
							<span class="wps-badge wps-badge-warning">
								<?php echo esc_html( sprintf( _n( '%d ASN', '%d ASNs', $blocked_asns, 'wp-secure' ), $blocked_asns ) ); ?>
							</span>
						<?php endif; ?>
					</td>
				</tr>
				<?php endif; ?>
			</table>
		</div>
		<?php
	}

	/**
	 * Tarjeta de estadística numérica.
	 */
	private function render_stat_card( string $title, int $value, string $icon, string $extra_class = '' ): void {
		?>
		<div class="wps-card <?php echo esc_attr( $extra_class ); ?>">
			<div class="wps-card-icon"><span class="dashicons <?php echo esc_attr( $icon ); ?>"></span></div>
			<div class="wps-card-data">
				<span class="wps-card-number"><?php echo esc_html( number_format_i18n( $value ) ); ?></span>
				<span class="wps-card-label"><?php echo esc_html( $title ); ?></span>
			</div>
		</div>
		<?php
	}

	/**
	 * Tabla de últimos eventos de seguridad.
	 */
	private function render_recent_events(): void {
		$db    = WPS_Db::get_instance();
		$table = WPS_Db_Schema::table( 'security_events' );

		$events = $db->get_results(
			"SELECT * FROM {$table} ORDER BY created_at DESC LIMIT 10"
		);

		if ( empty( $events ) ) {
			echo '<p class="wps-no-data">' . esc_html__( 'No hay eventos registrados aún.', 'wp-secure' ) . '</p>';
			return;
		}
		?>
		<table class="wps-table widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
					<th><?php esc_html_e( 'Severidad', 'wp-secure' ); ?></th>
					<th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
					<th><?php esc_html_e( 'IP', 'wp-secure' ); ?></th>
					<th><?php esc_html_e( 'URI', 'wp-secure' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $events as $event ) : ?>
				<tr class="wps-severity-<?php echo esc_attr( $event['severity'] ); ?>">
					<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', strtotime( $event['created_at'] ) ) ); ?></td>
					<td><span class="wps-badge wps-badge-<?php echo esc_attr( $event['severity'] ); ?>"><?php echo esc_html( ucfirst( $event['severity'] ) ); ?></span></td>
					<td><?php echo esc_html( WPS_Event_Types::label( $event['event_type'] ) ); ?></td>
					<td>
						<?php if ( $event['ip_address'] ) : ?>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-traffic&ip=' . urlencode( $event['ip_address'] ) ) ); ?>">
								<code><?php echo esc_html( $event['ip_address'] ); ?></code>
							</a>
						<?php else : ?>
							—
						<?php endif; ?>
					</td>
					<td><?php echo esc_html( $event['request_uri'] ? mb_strimwidth( $event['request_uri'], 0, 80, '…' ) : '—' ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Información del sistema.
	 */
	private function render_system_info(): void {
		global $wpdb;
		?>
		<table class="wps-table widefat striped">
			<tbody>
				<tr>
					<td><strong><?php esc_html_e( 'Versión PHP', 'wp-secure' ); ?></strong></td>
					<td><?php echo esc_html( PHP_VERSION ); ?></td>
				</tr>
				<tr>
					<td><strong><?php esc_html_e( 'Versión WordPress', 'wp-secure' ); ?></strong></td>
					<td><?php echo esc_html( get_bloginfo( 'version' ) ); ?></td>
				</tr>
				<tr>
					<td><strong><?php esc_html_e( 'Servidor', 'wp-secure' ); ?></strong></td>
					<td><?php echo esc_html( $_SERVER['SERVER_SOFTWARE'] ?? 'N/A' ); ?></td>
				</tr>
				<tr>
					<td><strong><?php esc_html_e( 'Base de datos', 'wp-secure' ); ?></strong></td>
					<td><?php echo esc_html( $wpdb->db_version() ); ?></td>
				</tr>
				<tr>
					<td><strong><?php esc_html_e( 'Prefijo de tablas WPS', 'wp-secure' ); ?></strong></td>
					<td><code><?php echo esc_html( $wpdb->prefix . 'wps_' ); ?></code></td>
				</tr>
				<tr>
					<td><strong><?php esc_html_e( 'IP actual', 'wp-secure' ); ?></strong></td>
					<td><code><?php echo esc_html( WPS_Request::get_instance()->ip() ); ?></code></td>
				</tr>
			</tbody>
		</table>
		<?php
	}
}
