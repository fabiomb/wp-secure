<?php
defined( 'ABSPATH' ) || exit;

/**
 * Visor de tráfico en vivo.
 *
 * Muestra las últimas peticiones registradas en wps_traffic_log con
 * polling AJAX cada 5 segundos. Incluye filtros por tipo, país,
 * estado y detalle por IP.
 */
class WPS_Admin_Live_Traffic {

	/** @var WPS_Loader */
	private $loader;

	/** @var int Registros por página. */
	private $per_page = 50;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Renderizar la página de tráfico en vivo.
	 */
	public function render(): void {
		// Si hay parámetro ip, mostrar detalle.
		if ( isset( $_GET['ip'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_GET['ip'] ) );
			if ( WPS_Ip_Utils::is_valid_ip( $ip ) ) {
				$this->render_ip_detail( $ip );
				return;
			}
		}

		$this->render_traffic_list();
	}

	/**
	 * Renderizar la lista de tráfico.
	 */
	private function render_traffic_list(): void {
		?>
		<div class="wrap wps-wrap">
			<h1>
				<?php esc_html_e( 'WP Seguro — Tráfico en Vivo', 'wp-secure' ); ?>
				<span id="wps-traffic-status" class="wps-badge wps-badge-ok" style="vertical-align:middle;margin-left:8px;">
					<?php esc_html_e( 'En vivo', 'wp-secure' ); ?>
				</span>
			</h1>

			<!-- Filtros -->
			<div class="wps-section">
				<form class="wps-filters-form" id="wps-traffic-filters">
					<input type="hidden" name="page" value="wp-secure-traffic" />
					<label for="wps-filter-type"><?php esc_html_e( 'Tipo:', 'wp-secure' ); ?></label>
					<select id="wps-filter-type" name="visitor_type">
						<option value=""><?php esc_html_e( 'Todos', 'wp-secure' ); ?></option>
						<option value="page"><?php esc_html_e( 'Página', 'wp-secure' ); ?></option>
						<option value="login"><?php esc_html_e( 'Login', 'wp-secure' ); ?></option>
						<option value="xmlrpc"><?php esc_html_e( 'XML-RPC', 'wp-secure' ); ?></option>
						<option value="restapi"><?php esc_html_e( 'REST API', 'wp-secure' ); ?></option>
						<option value="admin"><?php esc_html_e( 'Admin', 'wp-secure' ); ?></option>
						<option value="ajax"><?php esc_html_e( 'AJAX', 'wp-secure' ); ?></option>
						<option value="cron"><?php esc_html_e( 'Cron', 'wp-secure' ); ?></option>
						<option value="feed"><?php esc_html_e( 'Feed', 'wp-secure' ); ?></option>
						<option value="static"><?php esc_html_e( 'Estático', 'wp-secure' ); ?></option>
					</select>

					<label for="wps-filter-method"><?php esc_html_e( 'Método:', 'wp-secure' ); ?></label>
					<select id="wps-filter-method" name="method">
						<option value=""><?php esc_html_e( 'Todos', 'wp-secure' ); ?></option>
						<option value="GET">GET</option>
						<option value="POST">POST</option>
						<option value="PUT">PUT</option>
						<option value="DELETE">DELETE</option>
					</select>

					<label for="wps-filter-ip"><?php esc_html_e( 'IP:', 'wp-secure' ); ?></label>
					<input type="text" id="wps-filter-ip" name="ip" placeholder="<?php esc_attr_e( 'Filtrar por IP...', 'wp-secure' ); ?>" class="regular-text" style="max-width:160px;" />

					<label>
						<input type="checkbox" id="wps-traffic-pause" />
						<?php esc_html_e( 'Pausar', 'wp-secure' ); ?>
					</label>
				</form>
			</div>

			<!-- Tabla de tráfico -->
			<div class="wps-section">
				<table class="wps-table widefat striped" id="wps-traffic-table">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Hora', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'IP', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'País', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Método', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'URI', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Status', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'User-Agent', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
						</tr>
					</thead>
					<tbody id="wps-traffic-body">
						<tr><td colspan="9" class="wps-no-data"><?php esc_html_e( 'Cargando...', 'wp-secure' ); ?></td></tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Renderizar la vista de detalle de una IP.
	 */
	private function render_ip_detail( string $ip ): void {
		$db           = WPS_Db::get_instance();
		$traffic_tbl  = WPS_Db_Schema::table( 'traffic_log' );
		$events_tbl   = WPS_Db_Schema::table( 'security_events' );
		$blocked_tbl  = WPS_Db_Schema::table( 'blocked_ips' );
		$blocker      = WPS_Blocker::get_instance();
		$whitelist    = WPS_Whitelist::get_instance();

		// Geo info.
		$geo_data = array( 'country' => null, 'asn' => null, 'asn_name' => null );
		if ( ! WPS_Ip_Utils::is_private_ip( $ip ) ) {
			$geo = WPS_Geo::get_instance();
			$geo_data = $geo->lookup( $ip );
		}

		// Estado de bloqueo.
		$block       = $blocker->is_blocked( $ip );
		$is_wl       = $whitelist->is_whitelisted( $ip );

		// Conteos.
		$total_hits = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$traffic_tbl} WHERE ip_address = %s",
			$ip
		);
		$hits_24h = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$traffic_tbl} WHERE ip_address = %s AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)",
			$ip
		);
		$event_count = (int) $db->get_var(
			"SELECT COUNT(*) FROM {$events_tbl} WHERE ip_address = %s",
			$ip
		);

		// Últimas peticiones.
		$recent_requests = $db->get_results(
			"SELECT * FROM {$traffic_tbl} WHERE ip_address = %s ORDER BY created_at DESC LIMIT 50",
			$ip
		);

		// Eventos de seguridad de esta IP.
		$security_events = $db->get_results(
			"SELECT * FROM {$events_tbl} WHERE ip_address = %s ORDER BY created_at DESC LIMIT 20",
			$ip
		);

		// Historial de bloqueos.
		$block_history = $db->get_results(
			"SELECT * FROM {$blocked_tbl} WHERE ip_address = %s ORDER BY blocked_at DESC",
			$ip
		);

		$back_url = admin_url( 'admin.php?page=wp-secure-traffic' );
		?>
		<div class="wrap wps-wrap">
			<h1>
				<a href="<?php echo esc_url( $back_url ); ?>" class="page-title-action" style="margin-right:8px;">
					&larr; <?php esc_html_e( 'Volver', 'wp-secure' ); ?>
				</a>
				<?php echo esc_html( sprintf( __( 'Detalle de IP: %s', 'wp-secure' ), $ip ) ); ?>
			</h1>

			<!-- Tarjetas de información -->
			<div class="wps-cards-row">
				<div class="wps-card">
					<div class="wps-card-icon"><span class="dashicons dashicons-admin-site-alt3"></span></div>
					<div class="wps-card-data">
						<span class="wps-card-number"><?php echo esc_html( $geo_data['country'] ? WPS_Geo::country_name( $geo_data['country'] ) : '—' ); ?></span>
						<span class="wps-card-label"><?php esc_html_e( 'País', 'wp-secure' ); ?> <?php echo esc_html( $geo_data['country'] ?? '' ); ?></span>
					</div>
				</div>
				<div class="wps-card">
					<div class="wps-card-icon"><span class="dashicons dashicons-networking"></span></div>
					<div class="wps-card-data">
						<span class="wps-card-number"><?php echo esc_html( $geo_data['asn'] ? 'AS' . $geo_data['asn'] : '—' ); ?></span>
						<span class="wps-card-label"><?php echo esc_html( $geo_data['asn_name'] ?? __( 'ASN', 'wp-secure' ) ); ?></span>
					</div>
				</div>
				<div class="wps-card">
					<div class="wps-card-icon"><span class="dashicons dashicons-visibility"></span></div>
					<div class="wps-card-data">
						<span class="wps-card-number"><?php echo esc_html( number_format_i18n( $hits_24h ) ); ?></span>
						<span class="wps-card-label"><?php esc_html_e( 'Peticiones 24h', 'wp-secure' ); ?></span>
					</div>
				</div>
				<div class="wps-card <?php echo $event_count > 0 ? 'wps-card-danger' : ''; ?>">
					<div class="wps-card-icon"><span class="dashicons dashicons-warning"></span></div>
					<div class="wps-card-data">
						<span class="wps-card-number"><?php echo esc_html( number_format_i18n( $event_count ) ); ?></span>
						<span class="wps-card-label"><?php esc_html_e( 'Eventos seguridad', 'wp-secure' ); ?></span>
					</div>
				</div>
			</div>

			<!-- Estado y acciones rápidas -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Estado y Acciones', 'wp-secure' ); ?></h2>
				<table class="wps-status-table">
					<tr>
						<td><strong><?php esc_html_e( 'Estado de bloqueo', 'wp-secure' ); ?></strong></td>
						<td>
							<?php if ( $block ) : ?>
								<span class="wps-badge wps-badge-critical"><?php esc_html_e( 'Bloqueada', 'wp-secure' ); ?></span>
								<?php echo esc_html( $block['reason'] ?? '' ); ?>
							<?php else : ?>
								<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'No bloqueada', 'wp-secure' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Whitelist', 'wp-secure' ); ?></strong></td>
						<td>
							<?php if ( $is_wl ) : ?>
								<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'En whitelist', 'wp-secure' ); ?></span>
							<?php else : ?>
								<span class="wps-badge wps-badge-pending"><?php esc_html_e( 'No', 'wp-secure' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Total peticiones', 'wp-secure' ); ?></strong></td>
						<td><?php echo esc_html( number_format_i18n( $total_hits ) ); ?></td>
					</tr>
				</table>
				<div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
					<?php if ( ! $block ) : ?>
						<button type="button" class="button wps-ajax-action" data-action="wps_block_ip" data-ip="<?php echo esc_attr( $ip ); ?>" data-reason="<?php echo esc_attr__( 'Bloqueo manual desde detalle IP', 'wp-secure' ); ?>">
							<span class="dashicons dashicons-dismiss" style="vertical-align:text-top;"></span>
							<?php esc_html_e( 'Bloquear IP', 'wp-secure' ); ?>
						</button>
					<?php else : ?>
						<button type="button" class="button wps-ajax-action" data-action="wps_unblock_ip" data-id="<?php echo esc_attr( $block['id'] ); ?>">
							<span class="dashicons dashicons-yes-alt" style="vertical-align:text-top;"></span>
							<?php esc_html_e( 'Desbloquear IP', 'wp-secure' ); ?>
						</button>
					<?php endif; ?>
					<?php if ( ! $is_wl ) : ?>
						<button type="button" class="button wps-ajax-action" data-action="wps_whitelist_add" data-ip="<?php echo esc_attr( $ip ); ?>" data-label="<?php echo esc_attr( sprintf( __( 'Agregada desde detalle IP — %s', 'wp-secure' ), $ip ) ); ?>" data-type="global">
							<span class="dashicons dashicons-yes" style="vertical-align:text-top;"></span>
							<?php esc_html_e( 'Agregar a Whitelist', 'wp-secure' ); ?>
						</button>
					<?php endif; ?>
				</div>
			</div>

			<!-- Últimas peticiones -->
			<div class="wps-section">
				<h2><?php echo esc_html( sprintf( __( 'Últimas Peticiones (%d)', 'wp-secure' ), count( $recent_requests ) ) ); ?></h2>
				<?php if ( empty( $recent_requests ) ) : ?>
					<p class="wps-no-data"><?php esc_html_e( 'Sin registros.', 'wp-secure' ); ?></p>
				<?php else : ?>
					<table class="wps-table widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Hora', 'wp-secure' ); ?></th>
								<th><?php esc_html_e( 'Método', 'wp-secure' ); ?></th>
								<th><?php esc_html_e( 'URI', 'wp-secure' ); ?></th>
								<th><?php esc_html_e( 'Status', 'wp-secure' ); ?></th>
								<th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
								<th><?php esc_html_e( 'User-Agent', 'wp-secure' ); ?></th>
							</tr>
						</thead>
						<tbody>
						<?php foreach ( $recent_requests as $req ) : ?>
							<tr>
								<td><?php echo esc_html( wp_date( 'H:i:s', strtotime( $req['created_at'] ) ) ); ?></td>
								<td><code><?php echo esc_html( $req['request_method'] ); ?></code></td>
								<td title="<?php echo esc_attr( $req['request_uri'] ); ?>"><?php echo esc_html( mb_strimwidth( $req['request_uri'], 0, 80, '…' ) ); ?></td>
								<td><?php echo esc_html( $req['http_status'] ?? '—' ); ?></td>
								<td><span class="wps-badge wps-badge-info"><?php echo esc_html( $req['visitor_type'] ); ?></span></td>
								<td>
									<?php
									$ua_full = $req['user_agent'] ?? '';
									$ua_short = mb_strimwidth( $ua_full, 0, 80, '…' );
									$ua_needs_expand = mb_strlen( $ua_full ) > 80;
									?>
									<span class="wps-ua-cell<?php echo $ua_needs_expand ? '' : ''; ?>">
										<span class="wps-ua-short"><?php echo esc_html( $ua_short ); ?></span>
										<?php if ( $ua_needs_expand ) : ?>
											<span class="wps-ua-full"><?php echo esc_html( $ua_full ); ?></span>
											<button type="button" class="wps-ua-toggle" data-collapsed="▼" data-expanded="▲">▼</button>
										<?php endif; ?>
									</span>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>

			<?php if ( ! empty( $security_events ) ) : ?>
			<!-- Eventos de seguridad -->
			<div class="wps-section">
				<h2><?php echo esc_html( sprintf( __( 'Eventos de Seguridad (%d)', 'wp-secure' ), count( $security_events ) ) ); ?></h2>
				<table class="wps-table widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Severidad', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'URI', 'wp-secure' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $security_events as $ev ) : ?>
						<tr class="wps-severity-<?php echo esc_attr( $ev['severity'] ); ?>">
							<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', strtotime( $ev['created_at'] ) ) ); ?></td>
							<td><span class="wps-badge wps-badge-<?php echo esc_attr( $ev['severity'] ); ?>"><?php echo esc_html( ucfirst( $ev['severity'] ) ); ?></span></td>
							<td><?php echo esc_html( WPS_Event_Types::label( $ev['event_type'] ) ); ?></td>
							<td><?php echo esc_html( $ev['request_uri'] ? mb_strimwidth( $ev['request_uri'], 0, 60, '…' ) : '—' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<?php endif; ?>

			<?php if ( ! empty( $block_history ) ) : ?>
			<!-- Historial de bloqueos -->
			<div class="wps-section">
				<h2><?php esc_html_e( 'Historial de Bloqueos', 'wp-secure' ); ?></h2>
				<table class="wps-table widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Razón', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Expira', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Activo', 'wp-secure' ); ?></th>
							<th><?php esc_html_e( 'Hits', 'wp-secure' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $block_history as $bh ) : ?>
						<tr>
							<td><?php echo esc_html( wp_date( 'Y-m-d H:i', strtotime( $bh['blocked_at'] ) ) ); ?></td>
							<td><code><?php echo esc_html( $bh['block_type'] ); ?></code></td>
							<td><?php echo esc_html( $bh['reason'] ); ?></td>
							<td><?php echo esc_html( $bh['expires_at'] ? wp_date( 'Y-m-d H:i', strtotime( $bh['expires_at'] ) ) : __( 'Permanente', 'wp-secure' ) ); ?></td>
							<td>
								<?php if ( $bh['is_active'] ) : ?>
									<span class="wps-badge wps-badge-critical"><?php esc_html_e( 'Sí', 'wp-secure' ); ?></span>
								<?php else : ?>
									<span class="wps-badge wps-badge-pending"><?php esc_html_e( 'No', 'wp-secure' ); ?></span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( number_format_i18n( $bh['hit_count'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<?php endif; ?>
		</div>
		<?php
	}
}
