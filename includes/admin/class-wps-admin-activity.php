<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página del registro de actividad.
 */
class WPS_Admin_Activity {

	const PER_PAGE = 50;

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Activity_Log */
	private $log;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
		$this->log    = new WPS_Activity_Log( $loader );
	}

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- filtros de sólo lectura.
		$group   = isset( $_GET['group'] ) ? sanitize_key( wp_unslash( $_GET['group'] ) ) : '';
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		$page    = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:enable

		$result = $this->log->query( array( 'group' => $group, 'user_id' => $user_id ), $page, self::PER_PAGE );
		$pages  = (int) ceil( $result['total'] / self::PER_PAGE );
		$groups = array(
			''         => __( 'Todas las acciones', 'wp-secure' ),
			'users'    => __( 'Usuarios', 'wp-secure' ),
			'content'  => __( 'Contenido', 'wp-secure' ),
			'plugins'  => __( 'Plugins, temas y núcleo', 'wp-secure' ),
			'settings' => __( 'Ajustes', 'wp-secure' ),
		);
		$users = get_users( array( 'capability' => 'edit_posts', 'fields' => array( 'ID', 'user_login' ), 'number' => 200 ) );
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Actividad', 'wp-secure' ); ?></h1>

			<?php if ( ! $this->loader->get_setting( 'activity_log_enabled', true ) ) : ?>
				<div class="notice notice-warning"><p><?php esc_html_e( 'El registro de actividad está desactivado en Configuración → Firewall Avanzado.', 'wp-secure' ); ?></p></div>
			<?php endif; ?>

			<p class="description">
				<?php esc_html_e( 'Quién hizo qué y cuándo: usuarios, contenido, plugins, temas y ajustes. Se registran las acciones de quienes pueden editar contenido y las de WP-CLI; es independiente del log de seguridad.', 'wp-secure' ); ?>
			</p>

			<form method="get" style="margin:16px 0;">
				<input type="hidden" name="page" value="wp-secure-activity" />
				<select name="group">
					<?php foreach ( $groups as $value => $label ) : ?>
						<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $group, $value ); ?>><?php echo esc_html( $label ); ?></option>
					<?php endforeach; ?>
				</select>
				<select name="user_id">
					<option value="0"><?php esc_html_e( 'Todos los usuarios', 'wp-secure' ); ?></option>
					<?php foreach ( $users as $user ) : ?>
						<option value="<?php echo esc_attr( $user->ID ); ?>" <?php selected( $user_id, (int) $user->ID ); ?>><?php echo esc_html( $user->user_login ); ?></option>
					<?php endforeach; ?>
				</select>
				<?php submit_button( __( 'Filtrar', 'wp-secure' ), 'secondary', '', false ); ?>
				<span class="description" style="margin-left:8px;">
					<?php
					/* translators: %s: number of entries */
					echo esc_html( sprintf( __( '%s entradas', 'wp-secure' ), number_format_i18n( $result['total'] ) ) );
					?>
				</span>
			</form>

			<?php if ( ! $result['rows'] ) : ?>
				<p><?php esc_html_e( 'No hay actividad registrada.', 'wp-secure' ); ?></p>
			<?php else : ?>
				<table class="widefat striped wps-table">
					<thead><tr>
						<th style="width:140px;"><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
						<th style="width:160px;"><?php esc_html_e( 'Usuario', 'wp-secure' ); ?></th>
						<th style="width:220px;"><?php esc_html_e( 'Acción', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Objeto', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Detalle', 'wp-secure' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $result['rows'] as $row ) : ?>
						<tr>
							<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', strtotime( $row['created_at'] . ' UTC' ) ) ); ?></td>
							<td>
								<strong><?php echo esc_html( $row['user_login'] ); ?></strong>
								<?php if ( '' !== $row['ip_address'] ) : ?>
									<br><code><?php echo esc_html( $row['ip_address'] ); ?></code>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( WPS_Activity_Log::label( $row['action'] ) ); ?></td>
							<td>
								<?php echo esc_html( $row['object_name'] ); ?>
								<?php if ( '' !== $row['object_type'] && ! in_array( $row['object_type'], array( 'user', 'plugin', 'theme', 'option', 'site', 'core', 'file', 'wp-secure' ), true ) ) : ?>
									<span class="description">(<?php echo esc_html( $row['object_type'] ); ?><?php echo $row['object_id'] ? ' #' . esc_html( $row['object_id'] ) : ''; ?>)</span>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( self::details_text( (string) $row['details'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>

				<?php if ( $pages > 1 ) : ?>
					<div class="tablenav"><div class="tablenav-pages">
						<?php
						echo wp_kses_post( paginate_links( array(
							'base'    => add_query_arg( 'paged', '%#%' ),
							'format'  => '',
							'current' => $page,
							'total'   => $pages,
						) ) );
						?>
					</div></div>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Detalles en una línea legible: «from: x → to: y», «fields: email, password».
	 */
	public static function details_text( string $json ): string {
		$details = json_decode( $json, true );
		if ( ! is_array( $details ) || ! $details ) {
			return '';
		}

		if ( array_key_exists( 'from', $details ) && array_key_exists( 'to', $details ) ) {
			$from = is_array( $details['from'] ) ? implode( ', ', $details['from'] ) : (string) $details['from'];
			$to   = is_array( $details['to'] ) ? implode( ', ', $details['to'] ) : (string) $details['to'];
			return ( '' !== $from ? $from : '∅' ) . ' → ' . ( '' !== $to ? $to : '∅' );
		}

		$parts = array();
		foreach ( $details as $key => $value ) {
			$parts[] = $key . ': ' . ( is_array( $value ) ? implode( ', ', $value ) : (string) $value );
		}
		return implode( ' · ', $parts );
	}
}
