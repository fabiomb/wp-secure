<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página del chequeo de endurecimiento.
 */
class WPS_Admin_Hardening {

	/** @var WPS_Hardening_Check */
	private $check;

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Csp */
	private $csp;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
		$this->check  = new WPS_Hardening_Check( $loader );
		$this->csp    = new WPS_Csp( $loader );
	}

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		$message = $this->handle_csp_actions();
		$fresh   = $this->wants_fresh_run();
		if ( null === $fresh ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Nonce inválido.', 'wp-secure' ) . '</p></div>';
			$fresh = false;
		}

		$results = $this->check->run( $fresh );
		$counts  = WPS_Hardening_Check::counts( $results );
		$badges  = array(
			WPS_Hardening_Check::FAIL => array( 'wps-badge-danger', __( 'Problema', 'wp-secure' ) ),
			WPS_Hardening_Check::WARN => array( 'wps-badge-warning', __( 'Mejorable', 'wp-secure' ) ),
			WPS_Hardening_Check::PASS => array( 'wps-badge-ok', __( 'Correcto', 'wp-secure' ) ),
			WPS_Hardening_Check::INFO => array( 'wps-badge-muted', __( 'Informativo', 'wp-secure' ) ),
		);
		$order = array_flip( array_keys( $badges ) );

		// Primero lo que hay que corregir.
		usort( $results, function ( $a, $b ) use ( $order ) {
			return $order[ $a['status'] ] <=> $order[ $b['status'] ];
		} );
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Endurecimiento', 'wp-secure' ); ?></h1>

			<?php if ( $message ) : ?>
				<div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible"><p><?php echo esc_html( $message['text'] ); ?></p></div>
			<?php endif; ?>

			<p class="description">
				<?php esc_html_e( 'Configuración del sitio y del servidor que el firewall no puede cubrir. WP Seguro sólo la verifica y explica cómo corregirla: no modifica wp-config.php ni la configuración del servidor.', 'wp-secure' ); ?>
			</p>

			<p style="margin:16px 0;">
				<?php foreach ( $badges as $status => $badge ) : ?>
					<span class="wps-badge <?php echo esc_attr( $badge[0] ); ?>" style="margin-right:8px;"><?php echo esc_html( $badge[1] . ': ' . $counts[ $status ] ); ?></span>
				<?php endforeach; ?>
			</p>

			<table class="widefat striped wps-table">
				<thead><tr>
					<th style="width:120px;"><?php esc_html_e( 'Estado', 'wp-secure' ); ?></th>
					<th style="width:220px;"><?php esc_html_e( 'Verificación', 'wp-secure' ); ?></th>
					<th><?php esc_html_e( 'Detalle y cómo corregirlo', 'wp-secure' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $results as $result ) : ?>
					<tr>
						<td><span class="wps-badge <?php echo esc_attr( $badges[ $result['status'] ][0] ); ?>"><?php echo esc_html( $badges[ $result['status'] ][1] ); ?></span></td>
						<td><strong><?php echo esc_html( $result['label'] ); ?></strong></td>
						<td>
							<?php echo esc_html( $result['message'] ); ?>
							<?php if ( '' !== $result['fix'] && in_array( $result['status'], array( WPS_Hardening_Check::FAIL, WPS_Hardening_Check::WARN, WPS_Hardening_Check::INFO ), true ) ) : ?>
								<pre style="margin:8px 0 0;white-space:pre-wrap;"><code><?php echo esc_html( $result['fix'] ); ?></code></pre>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>

			<form method="post" style="margin-top:16px;">
				<?php wp_nonce_field( 'wps_hardening', 'wps_hardening_nonce' ); ?>
				<?php submit_button( __( 'Volver a comprobar', 'wp-secure' ), 'secondary', 'wps_hardening_recheck', false ); ?>
				<span class="description" style="margin-left:8px;"><?php esc_html_e( 'El listado de directorios y el debug.log se comprueban con peticiones del sitio a sí mismo y se guardan 12 horas.', 'wp-secure' ); ?></span>
			</form>

			<?php $this->render_csp(); ?>
		</div>
		<?php
	}

	/**
	 * Sección de Content-Security-Policy: reportes y política sugerida.
	 */
	private function render_csp(): void {
		$mode    = $this->csp->mode();
		$reports = $this->csp->reports();
		$modes   = array(
			'off'     => __( 'Desactivada', 'wp-secure' ),
			'report'  => __( 'Sólo reportar', 'wp-secure' ),
			'enforce' => __( 'Aplicada', 'wp-secure' ),
		);

		uasort( $reports, function ( $a, $b ) {
			return $b['last'] <=> $a['last'];
		} );
		?>
		<h2 id="wps-csp" style="margin-top:32px;"><?php esc_html_e( 'Content-Security-Policy', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'La CSP le dice al navegador de qué orígenes puede cargar scripts, estilos, imágenes y marcos: un script inyectado desde otro dominio no se ejecuta. En modo «Sólo reportar» no bloquea nada; los navegadores informan lo que habría bloqueado y acá se arma la política sugerida.', 'wp-secure' ); ?>
		</p>

		<table class="widefat" style="max-width:640px;margin:16px 0;">
			<tbody>
				<tr><th><?php esc_html_e( 'Modo', 'wp-secure' ); ?></th><td>
					<?php echo esc_html( $modes[ $mode ] ); ?>
					— <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-settings' ) ); ?>"><?php esc_html_e( 'cambiar en Configuración', 'wp-secure' ); ?></a>
				</td></tr>
				<tr><th><?php esc_html_e( 'Orígenes reportados', 'wp-secure' ); ?></th><td><?php echo esc_html( number_format_i18n( count( $reports ) ) ); ?></td></tr>
			</tbody>
		</table>

		<?php if ( 'off' === $mode && ! $reports ) : ?>
			<p><?php esc_html_e( 'Activá «Sólo reportar» en Configuración → Firewall Avanzado y recorré el sitio (o esperá unos días de visitas) para juntar reportes.', 'wp-secure' ); ?></p>
			<?php return; ?>
		<?php endif; ?>

		<h3><?php esc_html_e( 'Política actual', 'wp-secure' ); ?></h3>
		<pre style="white-space:pre-wrap;"><code><?php echo esc_html( str_replace( '; ', ";\n", $this->csp->policy() ) ); ?></code></pre>

		<?php if ( $reports ) : ?>
			<h3><?php esc_html_e( 'Lo que la política bloquearía', 'wp-secure' ); ?></h3>
			<table class="widefat striped wps-table">
				<thead><tr>
					<th style="width:140px;"><?php esc_html_e( 'Directiva', 'wp-secure' ); ?></th>
					<th><?php esc_html_e( 'Origen', 'wp-secure' ); ?></th>
					<th><?php esc_html_e( 'Última página', 'wp-secure' ); ?></th>
					<th style="width:90px;"><?php esc_html_e( 'Muestras', 'wp-secure' ); ?></th>
					<th style="width:150px;"><?php esc_html_e( 'Último', 'wp-secure' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $reports as $report ) : ?>
					<tr>
						<td><code><?php echo esc_html( $report['directive'] ); ?></code></td>
						<td><code><?php echo esc_html( $report['source'] ); ?></code></td>
						<td><?php echo esc_html( $report['page'] ); ?></td>
						<td><?php echo esc_html( number_format_i18n( $report['count'] ) ); ?></td>
						<td><?php echo esc_html( wp_date( 'Y-m-d H:i', $report['last'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<p class="description"><?php esc_html_e( 'Un reporte repetido se cuenta como mucho una vez cada 10 minutos. Revisá cada origen: uno que no reconocés puede ser justamente un script inyectado.', 'wp-secure' ); ?></p>

			<h3><?php esc_html_e( 'Política sugerida', 'wp-secure' ); ?></h3>
			<pre style="white-space:pre-wrap;"><code><?php echo esc_html( str_replace( '; ', ";\n", $this->csp->suggested() ) ); ?></code></pre>

			<form method="post" style="display:inline-block;margin-right:8px;">
				<?php wp_nonce_field( 'wps_csp', 'wps_csp_nonce' ); ?>
				<input type="hidden" name="wps_csp_action" value="use_suggested" />
				<?php submit_button( __( 'Usar la política sugerida', 'wp-secure' ), 'primary', 'submit', false, array( 'data-wps-confirm' => __( '¿Reemplazar la política por la sugerida? Los reportes se borran para empezar a juntar de nuevo con la política nueva.', 'wp-secure' ) ) ); ?>
			</form>
			<form method="post" style="display:inline-block;">
				<?php wp_nonce_field( 'wps_csp', 'wps_csp_nonce' ); ?>
				<input type="hidden" name="wps_csp_action" value="clear" />
				<?php submit_button( __( 'Borrar reportes', 'wp-secure' ), 'secondary', 'submit', false ); ?>
			</form>
		<?php else : ?>
			<p><?php esc_html_e( 'Todavía no llegaron reportes. Si el modo es «Sólo reportar» y pasan unos días sin reportes, la política no bloquearía nada del sitio.', 'wp-secure' ); ?></p>
		<?php endif; ?>
		<?php
	}

	/**
	 * Usar la política sugerida o borrar los reportes.
	 */
	private function handle_csp_actions(): ?array {
		if ( ! isset( $_POST['wps_csp_action'] ) || ! current_user_can( 'manage_options' ) ) {
			return null;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_csp_nonce'] ?? '' ) ), 'wps_csp' ) ) {
			return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
		}

		$action = sanitize_key( wp_unslash( $_POST['wps_csp_action'] ) );

		if ( 'use_suggested' === $action ) {
			$this->loader->set_setting( 'csp_policy', $this->csp->suggested() );
			$this->csp->clear_reports();

			WPS_Admin_Notifier::get_instance( $this->loader )->notify_settings_change(
				get_current_user_id(),
				__( 'Política CSP reemplazada por la sugerida', 'wp-secure' )
			);

			return array( 'type' => 'success', 'text' => __( 'Se guardó la política sugerida y se borraron los reportes. Seguí en «Sólo reportar» hasta que no aparezcan reportes nuevos.', 'wp-secure' ) );
		}

		if ( 'clear' === $action ) {
			$this->csp->clear_reports();
			return array( 'type' => 'success', 'text' => __( 'Se borraron los reportes.', 'wp-secure' ) );
		}

		return null;
	}

	/**
	 * ¿Se pidió volver a comprobar? Null si el nonce no es válido.
	 */
	private function wants_fresh_run(): ?bool {
		if ( ! isset( $_POST['wps_hardening_recheck'] ) ) {
			return false;
		}

		return wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_hardening_nonce'] ?? '' ) ), 'wps_hardening' ) ? true : null;
	}
}
