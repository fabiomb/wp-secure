<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página del chequeo de endurecimiento.
 */
class WPS_Admin_Hardening {

	/** @var WPS_Hardening_Check */
	private $check;

	public function __construct( WPS_Loader $loader ) {
		$this->check = new WPS_Hardening_Check( $loader );
	}

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		$fresh = $this->wants_fresh_run();
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
		</div>
		<?php
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
