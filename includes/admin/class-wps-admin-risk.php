<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página del motor de riesgo: reporte guiado del modo sombra.
 */
class WPS_Admin_Risk {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Renderizar la página.
	 */
	public function render(): void {
		$days   = isset( $_GET['days'] ) ? absint( $_GET['days'] ) : 7; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$days   = in_array( $days, array( 1, 7, 30 ), true ) ? $days : 7;
		$report = ( new WPS_Risk_Report( $this->loader ) )->build( $days );
		$modes  = array(
			'off'     => __( 'Desactivado', 'wp-secure' ),
			'shadow'  => __( 'Modo sombra (mide, no bloquea)', 'wp-secure' ),
			'enforce' => __( 'Activo (bloquea)', 'wp-secure' ),
		);
		$settings  = admin_url( 'admin.php?page=wp-secure-settings' );
		$threshold = $report['thresholds']['temp_block'];
		$hard      = $report['thresholds']['hard_block'];
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Motor de riesgo', 'wp-secure' ); ?></h1>

			<p class="description">
				<?php esc_html_e( 'El motor suma puntos por cada señal de una petición (User-Agent de herramienta, rutas sospechosas, 404 repetidos, logins fallidos, país, detecciones) y bloquea desde un umbral. En modo sombra sólo registra: este reporte muestra a quién habría bloqueado, con qué factores y qué pasaría con otro umbral, para calibrarlo antes de activarlo.', 'wp-secure' ); ?>
			</p>

			<table class="widefat" style="max-width:720px;margin:16px 0;">
				<tbody>
					<tr><th><?php esc_html_e( 'Modo', 'wp-secure' ); ?></th><td>
						<strong><?php echo esc_html( $modes[ $report['mode'] ] ?? $report['mode'] ); ?></strong>
						— <a href="<?php echo esc_url( $settings ); ?>"><?php esc_html_e( 'cambiar en Configuración', 'wp-secure' ); ?></a>
					</td></tr>
					<tr><th><?php esc_html_e( 'Umbral de bloqueo', 'wp-secure' ); ?></th><td>
						<?php
						/* translators: 1: temporary block threshold, 2: permanent block threshold */
						echo esc_html( PHP_INT_MAX === $hard ? sprintf( __( 'temporal desde %1$d; nunca permanente', 'wp-secure' ), $threshold ) : sprintf( __( 'temporal desde %1$d; permanente desde %2$d', 'wp-secure' ), $threshold, $hard ) );
						?>
					</td></tr>
					<tr><th><?php esc_html_e( 'Período', 'wp-secure' ); ?></th><td>
						<?php foreach ( array( 1 => __( '24 horas', 'wp-secure' ), 7 => __( '7 días', 'wp-secure' ), 30 => __( '30 días', 'wp-secure' ) ) as $value => $label ) : ?>
							<?php if ( $value === $days ) : ?>
								<strong><?php echo esc_html( $label ); ?></strong>
							<?php else : ?>
								<a href="<?php echo esc_url( add_query_arg( array( 'page' => 'wp-secure-risk', 'days' => $value ), admin_url( 'admin.php' ) ) ); ?>"><?php echo esc_html( $label ); ?></a>
							<?php endif; ?>
							&nbsp;
						<?php endforeach; ?>
					</td></tr>
					<tr><th><?php esc_html_e( 'Eventos registrados', 'wp-secure' ); ?></th><td>
						<?php
						echo esc_html( sprintf(
							/* translators: 1: low, 2: medium, 3: high */
							__( 'riesgo bajo: %1$s · medio: %2$s · alto: %3$s', 'wp-secure' ),
							number_format_i18n( $report['counts'][ WPS_Event_Types::RISK_LOW ] ),
							number_format_i18n( $report['counts'][ WPS_Event_Types::RISK_MEDIUM ] ),
							number_format_i18n( $report['counts'][ WPS_Event_Types::RISK_HIGH ] )
						) );
						?>
						<?php if ( $report['truncated'] ) : ?>
							<br><em><?php echo esc_html( sprintf( /* translators: %d: events */ __( 'Se analizan los %d eventos más recientes.', 'wp-secure' ), WPS_Risk_Report::MAX_EVENTS ) ); ?></em>
						<?php endif; ?>
					</td></tr>
				</tbody>
			</table>

			<?php $this->render_guidance( $report ); ?>

			<?php if ( $report['clients'] ) : ?>
				<h2><?php esc_html_e( 'Qué pasaría con cada umbral', 'wp-secure' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Clientes cuyo peor puntaje alcanza el umbral. «Ya bloqueados» son los que otra regla (detectores, rutas trampa, bloqueos manuales) bloqueó en el período: atacantes confirmados. «Nuevos» son los que sólo bloquearía el motor: revisalos antes de activarlo.', 'wp-secure' ); ?></p>
				<table class="widefat striped wps-table" style="max-width:720px;">
					<thead><tr>
						<th><?php esc_html_e( 'Umbral', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Clientes bloqueados', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Ya bloqueados por otra regla', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Nuevos', 'wp-secure' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $report['simulation'] as $row ) : ?>
						<tr<?php echo $row['current'] ? ' style="font-weight:600;"' : ''; ?>>
							<td>
								<?php echo esc_html( $row['threshold'] ); ?>
								<?php if ( $row['current'] ) : ?><span class="wps-badge wps-badge-info"><?php esc_html_e( 'actual', 'wp-secure' ); ?></span><?php endif; ?>
								<?php if ( $row['threshold'] === $report['suggested'] ) : ?><span class="wps-badge wps-badge-ok"><?php esc_html_e( 'sugerido', 'wp-secure' ); ?></span><?php endif; ?>
							</td>
							<td><?php echo esc_html( number_format_i18n( $row['clients'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $row['confirmed'] ) ); ?></td>
							<td><?php echo $row['new'] ? '<strong>' . esc_html( number_format_i18n( $row['new'] ) ) . '</strong>' : '0'; ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<?php if ( $report['factors'] ) : ?>
				<h2><?php esc_html_e( 'Factores que más pesan (umbral actual)', 'wp-secure' ); ?></h2>
				<p class="description"><?php esc_html_e( 'En cuántos clientes que se bloquearían aparece cada factor. Si un factor aparece sobre todo en clientes nuevos que son tráfico legítimo (por ejemplo, un monitor de disponibilidad con curl), es el que está empujando falsos positivos.', 'wp-secure' ); ?></p>
				<table class="widefat striped wps-table" style="max-width:720px;">
					<thead><tr>
						<th><?php esc_html_e( 'Factor', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Puntos', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Clientes', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'De ellos, nuevos', 'wp-secure' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $report['factors'] as $factor ) : ?>
						<tr>
							<td><?php echo esc_html( WPS_Risk_Report::factor_label( $factor['factor'] ) ); ?></td>
							<td><?php echo esc_html( $this->weight( $factor['factor'], $report['weights'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $factor['clients'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $factor['new_clients'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<?php if ( $report['new_clients'] ) : ?>
				<h2><?php esc_html_e( 'Clientes que sólo bloquearía el motor', 'wp-secure' ); ?></h2>
				<table class="widefat striped wps-table">
					<thead><tr>
						<th><?php esc_html_e( 'IP', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Peor puntaje', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Eventos', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Factores', 'wp-secure' ); ?></th>
						<th><?php esc_html_e( 'Último', 'wp-secure' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $report['new_clients'] as $client ) : ?>
						<tr>
							<td><code><?php echo esc_html( $client['ip'] ); ?></code></td>
							<td><?php echo esc_html( $client['max_score'] ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $client['events'] ) ); ?></td>
							<td><?php echo esc_html( implode( ', ', array_map( array( 'WPS_Risk_Report', 'factor_label' ), array_keys( $client['factors'] ) ) ) ); ?></td>
							<td><?php echo $client['last'] ? esc_html( wp_date( 'Y-m-d H:i', strtotime( $client['last'] . ' UTC' ) ) ) : '—'; ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p class="description"><?php esc_html_e( 'Si alguno es legítimo (un servicio propio, un monitor, una integración), agregalo a la whitelist o subí el umbral.', 'wp-secure' ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Recomendación según el modo y los datos.
	 */
	private function render_guidance( array $report ): void {
		$type = 'info';

		if ( 'off' === $report['mode'] && ! $report['clients'] ) {
			$text = __( 'Paso 1: activá el modo sombra en Configuración → Firewall Avanzado. No bloquea a nadie; durante unos días registra qué habría hecho el motor con tu tráfico real.', 'wp-secure' );
		} elseif ( ! $report['clients'] ) {
			$text = __( 'Todavía no hay peticiones con puntaje suficiente para bloquear en este período. Esperá unos días de tráfico.', 'wp-secure' );
		} elseif ( ! $report['would_block'] ) {
			$text = sprintf(
				/* translators: %d: current threshold */
				__( 'Con el umbral actual (%d) el motor no habría bloqueado a nadie en este período: activarlo todavía no cambiaría nada. La tabla de abajo muestra a quién alcanzaría un umbral más bajo.', 'wp-secure' ),
				$report['thresholds']['temp_block']
			);
		} elseif ( $this->days_of_data( $report ) < WPS_Risk_Report::MIN_DAYS && 'shadow' === $report['mode'] ) {
			/* translators: %d: minimum days */
			$text = sprintf( __( 'Hay pocos datos todavía. Conviene juntar al menos %d días de tráfico antes de decidir un umbral.', 'wp-secure' ), WPS_Risk_Report::MIN_DAYS );
		} elseif ( null !== $report['suggested'] ) {
			$type = 'success';
			$text = sprintf(
				/* translators: %d: suggested threshold */
				__( 'Con un umbral de %d, el motor sólo habría bloqueado clientes que otras reglas ya bloquearon. Fijá «Umbral de bloqueo por riesgo» en ese valor y, si estás en modo sombra, pasá a Activo.', 'wp-secure' ),
				$report['suggested']
			);
		} else {
			$type = 'warning';
			$text = __( 'Con cualquiera de los umbrales el motor bloquearía clientes que ninguna otra regla bloqueó. Revisá la lista de abajo: si son atacantes, podés activarlo; si hay tráfico legítimo, agregalo a la whitelist o seguí en modo sombra.', 'wp-secure' );
		}
		?>
		<div class="notice notice-<?php echo esc_attr( $type ); ?> inline" style="max-width:720px;"><p><?php echo esc_html( $text ); ?></p></div>
		<?php
	}

	private function days_of_data( array $report ): float {
		if ( empty( $report['first_event'] ) ) {
			return 0.0;
		}
		return ( time() - (int) strtotime( $report['first_event'] . ' UTC' ) ) / DAY_IN_SECONDS;
	}

	/**
	 * Puntos de un factor según la tabla del motor.
	 */
	private function weight( string $factor, array $weights ): string {
		$map = array( 'login_fail' => 'login_fail', '404' => 'multiple_404', 'risky_country' => 'risky_country' );
		$key = $map[ $factor ] ?? $factor;

		if ( ! isset( $weights[ $key ] ) ) {
			return '—';
		}
		return in_array( $factor, array( 'login_fail', '404' ), true )
			/* translators: %d: points per occurrence */
			? sprintf( __( '%d c/u', 'wp-secure' ), $weights[ $key ] )
			: (string) $weights[ $key ];
	}
}
