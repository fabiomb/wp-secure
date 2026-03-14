<?php
defined( 'ABSPATH' ) || exit;

/**
 * Wizard de configuración inicial.
 *
 * Se muestra automáticamente tras la primera activación del plugin.
 * Guía al administrador por los pasos esenciales: API key, modo de
 * datos, protección de login, XML-RPC, rate limiting y whitelist.
 */
class WPS_Admin_Wizard {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Renderizar el wizard.
	 */
	public function render(): void {
		$current_step = isset( $_GET['step'] ) ? absint( $_GET['step'] ) : 1;
		$total_steps  = 4;

		// Procesar POST si corresponde.
		if ( 'POST' === $_SERVER['REQUEST_METHOD'] && isset( $_POST['wps_wizard_nonce'] ) ) {
			if ( wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_wizard_nonce'] ) ), 'wps_wizard' )
				&& current_user_can( 'manage_options' ) ) {
				$this->save_step( $current_step );
				$next_step = $current_step + 1;
				if ( $next_step > $total_steps ) {
					// Wizard completado.
					$this->loader->set_setting( 'wizard_completed', true );
					wp_safe_redirect( admin_url( 'admin.php?page=wp-secure&wizard=done' ) );
					exit;
				}
				wp_safe_redirect( admin_url( 'admin.php?page=wp-secure-wizard&step=' . $next_step ) );
				exit;
			}
		}

		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Configuración Inicial', 'wp-secure' ); ?></h1>

			<!-- Progress bar -->
			<div class="wps-wizard-progress">
				<?php for ( $i = 1; $i <= $total_steps; $i++ ) :
					$class = 'wps-wizard-step-indicator';
					if ( $i < $current_step ) {
						$class .= ' completed';
					} elseif ( $i === $current_step ) {
						$class .= ' active';
					}
				?>
					<div class="<?php echo esc_attr( $class ); ?>">
						<span class="wps-wizard-step-number"><?php echo esc_html( $i ); ?></span>
						<span class="wps-wizard-step-label"><?php echo esc_html( $this->step_label( $i ) ); ?></span>
					</div>
				<?php endfor; ?>
			</div>

			<form method="post" class="wps-wizard-form">
				<?php wp_nonce_field( 'wps_wizard', 'wps_wizard_nonce' ); ?>

				<div class="wps-section">
					<?php
					switch ( $current_step ) {
						case 1:
							$this->render_step_api();
							break;
						case 2:
							$this->render_step_protection();
							break;
						case 3:
							$this->render_step_rate_limiting();
							break;
						case 4:
							$this->render_step_whitelist();
							break;
					}
					?>

					<div class="wps-wizard-actions">
						<?php if ( $current_step > 1 ) : ?>
							<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-wizard&step=' . ( $current_step - 1 ) ) ); ?>" class="button">
								&larr; <?php esc_html_e( 'Anterior', 'wp-secure' ); ?>
							</a>
						<?php endif; ?>

						<?php if ( $current_step < $total_steps ) : ?>
							<button type="submit" class="button button-primary">
								<?php esc_html_e( 'Siguiente', 'wp-secure' ); ?> &rarr;
							</button>
						<?php else : ?>
							<button type="submit" class="button button-primary">
								<?php esc_html_e( 'Finalizar', 'wp-secure' ); ?> ✓
							</button>
						<?php endif; ?>

						<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure' ) ); ?>" class="button button-link" style="margin-left:auto;">
							<?php esc_html_e( 'Saltar wizard', 'wp-secure' ); ?>
						</a>
					</div>
				</div>
			</form>
		</div>
		<?php
	}

	/**
	 * Etiqueta de cada paso.
	 */
	private function step_label( int $step ): string {
		$labels = array(
			1 => __( 'API y Datos', 'wp-secure' ),
			2 => __( 'Protección', 'wp-secure' ),
			3 => __( 'Rate Limiting', 'wp-secure' ),
			4 => __( 'Whitelist', 'wp-secure' ),
		);
		return $labels[ $step ] ?? '';
	}

	/**
	 * Paso 1: Configuración de API y modo de datos.
	 */
	private function render_step_api(): void {
		$api_key = $this->loader->get_setting( 'ipinfo_api_key', '' );
		$mode    = $this->loader->get_setting( 'ipinfo_mode', 'api' );
		?>
		<h2><?php esc_html_e( 'Paso 1: API y Datos de Geolocalización', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'WP Seguro utiliza ipinfo.io para resolver la geolocalización de IPs. Puedes usar la API en línea o descargar la base de datos local para mayor velocidad.', 'wp-secure' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><label for="wps_ipinfo_api_key"><?php esc_html_e( 'API Key ipinfo.io', 'wp-secure' ); ?></label></th>
				<td>
					<input type="text" id="wps_ipinfo_api_key" name="ipinfo_api_key" value="<?php echo esc_attr( $api_key ); ?>" class="regular-text" />
					<p class="description"><?php esc_html_e( 'Opcional. Obtén una API key gratuita en ipinfo.io/signup', 'wp-secure' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Modo de datos', 'wp-secure' ); ?></th>
				<td>
					<label><input type="radio" name="ipinfo_mode" value="api" <?php checked( $mode, 'api' ); ?> /> <?php esc_html_e( 'API en línea (requiere API key)', 'wp-secure' ); ?></label><br>
					<label><input type="radio" name="ipinfo_mode" value="local" <?php checked( $mode, 'local' ); ?> /> <?php esc_html_e( 'Base de datos local (MMDB)', 'wp-secure' ); ?></label>
					<p class="description"><?php esc_html_e( 'El modo local es más rápido pero requiere descargar la base de datos después.', 'wp-secure' ); ?></p>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Paso 2: Protección de login y XML-RPC.
	 */
	private function render_step_protection(): void {
		$login_max     = $this->loader->get_setting( 'login_max_attempts', 5 );
		$login_minutes = $this->loader->get_setting( 'login_block_minutes', 15 );
		$xmlrpc_block  = $this->loader->get_setting( 'xmlrpc_block_all', true );
		$block_unknown = $this->loader->get_setting( 'login_block_unknown_user', true );
		?>
		<h2><?php esc_html_e( 'Paso 2: Protección de Login y XML-RPC', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Configura la protección contra ataques de fuerza bruta y acceso a XML-RPC.', 'wp-secure' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><label for="wps_login_max_attempts"><?php esc_html_e( 'Intentos de login máximos', 'wp-secure' ); ?></label></th>
				<td>
					<input type="number" id="wps_login_max_attempts" name="login_max_attempts" value="<?php echo esc_attr( $login_max ); ?>" min="1" max="20" class="small-text" />
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wps_login_block_minutes"><?php esc_html_e( 'Minutos de bloqueo', 'wp-secure' ); ?></label></th>
				<td>
					<input type="number" id="wps_login_block_minutes" name="login_block_minutes" value="<?php echo esc_attr( $login_minutes ); ?>" min="1" max="1440" class="small-text" />
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Bloquear usuario inexistente', 'wp-secure' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="login_block_unknown_user" value="1" <?php checked( $block_unknown ); ?> />
						<?php esc_html_e( 'Bloquear IP inmediatamente si el usuario no existe', 'wp-secure' ); ?>
					</label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Bloquear XML-RPC', 'wp-secure' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="xmlrpc_block_all" value="1" <?php checked( $xmlrpc_block ); ?> />
						<?php esc_html_e( 'Bloquear completamente el acceso a xmlrpc.php (recomendado)', 'wp-secure' ); ?>
					</label>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Paso 3: Rate limiting.
	 */
	private function render_step_rate_limiting(): void {
		$pages = $this->loader->get_setting( 'rate_pages_per_min', 60 );
		$total = $this->loader->get_setting( 'rate_total_per_min', 240 );
		$f404  = $this->loader->get_setting( 'rate_404_per_min', 10 );
		$block = $this->loader->get_setting( 'rate_block_minutes', 15 );
		?>
		<h2><?php esc_html_e( 'Paso 3: Rate Limiting', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Limita la cantidad de peticiones por IP para prevenir abuso y ataques automatizados.', 'wp-secure' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><label for="wps_rate_pages"><?php esc_html_e( 'Peticiones/minuto (páginas)', 'wp-secure' ); ?></label></th>
				<td><input type="number" id="wps_rate_pages" name="rate_pages_per_min" value="<?php echo esc_attr( $pages ); ?>" min="10" max="500" class="small-text" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wps_rate_total"><?php esc_html_e( 'Peticiones/minuto (total)', 'wp-secure' ); ?></label></th>
				<td><input type="number" id="wps_rate_total" name="rate_total_per_min" value="<?php echo esc_attr( $total ); ?>" min="30" max="2000" class="small-text" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wps_rate_404"><?php esc_html_e( 'Errores 404/minuto', 'wp-secure' ); ?></label></th>
				<td><input type="number" id="wps_rate_404" name="rate_404_per_min" value="<?php echo esc_attr( $f404 ); ?>" min="3" max="100" class="small-text" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wps_rate_block"><?php esc_html_e( 'Duración del bloqueo (minutos)', 'wp-secure' ); ?></label></th>
				<td><input type="number" id="wps_rate_block" name="rate_block_minutes" value="<?php echo esc_attr( $block ); ?>" min="1" max="1440" class="small-text" /></td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Paso 4: Whitelist de la IP actual.
	 */
	private function render_step_whitelist(): void {
		$current_ip  = WPS_Request::get_instance()->ip();
		$is_wl       = WPS_Whitelist::get_instance()->is_whitelisted( $current_ip );
		?>
		<h2><?php esc_html_e( 'Paso 4: Whitelist', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Agrega tu IP actual a la whitelist para garantizar que nunca seas bloqueado por el firewall.', 'wp-secure' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><?php esc_html_e( 'Tu IP actual', 'wp-secure' ); ?></th>
				<td>
					<code style="font-size:16px;padding:6px 12px;"><?php echo esc_html( $current_ip ); ?></code>
					<?php if ( $is_wl ) : ?>
						<span class="wps-badge wps-badge-ok" style="margin-left:8px;"><?php esc_html_e( 'Ya en whitelist', 'wp-secure' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Agregar a whitelist', 'wp-secure' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="whitelist_current_ip" value="1" <?php checked( ! $is_wl ); ?> <?php disabled( $is_wl ); ?> />
						<?php esc_html_e( 'Agregar esta IP a la whitelist global', 'wp-secure' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Altamente recomendado para evitar bloquearte a ti mismo.', 'wp-secure' ); ?></p>
				</td>
			</tr>
		</table>

		<div class="wps-notice wps-notice-info" style="margin-top:16px;">
			<p>
				<strong><?php esc_html_e( 'Resumen:', 'wp-secure' ); ?></strong>
				<?php esc_html_e( 'Al finalizar, tu sitio estará protegido contra ataques de fuerza bruta, inyecciones SQL/XSS, scanners y tráfico abusivo. Puedes ajustar toda la configuración después desde el menú de Configuración.', 'wp-secure' ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * Guardar los datos del paso actual.
	 */
	private function save_step( int $step ): void {
		switch ( $step ) {
			case 1:
				$api_key = sanitize_text_field( wp_unslash( $_POST['ipinfo_api_key'] ?? '' ) );
				$mode    = sanitize_text_field( wp_unslash( $_POST['ipinfo_mode'] ?? 'api' ) );
				if ( ! in_array( $mode, array( 'api', 'local' ), true ) ) {
					$mode = 'api';
				}
				$this->loader->set_setting( 'ipinfo_api_key', $api_key );
				$this->loader->set_setting( 'ipinfo_mode', $mode );
				break;

			case 2:
				$this->loader->set_setting( 'login_max_attempts', absint( $_POST['login_max_attempts'] ?? 5 ) );
				$this->loader->set_setting( 'login_block_minutes', absint( $_POST['login_block_minutes'] ?? 15 ) );
				$this->loader->set_setting( 'login_block_unknown_user', isset( $_POST['login_block_unknown_user'] ) );
				$this->loader->set_setting( 'xmlrpc_block_all', isset( $_POST['xmlrpc_block_all'] ) );
				break;

			case 3:
				$this->loader->set_setting( 'rate_pages_per_min', absint( $_POST['rate_pages_per_min'] ?? 60 ) );
				$this->loader->set_setting( 'rate_total_per_min', absint( $_POST['rate_total_per_min'] ?? 240 ) );
				$this->loader->set_setting( 'rate_404_per_min', absint( $_POST['rate_404_per_min'] ?? 10 ) );
				$this->loader->set_setting( 'rate_block_minutes', absint( $_POST['rate_block_minutes'] ?? 15 ) );
				break;

			case 4:
				if ( isset( $_POST['whitelist_current_ip'] ) ) {
					$current_ip = WPS_Request::get_instance()->ip();
					$whitelist  = WPS_Whitelist::get_instance();
					if ( ! $whitelist->is_whitelisted( $current_ip ) ) {
						$whitelist->add_ip( $current_ip, __( 'IP del administrador (wizard)', 'wp-secure' ), 'global' );
					}
				}
				break;
		}
	}
}
