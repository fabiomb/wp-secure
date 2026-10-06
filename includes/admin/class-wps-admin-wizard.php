<?php
defined( 'ABSPATH' ) || exit;

/**
 * Wizard de configuración inicial.
 *
 * Se muestra automáticamente tras la primera activación del plugin.
 * Guía al administrador por los pasos esenciales:
 * 1. Básico: CDN/proxy y whitelist de la IP actual.
 * 2. Protección de login y XML-RPC.
 * 3. Rate limiting.
 * 4. Geolocalización (opcional): ninguna, ipinfo.io o MaxMind GeoLite2.
 *
 * Cada paso se guarda en admin_init (handle_submit) y redirige al siguiente;
 * render() sólo dibuja. Al finalizar, si el proveedor elegido usa base local
 * y todavía no está descargada, se lleva a la página de Geolocalización para
 * descargarla (nunca se descarga dentro del POST del wizard). Si faltan las
 * credenciales del proveedor se guarda igual y se avisa en la página
 * siguiente.
 */
class WPS_Admin_Wizard {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/** Cantidad de pasos del wizard. */
	const TOTAL_STEPS = 4;

	/**
	 * Guardar el paso enviado y avanzar al siguiente.
	 *
	 * Corre en admin_init, antes de que WordPress imprima el encabezado del
	 * admin: dentro del callback de la página la redirección ya no puede
	 * enviar cabeceras y el paso siguiente queda en blanco.
	 */
	public function handle_submit(): void {
		if ( 'wp-secure-wizard' !== ( $_GET['page'] ?? '' )
			|| 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' )
			|| ! isset( $_POST['wps_wizard_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_wizard_nonce'] ) ), 'wps_wizard' )
			|| ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$current_step = $this->current_step();
		$this->save_step( $current_step );

		$next_step = $current_step + 1;
		if ( $next_step > self::TOTAL_STEPS ) {
			$this->loader->set_setting( 'wizard_completed', true );
			wp_safe_redirect( $this->finish_url() );
			exit;
		}

		wp_safe_redirect( admin_url( 'admin.php?page=wp-secure-wizard&step=' . $next_step ) );
		exit;
	}

	/**
	 * Paso pedido en la URL, acotado a los pasos existentes.
	 */
	public function current_step(): int {
		$step = isset( $_GET['step'] ) ? absint( $_GET['step'] ) : 1;
		return max( 1, min( self::TOTAL_STEPS, $step ) );
	}

	/**
	 * Destino al finalizar, según el proveedor de geolocalización elegido.
	 *
	 * - Base local sin descargar: página de Geolocalización, para descargarla.
	 * - Proveedor sin credenciales: aviso de configuración incompleta.
	 * - Si no: dashboard.
	 */
	public function finish_url(): string {
		$manager  = WPS_Ipdb_Manager::get_instance();
		$provider = $manager->get_provider();

		if ( WPS_Ipdb_Manager::PROVIDER_NONE === $provider ) {
			return admin_url( 'admin.php?page=wp-secure&wizard=done' );
		}

		$has_credentials = $manager->has_credentials( $provider );

		if ( 'local' === $manager->get_mode( $provider ) && ! $manager->is_local_complete( $provider ) ) {
			return admin_url( 'admin.php?page=wp-secure-ipdb&wizard=done&wps_geo=' . ( $has_credentials ? 'download' : 'incomplete' ) );
		}

		if ( ! $has_credentials ) {
			return admin_url( 'admin.php?page=wp-secure&wizard=done&wps_geo=incomplete' );
		}

		return admin_url( 'admin.php?page=wp-secure&wizard=done' );
	}

	/**
	 * IP del administrador según el modo de proxy guardado ahora.
	 *
	 * WPS_Request resolvió la IP al construirse, con el modo de proxy que
	 * había al comenzar la petición. En el paso 1 ese modo puede acabar de
	 * cambiar, así que se vuelve a resolver con WPS_Proxy_Config, que lee el
	 * ajuste del loader en cada llamada.
	 */
	public function resolve_current_ip(): string {
		$proxy = WPS_Proxy_Config::get_instance();
		$proxy->set_loader( $this->loader );

		$ip = $proxy->get_real_ip();
		if ( WPS_Ip_Utils::is_valid_ip( $ip ) ) {
			return $ip;
		}

		$remote_addr = WPS_Ip_Utils::strip_port( $_SERVER['REMOTE_ADDR'] ?? '' );
		return WPS_Ip_Utils::is_valid_ip( $remote_addr ) ? $remote_addr : '';
	}

	/**
	 * Opciones de `proxy_mode`, las mismas de Configuración → CDN / Proxy.
	 *
	 * @return array<string, string>
	 */
	private function proxy_modes(): array {
		$fields = ( new WPS_Admin_Settings( $this->loader ) )->fields();
		return $fields['proxy_mode']['options'];
	}

	/**
	 * Renderizar el wizard.
	 */
	public function render(): void {
		$current_step = $this->current_step();
		$total_steps  = self::TOTAL_STEPS;

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
							$this->render_step_basic();
							break;
						case 2:
							$this->render_step_protection();
							break;
						case 3:
							$this->render_step_rate_limiting();
							break;
						case 4:
							$this->render_step_geo();
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
			1 => __( 'Básico', 'wp-secure' ),
			2 => __( 'Protección', 'wp-secure' ),
			3 => __( 'Rate Limiting', 'wp-secure' ),
			4 => __( 'Geolocalización (opcional)', 'wp-secure' ),
		);
		return $labels[ $step ] ?? '';
	}

	/**
	 * Paso 1: CDN/proxy y whitelist de la IP actual.
	 */
	private function render_step_basic(): void {
		$proxy_mode = $this->loader->get_setting( 'proxy_mode', 'auto' );
		$current_ip = $this->resolve_current_ip();
		$is_wl      = '' !== $current_ip && WPS_Whitelist::get_instance()->is_whitelisted( $current_ip );
		?>
		<h2><?php esc_html_e( 'Paso 1: Básico', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Indicá si el sitio está detrás de un CDN o proxy, para que el firewall vea la IP real de cada visitante, y agregá tu IP a la whitelist para no bloquearte.', 'wp-secure' ); ?>
		</p>

		<table class="form-table">
			<tr>
				<th scope="row"><label for="wps_proxy_mode"><?php esc_html_e( 'CDN / Proxy', 'wp-secure' ); ?></label></th>
				<td>
					<select id="wps_proxy_mode" name="proxy_mode">
						<?php foreach ( $this->proxy_modes() as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $proxy_mode, $value ); ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</select>
					<p class="description"><?php esc_html_e( 'Auto-detectar funciona para Cloudflare y Sucuri. Con "Personalizado", las IPs de proxy confiables y el header de IP real se configuran en Configuración → CDN / Proxy.', 'wp-secure' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Tu IP actual', 'wp-secure' ); ?></th>
				<td>
					<?php if ( '' !== $current_ip ) : ?>
						<code style="font-size:16px;padding:6px 12px;"><?php echo esc_html( $current_ip ); ?></code>
						<?php if ( $is_wl ) : ?>
							<span class="wps-badge wps-badge-ok" style="margin-left:8px;"><?php esc_html_e( 'Ya en whitelist', 'wp-secure' ); ?></span>
						<?php endif; ?>
					<?php else : ?>
						<?php esc_html_e( 'No se pudo detectar.', 'wp-secure' ); ?>
					<?php endif; ?>
					<p class="description"><?php esc_html_e( 'Detectada con el modo de proxy guardado. Si cambiás el modo, al pasar al paso siguiente se vuelve a detectar con el nuevo.', 'wp-secure' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Agregar a whitelist', 'wp-secure' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="whitelist_current_ip" value="1" <?php checked( ! $is_wl ); ?> <?php disabled( $is_wl ); ?> />
						<?php esc_html_e( 'Agregar mi IP a la whitelist global', 'wp-secure' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Altamente recomendado para evitar bloquearte a ti mismo.', 'wp-secure' ); ?></p>
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
	 * Paso 4: Geolocalización (opcional) y resumen.
	 *
	 * Las filas de cada proveedor llevan `data-wps-geo`; un script mínimo
	 * oculta las del proveedor no elegido. Sin JavaScript se ven todas.
	 */
	private function render_step_geo(): void {
		$manager     = WPS_Ipdb_Manager::get_instance();
		$provider    = $manager->get_provider();
		$ipinfo_key  = $this->loader->get_setting( 'ipinfo_api_key', '' );
		$ipinfo_mode = $manager->get_mode( WPS_Ipdb_Manager::PROVIDER_IPINFO );
		$mm_account  = $this->loader->get_setting( 'maxmind_account_id', '' );
		$mm_license  = $this->loader->get_setting( 'maxmind_license_key', '' );
		$mm_mode     = $manager->get_mode( WPS_Ipdb_Manager::PROVIDER_MAXMIND );
		?>
		<h2><?php esc_html_e( 'Paso 4: Geolocalización (opcional)', 'wp-secure' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'La geolocalización resuelve el país y la red (ASN) de cada IP. Podés dejarla desactivada y configurarla más adelante desde Configuración → Geolocalización.', 'wp-secure' ); ?>
		</p>

		<?php WPS_Admin_Ipdb::render_optional_explanation(); ?>

		<table class="form-table" id="wps-wizard-geo">
			<tr>
				<th scope="row"><?php esc_html_e( 'Proveedor', 'wp-secure' ); ?></th>
				<td>
					<?php foreach ( WPS_Ipdb_Manager::providers() as $value => $label ) : ?>
						<label style="display:block;margin-bottom:4px;">
							<input type="radio" name="geo_provider" value="<?php echo esc_attr( $value ); ?>" <?php checked( $provider, $value ); ?> />
							<?php echo esc_html( $label ); ?>
						</label>
					<?php endforeach; ?>
				</td>
			</tr>

			<!-- ipinfo.io -->
			<tr data-wps-geo="ipinfo">
				<th scope="row"><label for="wps_ipinfo_api_key"><?php esc_html_e( 'API Key ipinfo.io', 'wp-secure' ); ?></label></th>
				<td>
					<input type="password" id="wps_ipinfo_api_key" name="ipinfo_api_key" value="<?php echo esc_attr( $ipinfo_key ); ?>" class="regular-text" autocomplete="off" />
					<p class="description"><?php esc_html_e( 'Obtené una API key gratuita en ipinfo.io/signup.', 'wp-secure' ); ?></p>
				</td>
			</tr>
			<tr data-wps-geo="ipinfo">
				<th scope="row"><?php esc_html_e( 'Modo ipinfo.io', 'wp-secure' ); ?></th>
				<td>
					<label><input type="radio" name="ipinfo_mode" value="api" <?php checked( $ipinfo_mode, 'api' ); ?> /> <?php esc_html_e( 'API en línea', 'wp-secure' ); ?></label><br>
					<label><input type="radio" name="ipinfo_mode" value="local" <?php checked( $ipinfo_mode, 'local' ); ?> /> <?php esc_html_e( 'Base de datos local (MMDB)', 'wp-secure' ); ?></label>
					<p class="description"><?php esc_html_e( 'El modo local es más rápido; la base se descarga después de finalizar.', 'wp-secure' ); ?></p>
				</td>
			</tr>

			<!-- MaxMind GeoLite2 -->
			<tr data-wps-geo="maxmind">
				<th scope="row"><label for="wps_maxmind_account_id"><?php esc_html_e( 'Account ID MaxMind', 'wp-secure' ); ?></label></th>
				<td>
					<input type="text" id="wps_maxmind_account_id" name="maxmind_account_id" value="<?php echo esc_attr( $mm_account ); ?>" class="regular-text" autocomplete="off" />
					<p class="description"><?php esc_html_e( 'La cuenta GeoLite2 es gratuita: maxmind.com/en/geolite2/signup.', 'wp-secure' ); ?></p>
				</td>
			</tr>
			<tr data-wps-geo="maxmind">
				<th scope="row"><label for="wps_maxmind_license_key"><?php esc_html_e( 'License Key MaxMind', 'wp-secure' ); ?></label></th>
				<td>
					<input type="password" id="wps_maxmind_license_key" name="maxmind_license_key" value="<?php echo esc_attr( $mm_license ); ?>" class="regular-text" autocomplete="off" />
					<p class="description"><?php esc_html_e( 'Se genera en tu cuenta de MaxMind → Manage License Keys.', 'wp-secure' ); ?></p>
				</td>
			</tr>
			<tr data-wps-geo="maxmind">
				<th scope="row"><?php esc_html_e( 'Modo MaxMind', 'wp-secure' ); ?></th>
				<td>
					<label><input type="radio" name="maxmind_mode" value="local" <?php checked( $mm_mode, 'local' ); ?> /> <?php esc_html_e( 'Bases locales GeoLite2 Country + ASN (recomendado)', 'wp-secure' ); ?></label><br>
					<label><input type="radio" name="maxmind_mode" value="api" <?php checked( $mm_mode, 'api' ); ?> /> <?php esc_html_e( 'Servicio web GeoLite (1000 consultas por día)', 'wp-secure' ); ?></label>
					<p class="description"><?php esc_html_e( 'Las bases locales se descargan después de finalizar y se actualizan solas cada semana.', 'wp-secure' ); ?></p>
				</td>
			</tr>
		</table>

		<script>
		( function () {
			var table = document.getElementById( 'wps-wizard-geo' );
			if ( ! table ) {
				return;
			}
			function sync() {
				var checked = table.querySelector( 'input[name="geo_provider"]:checked' );
				var current = checked ? checked.value : 'none';
				table.querySelectorAll( 'tr[data-wps-geo]' ).forEach( function ( row ) {
					row.style.display = row.getAttribute( 'data-wps-geo' ) === current ? '' : 'none';
				} );
			}
			table.querySelectorAll( 'input[name="geo_provider"]' ).forEach( function ( input ) {
				input.addEventListener( 'change', sync );
			} );
			sync();
		} )();
		</script>

		<?php
		$this->render_summary();
	}

	/**
	 * Resumen de lo configurado en los pasos anteriores.
	 */
	private function render_summary(): void {
		$proxy_modes = $this->proxy_modes();
		$proxy_mode  = $this->loader->get_setting( 'proxy_mode', 'auto' );
		?>
		<div class="wps-notice wps-notice-info" style="margin-top:16px;">
			<p><strong><?php esc_html_e( 'Resumen:', 'wp-secure' ); ?></strong></p>
			<ul style="list-style:disc;margin-left:20px;">
				<li>
					<?php
					printf(
						/* translators: %s: proxy mode */
						esc_html__( 'CDN / Proxy: %s', 'wp-secure' ),
						esc_html( $proxy_modes[ $proxy_mode ] ?? $proxy_mode )
					);
					?>
				</li>
				<li>
					<?php
					printf(
						/* translators: 1: attempts, 2: minutes */
						esc_html__( 'Login: bloqueo tras %1$d intentos, durante %2$d minutos.', 'wp-secure' ),
						(int) $this->loader->get_setting( 'login_max_attempts', 5 ),
						(int) $this->loader->get_setting( 'login_block_minutes', 15 )
					);
					?>
				</li>
				<li>
					<?php
					printf(
						/* translators: %d: requests per minute */
						esc_html__( 'Rate limiting: %d páginas por minuto por IP.', 'wp-secure' ),
						(int) $this->loader->get_setting( 'rate_pages_per_min', 60 )
					);
					?>
				</li>
			</ul>
			<p><?php esc_html_e( 'Al finalizar, tu sitio estará protegido contra ataques de fuerza bruta, inyecciones SQL/XSS, scanners y tráfico abusivo. Podés ajustar toda la configuración después desde el menú de Configuración.', 'wp-secure' ); ?></p>
		</div>
		<?php
	}

	/**
	 * Guardar los datos del paso actual.
	 */
	private function save_step( int $step ): void {
		switch ( $step ) {
			case 1:
				$proxy_mode = sanitize_text_field( wp_unslash( $_POST['proxy_mode'] ?? 'auto' ) );
				if ( ! array_key_exists( $proxy_mode, $this->proxy_modes() ) ) {
					$proxy_mode = 'auto';
				}
				$this->loader->set_setting( 'proxy_mode', $proxy_mode );

				if ( isset( $_POST['whitelist_current_ip'] ) ) {
					// Con el modo de proxy recién guardado, no con el de la petición.
					$current_ip = $this->resolve_current_ip();
					$whitelist  = WPS_Whitelist::get_instance();
					if ( '' !== $current_ip && ! $whitelist->is_whitelisted( $current_ip ) ) {
						$whitelist->add_ip( $current_ip, __( 'IP del administrador (wizard)', 'wp-secure' ), 'global' );
					}
				}
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
				$provider = sanitize_key( wp_unslash( $_POST['geo_provider'] ?? WPS_Ipdb_Manager::PROVIDER_NONE ) );
				if ( ! in_array( $provider, WPS_Ipdb_Manager::PROVIDER_IDS, true ) ) {
					$provider = WPS_Ipdb_Manager::PROVIDER_NONE;
				}

				$ipinfo_mode = sanitize_key( wp_unslash( $_POST['ipinfo_mode'] ?? 'api' ) );
				$mm_mode     = sanitize_key( wp_unslash( $_POST['maxmind_mode'] ?? 'local' ) );

				// Se guarda el proveedor elegido aunque falten credenciales: la
				// página siguiente avisa que la configuración está incompleta.
				$this->loader->set_setting( 'geo_provider', $provider );
				$this->loader->set_setting( 'ipinfo_api_key', sanitize_text_field( wp_unslash( $_POST['ipinfo_api_key'] ?? '' ) ) );
				$this->loader->set_setting( 'ipinfo_mode', 'local' === $ipinfo_mode ? 'local' : 'api' );
				$this->loader->set_setting( 'maxmind_account_id', sanitize_text_field( wp_unslash( $_POST['maxmind_account_id'] ?? '' ) ) );
				$this->loader->set_setting( 'maxmind_license_key', sanitize_text_field( wp_unslash( $_POST['maxmind_license_key'] ?? '' ) ) );
				$this->loader->set_setting( 'maxmind_mode', 'api' === $mm_mode ? 'api' : 'local' );
				break;
		}
	}
}
