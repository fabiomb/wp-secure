<?php
defined( 'ABSPATH' ) || exit;

/**
 * Alertas de escalada de privilegios.
 *
 * Quien toma el control de un sitio suele dejar rastros en pocos lugares: crea
 * un administrador o asciende una cuenta, instala o activa un plugin (a menudo
 * un backdoor), cambia el tema, edita un archivo desde el panel o desactiva
 * el firewall. Cada uno registra un evento y, si el aviso está activo, manda
 * un mail con quién, desde dónde y qué.
 */
class WPS_Privilege_Monitor {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Registrar hooks. Corre en todas las peticiones: un usuario también se
	 * crea desde la REST API, WP-CLI o un registro público.
	 */
	public function init(): void {
		add_action( 'user_register', array( $this, 'on_user_register' ) );
		add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
		add_action( 'add_user_role', array( $this, 'on_add_user_role' ), 10, 2 );
		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ) );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ) );
		add_action( 'upgrader_process_complete', array( $this, 'on_install' ), 10, 2 );
		add_action( 'switch_theme', array( $this, 'on_switch_theme' ), 10, 3 );
		add_action( 'wp_ajax_edit-theme-plugin-file', array( $this, 'on_file_edit' ), 0 );
	}

	/*──────────────────────────────────────────────
	 * Usuarios
	 *──────────────────────────────────────────────*/

	/**
	 * @param int $user_id Usuario creado.
	 */
	public function on_user_register( $user_id ): void {
		$user = get_userdata( (int) $user_id );
		if ( $user && user_can( $user, 'manage_options' ) ) {
			$this->report( __( 'Se creó un administrador', 'wp-secure' ), array(
				'user'  => $user->user_login ?? '',
				'email' => $user->user_email ?? '',
			) );
		}
	}

	/**
	 * @param int      $user_id   Usuario.
	 * @param string   $role      Rol nuevo.
	 * @param string[] $old_roles Roles anteriores.
	 */
	public function on_set_user_role( $user_id, $role, $old_roles = array() ): void {
		if ( ! self::grants_admin( (string) $role ) ) {
			return;
		}

		foreach ( (array) $old_roles as $old ) {
			if ( self::grants_admin( (string) $old ) ) {
				return; // Ya era administrador.
			}
		}

		$this->report_promotion( (int) $user_id, (string) $role, (array) $old_roles );
	}

	/**
	 * @param int    $user_id Usuario.
	 * @param string $role    Rol agregado.
	 */
	public function on_add_user_role( $user_id, $role ): void {
		if ( self::grants_admin( (string) $role ) ) {
			$this->report_promotion( (int) $user_id, (string) $role, array() );
		}
	}

	private function report_promotion( int $user_id, string $role, array $old_roles ): void {
		$user = get_userdata( $user_id );

		$this->report( __( 'Un usuario pasó a tener permisos de administración', 'wp-secure' ), array(
			'user'      => $user->user_login ?? (string) $user_id,
			'role'      => $role,
			'old_roles' => implode( ', ', $old_roles ),
		) );
	}

	/**
	 * ¿El rol permite administrar el sitio (`manage_options`)?
	 *
	 * No se mira sólo `administrator`: un rol personalizado con esa capacidad
	 * da el mismo control.
	 */
	public static function grants_admin( string $role ): bool {
		if ( 'administrator' === $role ) {
			return true;
		}

		$role_object = function_exists( 'get_role' ) ? get_role( $role ) : null;

		return $role_object && ! empty( $role_object->capabilities['manage_options'] );
	}

	/*──────────────────────────────────────────────
	 * Plugins, temas y archivos
	 *──────────────────────────────────────────────*/

	/**
	 * @param string $plugin Archivo principal del plugin.
	 */
	public function on_plugin_activated( $plugin ): void {
		$this->report( __( 'Se activó un plugin', 'wp-secure' ), array( 'plugin' => (string) $plugin ) );
	}

	/**
	 * @param string $plugin Archivo principal del plugin.
	 */
	public function on_plugin_deactivated( $plugin ): void {
		$is_self = defined( 'WPS_PLUGIN_BASENAME' ) && WPS_PLUGIN_BASENAME === $plugin;

		$this->report(
			$is_self ? __( 'Se desactivó WP Seguro', 'wp-secure' ) : __( 'Se desactivó un plugin', 'wp-secure' ),
			array( 'plugin' => (string) $plugin )
		);
	}

	/**
	 * @param WP_Upgrader $upgrader   Instancia del instalador.
	 * @param array       $hook_extra Datos de la operación.
	 */
	public function on_install( $upgrader, $hook_extra ): void {
		if ( 'install' !== ( $hook_extra['action'] ?? '' ) ) {
			return;
		}

		$type = (string) ( $hook_extra['type'] ?? '' );
		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			return;
		}

		$name = '';
		if ( is_object( $upgrader ) && ! empty( $upgrader->new_plugin_data['Name'] ) ) {
			$name = $upgrader->new_plugin_data['Name'];
		} elseif ( is_object( $upgrader ) && ! empty( $upgrader->new_theme_data['Name'] ) ) {
			$name = $upgrader->new_theme_data['Name'];
		}

		$this->report(
			'plugin' === $type ? __( 'Se instaló un plugin', 'wp-secure' ) : __( 'Se instaló un tema', 'wp-secure' ),
			array( 'name' => $name )
		);
	}

	/**
	 * @param string   $new_name  Nombre del tema nuevo.
	 * @param WP_Theme $new_theme Tema nuevo.
	 * @param WP_Theme $old_theme Tema anterior.
	 */
	public function on_switch_theme( $new_name, $new_theme = null, $old_theme = null ): void {
		$this->report( __( 'Se cambió el tema', 'wp-secure' ), array(
			'theme'     => (string) $new_name,
			'old_theme' => is_object( $old_theme ) && method_exists( $old_theme, 'get' ) ? (string) $old_theme->get( 'Name' ) : '',
		) );
	}

	/**
	 * Edición de un archivo de plugin o tema desde el panel.
	 *
	 * Corre antes que el guardado de WordPress, así que registra el intento de
	 * un usuario con permiso para editar. Desactivar el editor
	 * (`DISALLOW_FILE_EDIT`) evita este vector por completo.
	 */
	public function on_file_edit(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$file   = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		$plugin = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : '';
		$theme  = isset( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( $_POST['theme'] ) ) : '';
		// phpcs:enable

		if ( '' === $file || ! ( current_user_can( 'edit_plugins' ) || current_user_can( 'edit_themes' ) ) ) {
			return;
		}

		$this->report( __( 'Se editó un archivo desde el panel', 'wp-secure' ), array(
			'file'   => $file,
			'plugin' => $plugin,
			'theme'  => $theme,
		) );
	}

	/*──────────────────────────────────────────────
	 * Registro
	 *──────────────────────────────────────────────*/

	/**
	 * Registrar el evento y avisar por mail.
	 *
	 * @param string $summary Qué pasó.
	 * @param array  $details Datos del cambio.
	 */
	private function report( string $summary, array $details ): void {
		$request = WPS_Request::get_instance();
		$actor   = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;

		$details = array_filter( $details, 'strlen' ) + array(
			'by' => ( $actor && ! empty( $actor->user_login ) ) ? $actor->user_login : __( 'sistema', 'wp-secure' ),
		);

		WPS_Logger::get_instance()->event_immediate( WPS_Event_Types::PRIVILEGE_CHANGE, array(
			'ip_address'  => $request->ip(),
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'wp_user_id'  => $actor->ID ?? null,
			'details'     => array( 'summary' => $summary ) + $details,
		) );

		WPS_Admin_Notifier::get_instance( $this->loader )->notify_privilege_change( $summary, $details, $request->ip() );
	}
}
