<?php
defined( 'ABSPATH' ) || exit;

/**
 * Registro de actividad del equipo del sitio: quién hizo qué y cuándo.
 *
 * Separado del log de seguridad: registra acciones legítimas (o que lo
 * parecen) de usuarios con acceso al panel, para reconstruir qué pasó
 * después de un incidente o de un cambio inesperado.
 *
 * - Sólo acciones de usuarios que pueden editar contenido (`edit_posts`) y
 *   de WP-CLI; los clientes de una tienda o los suscriptores no generan
 *   entradas.
 * - Usuarios, contenido, medios, plugins, temas, núcleo, ajustes principales
 *   de WordPress y la configuración de WP Seguro.
 * - Se guarda en su propia tabla y se purga según la retención configurada.
 */
class WPS_Activity_Log {

	/** Tipos de post internos que no son contenido editorial. */
	const SKIP_POST_TYPES = array( 'revision', 'nav_menu_item', 'customize_changeset', 'oembed_cache', 'user_request', 'wp_global_styles', 'custom_css' );

	/** Ajustes de WordPress que se registran (Ajustes → Generales, Lectura, Discusión, Enlaces permanentes). */
	const WATCHED_OPTIONS = array(
		'blogname', 'blogdescription', 'siteurl', 'home', 'admin_email', 'new_admin_email',
		'users_can_register', 'default_role', 'permalink_structure', 'category_base', 'tag_base',
		'blog_public', 'show_on_front', 'page_on_front', 'page_for_posts', 'default_comment_status',
		'comment_registration', 'comment_moderation', 'comment_previously_approved', 'WPLANG', 'timezone_string',
	);

	/** Grupos de acciones para filtrar. */
	const GROUPS = array(
		'users'    => array( 'user_login', 'user_logout', 'user_created', 'user_deleted', 'user_role_changed', 'user_updated', 'password_reset' ),
		'content'  => array( 'post_created', 'post_published', 'post_updated', 'post_unpublished', 'post_trashed', 'post_restored', 'post_deleted', 'media_uploaded', 'media_deleted', 'content_exported' ),
		'plugins'  => array( 'plugin_activated', 'plugin_deactivated', 'plugin_installed', 'plugin_updated', 'plugin_deleted', 'theme_switched', 'theme_installed', 'theme_updated', 'theme_deleted', 'core_updated', 'file_edited' ),
		'settings' => array( 'option_updated', 'wps_settings' ),
	);

	/** Largo máximo de un valor de ajuste en los detalles. */
	const MAX_VALUE_LENGTH = 200;

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Db|null */
	private $db;

	public function __construct( WPS_Loader $loader, ?WPS_Db $db = null ) {
		$this->loader = $loader;
		$this->db     = $db;
	}

	/**
	 * Registrar hooks. Corre en todas las peticiones: los cambios también
	 * llegan por la REST API (editor de bloques), AJAX y WP-CLI.
	 */
	public function init(): void {
		if ( ! $this->loader->get_setting( 'activity_log_enabled', true ) ) {
			return;
		}

		// Usuarios.
		add_action( 'wp_login', array( $this, 'on_login' ), 10, 2 );
		add_action( 'wp_logout', array( $this, 'on_logout' ) );
		add_action( 'user_register', array( $this, 'on_user_register' ) );
		add_action( 'delete_user', array( $this, 'on_delete_user' ) );
		add_action( 'set_user_role', array( $this, 'on_set_user_role' ), 10, 3 );
		add_action( 'profile_update', array( $this, 'on_profile_update' ), 10, 2 );
		add_action( 'after_password_reset', array( $this, 'on_password_reset' ) );

		// Contenido.
		add_action( 'transition_post_status', array( $this, 'on_transition_post_status' ), 10, 3 );
		add_action( 'post_updated', array( $this, 'on_post_updated' ), 10, 3 );
		add_action( 'before_delete_post', array( $this, 'on_delete_post' ) );
		add_action( 'add_attachment', array( $this, 'on_add_attachment' ) );
		add_action( 'delete_attachment', array( $this, 'on_delete_attachment' ) );
		add_action( 'export_wp', array( $this, 'on_export' ) );

		// Plugins, temas y núcleo.
		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ) );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ) );
		add_action( 'deleted_plugin', array( $this, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrade' ), 10, 2 );
		add_action( 'switch_theme', array( $this, 'on_switch_theme' ), 10, 3 );
		add_action( 'deleted_theme', array( $this, 'on_theme_deleted' ), 10, 2 );
		add_action( 'wp_ajax_edit-theme-plugin-file', array( $this, 'on_file_edit' ), 0 );

		// Ajustes.
		add_action( 'updated_option', array( $this, 'on_updated_option' ), 10, 3 );
		add_action( 'wps_settings_changed', array( $this, 'on_wps_settings_changed' ), 10, 2 );
	}

	/*──────────────────────────────────────────────
	 * Registro y consulta
	 *──────────────────────────────────────────────*/

	/**
	 * Registrar una acción del usuario actual.
	 *
	 * @param WP_User|null $actor Quién la hizo; por defecto, el usuario actual.
	 * @return bool Si se registró.
	 */
	public function record( string $action, string $object_type = '', int $object_id = 0, string $object_name = '', array $details = array(), $actor = null ): bool {
		$actor = $actor ?? ( function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null );
		$cli   = defined( 'WP_CLI' ) && WP_CLI;

		$user_id = ( $actor && ! empty( $actor->ID ) ) ? (int) $actor->ID : 0;

		if ( ! $cli && ( ! $user_id || ! user_can( $actor, 'edit_posts' ) ) ) {
			return false;
		}

		$login = $user_id ? (string) ( $actor->user_login ?? '' ) : 'wp-cli';

		return false !== $this->db()->insert( 'activity_log', array(
			'created_at'  => gmdate( 'Y-m-d H:i:s' ),
			'user_id'     => $user_id,
			'user_login'  => substr( $login, 0, 60 ),
			'ip_address'  => $cli ? '' : (string) WPS_Request::get_instance()->ip(),
			'action'      => $action,
			'object_type' => $object_type,
			'object_id'   => $object_id,
			'object_name' => mb_substr( $object_name, 0, 255 ),
			'details'     => $details ? (string) wp_json_encode( $details ) : '',
		) );
	}

	/**
	 * Entradas del registro, más recientes primero.
	 *
	 * @param array $filters group, user_id.
	 * @return array{rows: array[], total: int}
	 */
	public function query( array $filters = array(), int $page = 1, int $per_page = 50 ): array {
		$table  = WPS_Db_Schema::table( 'activity_log' );
		$where  = array( '1=1' );
		$args   = array();

		if ( ! empty( $filters['group'] ) && isset( self::GROUPS[ $filters['group'] ] ) ) {
			$actions = self::GROUPS[ $filters['group'] ];
			$where[] = 'action IN (' . implode( ',', array_fill( 0, count( $actions ), '%s' ) ) . ')';
			$args    = array_merge( $args, $actions );
		}

		if ( ! empty( $filters['user_id'] ) ) {
			$where[] = 'user_id = %d';
			$args[]  = (int) $filters['user_id'];
		}

		$sql_where = implode( ' AND ', $where );
		$offset    = max( 0, ( $page - 1 ) * $per_page );

		$total = (int) $this->db()->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$sql_where}", ...$args );
		$rows  = $this->db()->get_results(
			"SELECT * FROM {$table} WHERE {$sql_where} ORDER BY id DESC LIMIT %d OFFSET %d",
			...array_merge( $args, array( $per_page, $offset ) )
		);

		return array( 'rows' => $rows, 'total' => $total );
	}

	/**
	 * Borrar entradas más viejas que la retención configurada.
	 */
	public static function purge( int $days ): void {
		$table = WPS_Db_Schema::table( 'activity_log' );
		WPS_Db::get_instance()->query(
			"DELETE FROM {$table} WHERE created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
			max( 1, $days )
		);
	}

	private function db(): WPS_Db {
		return $this->db ?? WPS_Db::get_instance();
	}

	/**
	 * Etiqueta de una acción.
	 */
	public static function label( string $action ): string {
		$labels = array(
			'user_login'         => __( 'Inició sesión', 'wp-secure' ),
			'user_logout'        => __( 'Cerró sesión', 'wp-secure' ),
			'user_created'       => __( 'Creó un usuario', 'wp-secure' ),
			'user_deleted'       => __( 'Eliminó un usuario', 'wp-secure' ),
			'user_role_changed'  => __( 'Cambió el rol de un usuario', 'wp-secure' ),
			'user_updated'       => __( 'Modificó un usuario', 'wp-secure' ),
			'password_reset'     => __( 'Restableció una contraseña', 'wp-secure' ),
			'post_created'       => __( 'Creó contenido', 'wp-secure' ),
			'post_published'     => __( 'Publicó', 'wp-secure' ),
			'post_updated'       => __( 'Modificó contenido publicado', 'wp-secure' ),
			'post_unpublished'   => __( 'Despublicó', 'wp-secure' ),
			'post_trashed'       => __( 'Envió a la papelera', 'wp-secure' ),
			'post_restored'      => __( 'Restauró de la papelera', 'wp-secure' ),
			'post_deleted'       => __( 'Eliminó definitivamente', 'wp-secure' ),
			'media_uploaded'     => __( 'Subió un archivo', 'wp-secure' ),
			'media_deleted'      => __( 'Eliminó un archivo', 'wp-secure' ),
			'content_exported'   => __( 'Exportó el contenido', 'wp-secure' ),
			'plugin_activated'   => __( 'Activó un plugin', 'wp-secure' ),
			'plugin_deactivated' => __( 'Desactivó un plugin', 'wp-secure' ),
			'plugin_installed'   => __( 'Instaló un plugin', 'wp-secure' ),
			'plugin_updated'     => __( 'Actualizó un plugin', 'wp-secure' ),
			'plugin_deleted'     => __( 'Eliminó un plugin', 'wp-secure' ),
			'theme_switched'     => __( 'Cambió el tema', 'wp-secure' ),
			'theme_installed'    => __( 'Instaló un tema', 'wp-secure' ),
			'theme_updated'      => __( 'Actualizó un tema', 'wp-secure' ),
			'theme_deleted'      => __( 'Eliminó un tema', 'wp-secure' ),
			'core_updated'       => __( 'Actualizó WordPress', 'wp-secure' ),
			'file_edited'        => __( 'Editó un archivo desde el panel', 'wp-secure' ),
			'option_updated'     => __( 'Cambió un ajuste de WordPress', 'wp-secure' ),
			'wps_settings'       => __( 'Cambió la configuración de WP Seguro', 'wp-secure' ),
		);

		return $labels[ $action ] ?? $action;
	}

	/*──────────────────────────────────────────────
	 * Usuarios
	 *──────────────────────────────────────────────*/

	/**
	 * En wp_login el usuario todavía no es el actual.
	 */
	public function on_login( $user_login, $user = null ): void {
		if ( $user instanceof WP_User || is_object( $user ) ) {
			$this->record( 'user_login', 'user', (int) $user->ID, (string) $user_login, array(), $user );
		}
	}

	/**
	 * En wp_logout el usuario actual ya es 0: se pasa el que salió.
	 */
	public function on_logout( $user_id = 0 ): void {
		$user = get_userdata( (int) $user_id );
		if ( $user ) {
			$this->record( 'user_logout', 'user', (int) $user->ID, (string) $user->user_login, array(), $user );
		}
	}

	public function on_user_register( $user_id ): void {
		$user = get_userdata( (int) $user_id );
		if ( $user ) {
			$this->record( 'user_created', 'user', (int) $user_id, (string) $user->user_login, array( 'roles' => array_values( (array) $user->roles ) ) );
		}
	}

	public function on_delete_user( $user_id ): void {
		$user = get_userdata( (int) $user_id );
		$this->record( 'user_deleted', 'user', (int) $user_id, $user ? (string) $user->user_login : '' );
	}

	public function on_set_user_role( $user_id, $role, $old_roles = array() ): void {
		// Al crear un usuario también se fija su rol: eso ya es user_created.
		if ( ! $old_roles ) {
			return;
		}

		$user = get_userdata( (int) $user_id );
		$this->record( 'user_role_changed', 'user', (int) $user_id, $user ? (string) $user->user_login : '', array(
			'from' => array_values( (array) $old_roles ),
			'to'   => (string) $role,
		) );
	}

	/**
	 * Cambios de email, contraseña, nombre o web de un usuario.
	 */
	public function on_profile_update( $user_id, $old_user = null ): void {
		$user = get_userdata( (int) $user_id );
		if ( ! $user || ! is_object( $old_user ) ) {
			return;
		}

		$changed = array();
		foreach ( array( 'user_email' => 'email', 'user_pass' => 'password', 'display_name' => 'display_name', 'user_url' => 'url' ) as $field => $name ) {
			if ( (string) ( $old_user->$field ?? '' ) !== (string) ( $user->$field ?? '' ) ) {
				$changed[] = $name;
			}
		}

		if ( $changed ) {
			$this->record( 'user_updated', 'user', (int) $user_id, (string) $user->user_login, array( 'fields' => $changed ) );
		}
	}

	public function on_password_reset( $user ): void {
		if ( is_object( $user ) ) {
			// Quien restablece no está logueado: la acción es del propio usuario.
			$this->record( 'password_reset', 'user', (int) $user->ID, (string) $user->user_login, array(), $user );
		}
	}

	/*──────────────────────────────────────────────
	 * Contenido
	 *──────────────────────────────────────────────*/

	/**
	 * Acción de un cambio de estado de un post, o null si no se registra.
	 */
	public static function transition_action( string $new, string $old ): ?string {
		if ( $new === $old || in_array( $new, array( 'auto-draft', 'inherit' ), true ) ) {
			return null;
		}
		if ( 'trash' === $new ) {
			return 'post_trashed';
		}
		if ( 'trash' === $old ) {
			return 'post_restored';
		}
		if ( 'publish' === $new ) {
			return 'post_published';
		}
		if ( 'publish' === $old ) {
			return 'post_unpublished';
		}
		if ( in_array( $old, array( 'new', 'auto-draft' ), true ) ) {
			return 'post_created';
		}
		return null;
	}

	public function on_transition_post_status( $new_status, $old_status, $post ): void {
		$action = self::transition_action( (string) $new_status, (string) $old_status );
		if ( null !== $action && $this->is_tracked_post( $post ) ) {
			$this->record( $action, (string) $post->post_type, (int) $post->ID, (string) $post->post_title, array( 'status' => (string) $new_status ) );
		}
	}

	/**
	 * Cambios en contenido que ya estaba publicado (y sigue publicado).
	 */
	public function on_post_updated( $post_id, $after, $before ): void {
		if ( ! is_object( $after ) || ! is_object( $before ) || 'publish' !== $after->post_status || 'publish' !== $before->post_status ) {
			return;
		}
		if ( ! $this->is_tracked_post( $after ) ) {
			return;
		}

		$changed = array();
		foreach ( array( 'post_title' => 'title', 'post_content' => 'content', 'post_excerpt' => 'excerpt', 'post_name' => 'slug', 'post_author' => 'author' ) as $field => $name ) {
			if ( (string) $before->$field !== (string) $after->$field ) {
				$changed[] = $name;
			}
		}

		if ( $changed ) {
			$this->record( 'post_updated', (string) $after->post_type, (int) $post_id, (string) $after->post_title, array( 'fields' => $changed ) );
		}
	}

	public function on_delete_post( $post_id ): void {
		$post = get_post( (int) $post_id );
		if ( $post && 'auto-draft' !== $post->post_status && $this->is_tracked_post( $post ) ) {
			$this->record( 'post_deleted', (string) $post->post_type, (int) $post_id, (string) $post->post_title );
		}
	}

	public function on_add_attachment( $post_id ): void {
		$this->record( 'media_uploaded', 'attachment', (int) $post_id, basename( (string) get_attached_file( (int) $post_id ) ) );
	}

	public function on_delete_attachment( $post_id ): void {
		$this->record( 'media_deleted', 'attachment', (int) $post_id, basename( (string) get_attached_file( (int) $post_id ) ) );
	}

	public function on_export( $args = array() ): void {
		$this->record( 'content_exported', 'site', 0, '', array( 'content' => is_array( $args ) ? (string) ( $args['content'] ?? 'all' ) : 'all' ) );
	}

	private function is_tracked_post( $post ): bool {
		if ( ! is_object( $post ) || empty( $post->post_type ) || in_array( $post->post_type, self::SKIP_POST_TYPES, true ) ) {
			return false;
		}
		if ( 'attachment' === $post->post_type ) {
			return false; // Los medios tienen sus propias acciones.
		}
		if ( function_exists( 'wp_is_post_autosave' ) && wp_is_post_autosave( $post ) ) {
			return false;
		}

		$type = function_exists( 'get_post_type_object' ) ? get_post_type_object( $post->post_type ) : null;
		return ! $type || ! empty( $type->show_ui );
	}

	/*──────────────────────────────────────────────
	 * Plugins, temas y núcleo
	 *──────────────────────────────────────────────*/

	public function on_plugin_activated( $plugin ): void {
		$this->record( 'plugin_activated', 'plugin', 0, (string) $plugin );
	}

	public function on_plugin_deactivated( $plugin ): void {
		$this->record( 'plugin_deactivated', 'plugin', 0, (string) $plugin );
	}

	public function on_plugin_deleted( $plugin, $deleted = true ): void {
		if ( $deleted ) {
			$this->record( 'plugin_deleted', 'plugin', 0, (string) $plugin );
		}
	}

	/**
	 * Instalaciones y actualizaciones de plugins, temas y núcleo.
	 */
	public function on_upgrade( $upgrader, $hook_extra ): void {
		if ( ! is_array( $hook_extra ) ) {
			return;
		}

		$type   = (string) ( $hook_extra['type'] ?? '' );
		$action = (string) ( $hook_extra['action'] ?? '' );

		if ( 'core' === $type ) {
			$this->record( 'core_updated', 'core', 0, 'WordPress', array( 'version' => (string) get_bloginfo( 'version' ) ) );
			return;
		}

		if ( ! in_array( $type, array( 'plugin', 'theme' ), true ) || ! in_array( $action, array( 'install', 'update' ), true ) ) {
			return;
		}

		$slug = 'install' === $action ? 'installed' : 'updated';
		$key  = 'plugin' === $type ? 'plugins' : 'themes';
		$items = (array) ( $hook_extra[ $key ] ?? ( isset( $hook_extra[ $type ] ) ? array( $hook_extra[ $type ] ) : array() ) );

		// Una instalación no trae el nombre en hook_extra.
		if ( ! $items && 'install' === $action && is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) && 'plugin' === $type ) {
			$items = array( (string) $upgrader->plugin_info() );
		}
		if ( ! $items && 'install' === $action && is_object( $upgrader ) && 'theme' === $type && method_exists( $upgrader, 'theme_info' ) ) {
			$theme = $upgrader->theme_info();
			$items = array( $theme ? (string) $theme->get_stylesheet() : '' );
		}

		foreach ( $items ?: array( '' ) as $item ) {
			$this->record( $type . '_' . $slug, $type, 0, (string) $item );
		}
	}

	public function on_switch_theme( $new_name, $new_theme = null, $old_theme = null ): void {
		$this->record( 'theme_switched', 'theme', 0, (string) $new_name, array(
			'from' => is_object( $old_theme ) ? (string) $old_theme->get( 'Name' ) : '',
		) );
	}

	public function on_theme_deleted( $stylesheet, $deleted = true ): void {
		if ( $deleted ) {
			$this->record( 'theme_deleted', 'theme', 0, (string) $stylesheet );
		}
	}

	/**
	 * Guardado de un archivo desde el editor de plugins o temas.
	 */
	public function on_file_edit(): void {
		$file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		$from = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : ( isset( $_POST['theme'] ) ? sanitize_text_field( wp_unslash( $_POST['theme'] ) ) : '' ); // phpcs:ignore

		$this->record( 'file_edited', 'file', 0, $file, array( 'in' => $from ) );
	}

	/*──────────────────────────────────────────────
	 * Ajustes
	 *──────────────────────────────────────────────*/

	public function on_updated_option( $option, $old_value, $value ): void {
		if ( ! in_array( $option, self::WATCHED_OPTIONS, true ) ) {
			return;
		}

		$this->record( 'option_updated', 'option', 0, (string) $option, array(
			'from' => self::short_value( $old_value ),
			'to'   => self::short_value( $value ),
		) );
	}

	/**
	 * Cambios en la configuración de WP Seguro (panel, importación, WP-CLI).
	 */
	public function on_wps_settings_changed( $user_id, $change = '' ): void {
		$user = get_userdata( (int) $user_id );
		$this->record( 'wps_settings', 'wp-secure', 0, (string) $change, array(), $user ?: null );
	}

	private static function short_value( $value ): string {
		$value = is_scalar( $value ) ? (string) $value : (string) wp_json_encode( $value );
		return mb_strlen( $value ) > self::MAX_VALUE_LENGTH ? mb_substr( $value, 0, self::MAX_VALUE_LENGTH ) . '…' : $value;
	}
}
