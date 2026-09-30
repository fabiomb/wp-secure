<?php
/**
 * Tests del registro de actividad.
 */
class Test_WPS_Activity_Log extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wps_test_user_caps']    = array(
			1 => array( 'edit_posts' => true, 'manage_options' => true ),
			2 => array( 'edit_posts' => true ),
		);
		$GLOBALS['wps_test_userdata']     = array(
			2 => (object) array( 'ID' => 2, 'user_login' => 'redactora', 'roles' => array( 'editor' ) ),
			9 => (object) array( 'ID' => 9, 'user_login' => 'cliente', 'roles' => array( 'customer' ) ),
		);
		$GLOBALS['wps_test_current_user'] = (object) array( 'ID' => 1, 'user_login' => 'admin' );
		$GLOBALS['wps_test_actions']      = array();
		$GLOBALS['wpdb']->reset_queries();
	}

	protected function tearDown(): void {
		foreach ( array( 'wps_test_user_caps', 'wps_test_userdata', 'wps_test_current_user', 'wps_test_actions' ) as $key ) {
			unset( $GLOBALS[ $key ] );
		}
	}

	/*──────────────────────────────────────────────
	 * Quién se registra
	 *──────────────────────────────────────────────*/

	public function test_staff_actions_are_recorded_with_actor(): void {
		$this->log()->on_plugin_activated( 'akismet/akismet.php' );

		$row = $this->only_row();
		$this->assertSame( 'plugin_activated', $row['action'] );
		$this->assertSame( 1, $row['user_id'] );
		$this->assertSame( 'admin', $row['user_login'] );
		$this->assertSame( 'akismet/akismet.php', $row['object_name'] );
		$this->assertMatchesRegularExpression( '/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/', $row['created_at'] );
	}

	public function test_customers_and_anonymous_visitors_are_not_recorded(): void {
		$GLOBALS['wps_test_current_user'] = (object) array( 'ID' => 9, 'user_login' => 'cliente' );
		$this->log()->on_plugin_activated( 'x/x.php' );

		$GLOBALS['wps_test_current_user'] = (object) array( 'ID' => 0, 'user_login' => '' );
		$this->log()->on_plugin_activated( 'x/x.php' );

		$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
	}

	public function test_login_is_attributed_to_the_user_logging_in(): void {
		$GLOBALS['wps_test_current_user'] = (object) array( 'ID' => 0, 'user_login' => '' );

		$this->log()->on_login( 'redactora', $GLOBALS['wps_test_userdata'][2] );

		$this->assertSame( 'redactora', $this->only_row()['user_login'] );
	}

	public function test_disabled_log_registers_no_hooks(): void {
		$GLOBALS['wps_test_hooks'] = array();
		$this->log( array( 'activity_log_enabled' => false ) )->init();

		$this->assertSame( array(), $GLOBALS['wps_test_hooks'] );
	}

	/*──────────────────────────────────────────────
	 * Usuarios
	 *──────────────────────────────────────────────*/

	public function test_role_change_records_before_and_after(): void {
		$this->log()->on_set_user_role( 2, 'administrator', array( 'editor' ) );

		$row = $this->only_row();
		$this->assertSame( 'user_role_changed', $row['action'] );
		$this->assertSame( array( 'from' => array( 'editor' ), 'to' => 'administrator' ), json_decode( $row['details'], true ) );
	}

	public function test_initial_role_is_not_a_role_change(): void {
		$this->log()->on_set_user_role( 2, 'editor', array() );

		$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
	}

	public function test_profile_update_lists_sensitive_fields_only(): void {
		$old = (object) array( 'user_email' => 'a@example.com', 'user_pass' => 'hash1', 'display_name' => 'R', 'user_url' => '' );
		$GLOBALS['wps_test_userdata'][2] = (object) array( 'ID' => 2, 'user_login' => 'redactora', 'user_email' => 'b@example.com', 'user_pass' => 'hash2', 'display_name' => 'R', 'user_url' => '' );

		$this->log()->on_profile_update( 2, $old );

		$details = json_decode( $this->only_row()['details'], true );
		$this->assertSame( array( 'email', 'password' ), $details['fields'] );
		$this->assertStringNotContainsString( 'hash', $this->only_row()['details'], 'Nunca el hash de la contraseña.' );
	}

	/*──────────────────────────────────────────────
	 * Contenido
	 *──────────────────────────────────────────────*/

	public function test_post_status_transitions(): void {
		$this->assertSame( 'post_created', WPS_Activity_Log::transition_action( 'draft', 'new' ) );
		$this->assertSame( 'post_published', WPS_Activity_Log::transition_action( 'publish', 'draft' ) );
		$this->assertSame( 'post_published', WPS_Activity_Log::transition_action( 'publish', 'future' ) );
		$this->assertSame( 'post_unpublished', WPS_Activity_Log::transition_action( 'draft', 'publish' ) );
		$this->assertSame( 'post_trashed', WPS_Activity_Log::transition_action( 'trash', 'publish' ) );
		$this->assertSame( 'post_restored', WPS_Activity_Log::transition_action( 'draft', 'trash' ) );
		$this->assertNull( WPS_Activity_Log::transition_action( 'auto-draft', 'new' ) );
		$this->assertNull( WPS_Activity_Log::transition_action( 'draft', 'draft' ) );
		$this->assertNull( WPS_Activity_Log::transition_action( 'inherit', 'new' ) );
	}

	public function test_internal_post_types_are_ignored(): void {
		$this->log()->on_transition_post_status( 'publish', 'new', $this->post( 'revision' ) );
		$this->log()->on_transition_post_status( 'publish', 'new', $this->post( 'nav_menu_item' ) );

		$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
	}

	public function test_published_post_edit_lists_changed_fields(): void {
		$before = $this->post( 'post', array( 'post_content' => 'viejo' ) );
		$after  = $this->post( 'post', array( 'post_content' => 'nuevo' ) );

		$this->log()->on_post_updated( 10, $after, $before );

		$row = $this->only_row();
		$this->assertSame( 'post_updated', $row['action'] );
		$this->assertSame( array( 'fields' => array( 'content' ) ), json_decode( $row['details'], true ) );
	}

	public function test_draft_saves_are_not_post_updates(): void {
		$this->log()->on_post_updated( 10, $this->post( 'post', array( 'post_status' => 'draft', 'post_content' => 'b' ) ), $this->post( 'post', array( 'post_status' => 'draft' ) ) );
		$this->log()->on_post_updated( 10, $this->post( 'post' ), $this->post( 'post' ) );

		$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
	}

	/*──────────────────────────────────────────────
	 * Plugins y ajustes
	 *──────────────────────────────────────────────*/

	public function test_plugin_update_records_each_plugin(): void {
		$this->log()->on_upgrade( null, array( 'type' => 'plugin', 'action' => 'update', 'plugins' => array( 'a/a.php', 'b/b.php' ) ) );

		$this->assertSame( array( 'a/a.php', 'b/b.php' ), array_column( array_column( $GLOBALS['wpdb']->inserts, 1 ), 'object_name' ) );
		$this->assertSame( 'plugin_updated', $GLOBALS['wpdb']->inserts[0][1]['action'] );
	}

	public function test_translations_are_not_recorded(): void {
		$this->log()->on_upgrade( null, array( 'type' => 'translation', 'action' => 'update' ) );

		$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
	}

	public function test_only_watched_options_are_recorded(): void {
		$this->log()->on_updated_option( 'cron', array(), array( 1 ) );
		$this->log()->on_updated_option( '_transient_x', 'a', 'b' );
		$this->log()->on_updated_option( 'users_can_register', '0', '1' );

		$row = $this->only_row();
		$this->assertSame( 'users_can_register', $row['object_name'] );
		$this->assertSame( array( 'from' => '0', 'to' => '1' ), json_decode( $row['details'], true ) );
	}

	public function test_long_option_values_are_truncated(): void {
		$this->log()->on_updated_option( 'blogdescription', '', str_repeat( 'x', 500 ) );

		$details = json_decode( $this->only_row()['details'], true );
		$this->assertSame( WPS_Activity_Log::MAX_VALUE_LENGTH + 1, mb_strlen( $details['to'] ) );
	}

	public function test_wp_secure_settings_changes_reach_the_log(): void {
		$loader   = WPS_Loader::get_instance();
		$notifier = new \ReflectionProperty( 'WPS_Admin_Notifier', 'instance' );
		$notifier->setAccessible( true );
		$notifier->setValue( null, null );

		WPS_Admin_Notifier::get_instance( $this->loader( array( 'notify_settings_change' => false ) ) )->notify_settings_change( 1, 'Modo Inseguro activado' );

		$this->assertSame( array( array( 'wps_settings_changed', array( 1, 'Modo Inseguro activado' ) ) ), $GLOBALS['wps_test_actions'], 'Aunque el mail esté apagado.' );

		$this->log()->on_wps_settings_changed( 1, 'Modo Inseguro activado' );
		$this->assertSame( 'Modo Inseguro activado', $this->only_row()['object_name'] );
	}

	/*──────────────────────────────────────────────
	 * Consulta y página
	 *──────────────────────────────────────────────*/

	public function test_query_filters_by_group_and_user(): void {
		$this->log()->query( array( 'group' => 'plugins', 'user_id' => 2 ) );

		$args = $GLOBALS['wpdb']->prepared_args[0];
		$this->assertContains( 'plugin_activated', $args );
		$this->assertSame( 2, end( $args ) );
	}

	public function test_details_are_rendered_as_one_line(): void {
		$this->assertSame( 'editor → administrator', WPS_Admin_Activity::details_text( '{"from":["editor"],"to":"administrator"}' ) );
		$this->assertSame( 'fields: email, password', WPS_Admin_Activity::details_text( '{"fields":["email","password"]}' ) );
		$this->assertSame( '', WPS_Admin_Activity::details_text( '' ) );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function log( array $settings = array() ): WPS_Activity_Log {
		return new WPS_Activity_Log( $this->loader( $settings ) );
	}

	private function loader( array $settings ): WPS_Loader {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );
		return $loader;
	}

	private function post( string $type, array $fields = array() ) {
		return (object) ( $fields + array(
			'ID'           => 10,
			'post_type'    => $type,
			'post_status'  => 'publish',
			'post_title'   => 'Hola',
			'post_content' => 'texto',
			'post_excerpt' => '',
			'post_name'    => 'hola',
			'post_author'  => 1,
		) );
	}

	private function only_row(): array {
		$this->assertCount( 1, $GLOBALS['wpdb']->inserts );
		return $GLOBALS['wpdb']->inserts[0][1];
	}
}
