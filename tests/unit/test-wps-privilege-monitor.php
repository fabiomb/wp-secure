<?php
/**
 * Tests de las alertas de escalada de privilegios.
 */
class Test_WPS_Privilege_Monitor extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wps_test_mails']        = array();
		$GLOBALS['wps_test_user_caps']    = array( 7 => array( 'manage_options' => true ) );
		$GLOBALS['wps_test_userdata']     = array(
			7 => (object) array( 'ID' => 7, 'user_login' => 'intruso', 'user_email' => 'x@evil.tld' ),
			8 => (object) array( 'ID' => 8, 'user_login' => 'suscriptor', 'user_email' => 's@example.com' ),
		);
		$GLOBALS['wps_test_roles']        = array(
			'gerente'  => (object) array( 'capabilities' => array( 'manage_options' => true ) ),
			'editor'   => (object) array( 'capabilities' => array( 'edit_posts' => true ) ),
		);
		$GLOBALS['wps_test_current_user'] = (object) array( 'ID' => 1, 'user_login' => 'admin' );
		$GLOBALS['wpdb']->reset_queries();
	}

	protected function tearDown(): void {
		foreach ( array( 'wps_test_user_caps', 'wps_test_userdata', 'wps_test_roles', 'wps_test_current_user' ) as $key ) {
			unset( $GLOBALS[ $key ] );
		}
	}

	public function test_new_administrator_is_reported(): void {
		$this->monitor()->on_user_register( 7 );

		$this->assertCount( 1, $GLOBALS['wps_test_mails'] );
		$this->assertStringContainsString( 'intruso', $GLOBALS['wps_test_mails'][0]['message'] );
		$this->assertStringContainsString( 'by: admin', $GLOBALS['wps_test_mails'][0]['message'] );
		$this->assertSame( 1, $this->privilege_events() );
	}

	public function test_new_regular_user_is_not_reported(): void {
		$this->monitor()->on_user_register( 8 );

		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	public function test_promotion_to_administrator_is_reported(): void {
		$this->monitor()->on_set_user_role( 8, 'administrator', array( 'subscriber' ) );

		$this->assertCount( 1, $GLOBALS['wps_test_mails'] );
		$this->assertStringContainsString( 'suscriptor', $GLOBALS['wps_test_mails'][0]['message'] );
	}

	public function test_custom_role_with_manage_options_counts_as_admin(): void {
		$this->monitor()->on_set_user_role( 8, 'gerente', array( 'subscriber' ) );

		$this->assertCount( 1, $GLOBALS['wps_test_mails'], 'Un rol propio con manage_options da el mismo control.' );
	}

	public function test_changes_between_non_admin_roles_are_not_reported(): void {
		$this->monitor()->on_set_user_role( 8, 'editor', array( 'subscriber' ) );

		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	public function test_admin_changing_between_admin_roles_is_not_reported(): void {
		$this->monitor()->on_set_user_role( 7, 'gerente', array( 'administrator' ) );

		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	public function test_plugin_activation_and_install_are_reported(): void {
		$monitor = $this->monitor();

		$monitor->on_plugin_activated( 'backdoor/backdoor.php' );
		$monitor->on_install( (object) array( 'new_plugin_data' => array( 'Name' => 'Backdoor' ) ), array( 'action' => 'install', 'type' => 'plugin' ) );

		$this->assertCount( 2, $GLOBALS['wps_test_mails'] );
		$this->assertStringContainsString( 'backdoor/backdoor.php', $GLOBALS['wps_test_mails'][0]['message'] );
		$this->assertStringContainsString( 'Backdoor', $GLOBALS['wps_test_mails'][1]['message'] );
	}

	public function test_updates_are_not_reported_as_installs(): void {
		$this->monitor()->on_install( null, array( 'action' => 'update', 'type' => 'plugin' ) );

		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	public function test_deactivating_wp_secure_is_called_out(): void {
		$this->monitor()->on_plugin_deactivated( WPS_PLUGIN_BASENAME );

		$this->assertStringContainsString( 'WP Seguro', $GLOBALS['wps_test_mails'][0]['subject'] );
	}

	public function test_mail_respects_its_setting_but_the_event_is_logged(): void {
		$this->monitor( array( 'notify_privilege_changes' => false ) )->on_plugin_activated( 'x/x.php' );

		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
		$this->assertSame( 1, $this->privilege_events() );
	}

	private function monitor( array $settings = array() ): WPS_Privilege_Monitor {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings + array( 'notify_privilege_changes' => true, 'notify_email' => 'alertas@example.com' ) );

		$notifier = new \ReflectionProperty( 'WPS_Admin_Notifier', 'instance' );
		$notifier->setAccessible( true );
		$notifier->setValue( null, null );

		return new WPS_Privilege_Monitor( $loader );
	}

	private function privilege_events(): int {
		return count( array_filter( $GLOBALS['wpdb']->inserts, function ( $insert ) {
			return 'wp_wps_security_events' === $insert[0] && 'privilege_change' === $insert[1]['event_type'];
		} ) );
	}
}
