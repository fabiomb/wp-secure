<?php
/**
 * Tests del aviso de login de un administrador desde una red nueva.
 *
 * El ajuste venía activado por defecto, pero nada llamaba al aviso: nunca se
 * enviaba. Estos tests fijan cuándo corresponde avisar y cuándo no.
 */
class Test_WPS_New_Login_Ip extends \PHPUnit\Framework\TestCase {

	/** @var WPS_Admin_Notifier */
	private $notifier;

	protected function setUp(): void {
		$GLOBALS['wps_test_mails']     = array();
		$GLOBALS['wps_test_user_meta'] = array();
		$GLOBALS['wps_test_user_caps'] = array( 1 => array( 'manage_options' => true ) );

		$this->notifier = $this->notifier_with( array(
			'notify_new_login_ip' => true,
			'notify_email'        => 'alertas@example.com',
		) );
	}

	protected function tearDown(): void {
		$GLOBALS['wps_test_user_caps'] = array();
		$this->reset_notifier();
	}

	public function test_first_login_without_history_does_not_notify(): void {
		// Al instalar el plugin toda red es «nueva»: avisar sería ruido.
		$this->assertFalse( $this->notifier->track_login( $this->admin(), '10.0.0.5' ) );
		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	public function test_login_from_known_network_does_not_notify(): void {
		$this->notifier->track_login( $this->admin(), '10.0.0.5' );

		$this->assertFalse( $this->notifier->track_login( $this->admin(), '10.0.0.5' ) );
		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	public function test_login_from_new_network_notifies(): void {
		$this->notifier->track_login( $this->admin(), '10.0.0.5' );

		$this->assertTrue( $this->notifier->track_login( $this->admin(), '10.9.9.9' ) );
		$this->assertCount( 1, $GLOBALS['wps_test_mails'] );
		$this->assertSame( 'alertas@example.com', $GLOBALS['wps_test_mails'][0]['to'] );
		$this->assertStringContainsString( '10.9.9.9', $GLOBALS['wps_test_mails'][0]['message'] );
	}

	public function test_rotating_within_the_same_ipv6_64_does_not_notify(): void {
		$this->notifier->track_login( $this->admin(), '2001:db8:1:2::1' );

		$this->assertFalse( $this->notifier->track_login( $this->admin(), '2001:db8:1:2:ffff::9' ) );
	}

	public function test_non_admins_are_not_tracked(): void {
		$customer = (object) array( 'ID' => 2, 'user_login' => 'cliente' );

		$this->notifier->track_login( $customer, '10.0.0.5' );
		$this->assertFalse( $this->notifier->track_login( $customer, '10.9.9.9' ) );
		$this->assertArrayNotHasKey( 2, $GLOBALS['wps_test_user_meta'] );
	}

	public function test_networks_are_recorded_even_with_the_notice_disabled(): void {
		// Así, activarlo más tarde no dispara un mail por cada red ya usada.
		$quiet = $this->notifier_with( array( 'notify_new_login_ip' => false ) );
		$quiet->track_login( $this->admin(), '10.0.0.5' );
		$quiet->track_login( $this->admin(), '10.9.9.9' );

		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
		$this->assertCount( 2, $GLOBALS['wps_test_user_meta'][1][ WPS_Admin_Notifier::KNOWN_LOGIN_META ] );
	}

	public function test_known_networks_are_capped(): void {
		for ( $i = 1; $i <= WPS_Admin_Notifier::KNOWN_LOGIN_MAX + 5; $i++ ) {
			$this->notifier->track_login( $this->admin(), '10.0.1.' . $i );
		}

		$this->assertCount(
			WPS_Admin_Notifier::KNOWN_LOGIN_MAX,
			$GLOBALS['wps_test_user_meta'][1][ WPS_Admin_Notifier::KNOWN_LOGIN_META ]
		);
	}

	private function admin(): object {
		return (object) array( 'ID' => 1, 'user_login' => 'admin' );
	}

	private function notifier_with( array $settings ): WPS_Admin_Notifier {
		$loader = ( new \ReflectionClass( 'WPS_Loader' ) )->newInstanceWithoutConstructor();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, $settings );

		$this->reset_notifier();
		return WPS_Admin_Notifier::get_instance( $loader );
	}

	private function reset_notifier(): void {
		$prop = new \ReflectionProperty( 'WPS_Admin_Notifier', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}
}
