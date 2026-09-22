<?php
/**
 * Tests de las notificaciones de cambios de configuración y del resumen de
 * bloqueos automáticos.
 *
 * Ambas existían con su ajuste en el panel, pero nada las invocaba.
 */
class Test_WPS_Notifications extends \PHPUnit\Framework\TestCase {

	protected function setUp(): void {
		$GLOBALS['wps_test_mails']   = array();
		$GLOBALS['wps_test_options'] = array();
		$GLOBALS['wpdb']->reset_queries();
		$this->set_settings( array(
			'notify_auto_blocks'     => true,
			'notify_settings_change' => true,
			'notify_email'           => 'alertas@example.com',
		) );
	}

	protected function tearDown(): void {
		$this->set_settings( array() );
		$GLOBALS['wps_test_options'] = array();
	}

	/*──────────────────────────────────────────────
	 * Resumen de bloqueos automáticos
	 *──────────────────────────────────────────────*/

	public function test_automatic_blocks_are_queued_not_mailed(): void {
		$blocker = WPS_Blocker::get_instance();
		$blocker->block_ip( '45.33.32.156', 'auto_sqli', 'SQLi', 15 );
		$blocker->block_ip( '45.33.32.157', 'auto_rate', 'Rate limit', 15 );

		$this->assertCount( 0, $GLOBALS['wps_test_mails'], 'Un mail por bloqueo inunda el correo durante un ataque.' );
		$this->assertSame( 2, $GLOBALS['wps_test_options'][ WPS_Blocker::DIGEST_OPTION ]['count'] );
	}

	public function test_ipv6_network_blocks_are_queued(): void {
		WPS_Blocker::get_instance()->block_offender( '2001:db8:1:2::1', 'auto_xss', 'XSS', 15 );

		$items = $GLOBALS['wps_test_options'][ WPS_Blocker::DIGEST_OPTION ]['items'];
		$this->assertSame( '2001:db8:1:2::/64', $items[0]['target'] );
	}

	public function test_manual_blocks_are_not_queued(): void {
		WPS_Blocker::get_instance()->block_ip( '45.33.32.156', 'manual', 'Manual' );

		$this->assertArrayNotHasKey( WPS_Blocker::DIGEST_OPTION, $GLOBALS['wps_test_options'] );
	}

	public function test_nothing_is_queued_with_the_notice_disabled(): void {
		$this->set_settings( array( 'notify_auto_blocks' => false ) );

		WPS_Blocker::get_instance()->block_ip( '45.33.32.156', 'auto_sqli', 'SQLi', 15 );

		$this->assertArrayNotHasKey( WPS_Blocker::DIGEST_OPTION, $GLOBALS['wps_test_options'] );
	}

	public function test_digest_sends_one_mail_and_empties_the_queue(): void {
		$blocker = WPS_Blocker::get_instance();
		$blocker->block_ip( '45.33.32.156', 'auto_sqli', 'SQLi', 15 );
		$blocker->block_ip( '45.33.32.157', 'auto_login', 'Login', null );

		$this->assertTrue( $this->notifier()->send_block_digest() );

		$this->assertCount( 1, $GLOBALS['wps_test_mails'] );
		$mail = $GLOBALS['wps_test_mails'][0];
		$this->assertStringContainsString( '45.33.32.156', $mail['message'] );
		$this->assertStringContainsString( 'permanente', $mail['message'] );
		$this->assertArrayNotHasKey( WPS_Blocker::DIGEST_OPTION, $GLOBALS['wps_test_options'] );
	}

	public function test_empty_queue_sends_nothing(): void {
		$this->assertFalse( $this->notifier()->send_block_digest() );
		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	public function test_digest_details_are_capped_but_all_blocks_are_counted(): void {
		$blocker = WPS_Blocker::get_instance();
		$total   = WPS_Blocker::DIGEST_MAX_ITEMS + 7;
		for ( $i = 0; $i < $total; $i++ ) {
			$blocker->block_ip( '45.33.' . intdiv( $i, 250 ) . '.' . ( $i % 250 + 1 ), 'auto_rate', 'Rate', 15 );
		}

		$digest = $GLOBALS['wps_test_options'][ WPS_Blocker::DIGEST_OPTION ];
		$this->assertSame( $total, $digest['count'] );
		$this->assertCount( WPS_Blocker::DIGEST_MAX_ITEMS, $digest['items'] );

		$this->notifier()->send_block_digest();
		$this->assertStringContainsString( 'y 7 más', $GLOBALS['wps_test_mails'][0]['message'] );
	}

	/*──────────────────────────────────────────────
	 * Cambios de configuración
	 *──────────────────────────────────────────────*/

	public function test_settings_change_notice_describes_the_change(): void {
		$this->assertTrue( $this->notifier()->notify_settings_change( 1, 'Modo Inseguro activado' ) );

		$mail = $GLOBALS['wps_test_mails'][0];
		$this->assertStringContainsString( 'Modo Inseguro activado', $mail['subject'] );
		$this->assertStringContainsString( 'Admin de prueba', $mail['message'] );
	}

	public function test_settings_change_notice_respects_its_setting(): void {
		$this->set_settings( array( 'notify_settings_change' => false ) );

		$this->assertFalse( $this->notifier()->notify_settings_change( 1 ) );
		$this->assertCount( 0, $GLOBALS['wps_test_mails'] );
	}

	private function notifier(): WPS_Admin_Notifier {
		$prop = new \ReflectionProperty( 'WPS_Admin_Notifier', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );

		return WPS_Admin_Notifier::get_instance( WPS_Loader::get_instance() );
	}

	/**
	 * Fijar los settings del loader singleton, que es el que usa WPS_Blocker.
	 */
	private function set_settings( array $settings ): void {
		$cache = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( WPS_Loader::get_instance(), $settings );
	}
}
