<?php
/**
 * Tests unitarios para WPS_Crawler_Verifier.
 */
class Test_WPS_Crawler_Verifier extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $fixtures;

	protected function setUp(): void {
		$this->fixtures = require dirname( __DIR__ ) . '/fixtures/ips.php';
		$GLOBALS['wps_test_transients'] = array();
	}

	protected function tearDown(): void {
		WPS_Crawler_Verifier::get_instance()->set_resolver( null );
		$GLOBALS['wps_test_transients'] = array();
	}

	/*──────────────────────────────────────────────
	 * Identificación de UA
	 *──────────────────────────────────────────────*/

	public function test_identify_googlebot_ua(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$ua       = $this->fixtures['crawler_uas']['googlebot'];
		$this->assertEquals( 'googlebot', $verifier->identify_crawler_ua( $ua ) );
	}

	public function test_identify_bingbot_ua(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$ua       = $this->fixtures['crawler_uas']['bingbot'];
		$this->assertEquals( 'bingbot', $verifier->identify_crawler_ua( $ua ) );
	}

	public function test_identify_yandexbot_ua(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$ua       = $this->fixtures['crawler_uas']['yandexbot'];
		$this->assertEquals( 'yandexbot', $verifier->identify_crawler_ua( $ua ) );
	}

	public function test_identify_normal_ua_returns_null(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$ua       = $this->fixtures['crawler_uas']['normal'];
		$this->assertNull( $verifier->identify_crawler_ua( $ua ) );
	}

	public function test_identify_genuine_facebookbot_ua(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$ua       = $this->fixtures['crawler_uas']['facebookbot'];
		$this->assertEquals( 'facebookbot', $verifier->identify_crawler_ua( $ua ) );
	}

	public function test_ios_safari_with_appended_bot_tokens_not_treated_as_crawler(): void {
		// Navegador real de iOS/Safari que anexa "facebookexternalhit Facebot
		// Twitterbot" al final NO debe identificarse como crawler (falso positivo
		// que bloqueaba visitantes legítimos).
		$verifier = WPS_Crawler_Verifier::get_instance();
		$ua       = $this->fixtures['crawler_uas']['ios_safari_appended_bots'];
		$this->assertNull( $verifier->identify_crawler_ua( $ua ) );
		$this->assertEquals(
			WPS_Crawler_Verifier::RESULT_UNKNOWN,
			$verifier->verify( '203.0.113.50', $ua )
		);
	}

	public function test_identify_empty_ua_returns_null(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$this->assertNull( $verifier->identify_crawler_ua( '' ) );
	}

	/*──────────────────────────────────────────────
	 * Verify (con un resolver DNS falso, sin red)
	 *──────────────────────────────────────────────*/

	public function test_verify_non_crawler_returns_unknown(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$result   = $verifier->verify( '8.8.8.8', 'Mozilla/5.0 Normal Browser' );
		$this->assertEquals( WPS_Crawler_Verifier::RESULT_UNKNOWN, $result );
	}

	public function test_real_googlebot_over_ipv4_is_legitimate(): void {
		$this->use_dns(
			array( '66.249.66.1' => array( 'crawl-66-249-66-1.googlebot.com' ) ),
			array( 'crawl-66-249-66-1.googlebot.com' => array( '66.249.66.1' ) )
		);

		$this->assertEquals( WPS_Crawler_Verifier::RESULT_LEGITIMATE, $this->verify_googlebot( '66.249.66.1' ) );
	}

	public function test_real_googlebot_over_ipv6_is_legitimate(): void {
		// El forward trae A y AAAA; antes sólo se comparaba la IPv4.
		$this->use_dns(
			array( '2001:4860:4801:10::1' => array( 'crawl-2001-4860-4801-10--1.googlebot.com' ) ),
			array( 'crawl-2001-4860-4801-10--1.googlebot.com' => array( '66.249.66.1', '2001:4860:4801:0010:0000:0000:0000:0001' ) )
		);

		$this->assertEquals( WPS_Crawler_Verifier::RESULT_LEGITIMATE, $this->verify_googlebot( '2001:4860:4801:10::1' ) );
	}

	public function test_dns_failure_on_ptr_is_not_spoofing(): void {
		$this->use_dns( null, array() );

		$this->assertEquals(
			WPS_Crawler_Verifier::RESULT_UNVERIFIED,
			$this->verify_googlebot( '66.249.66.1' ),
			'Un timeout de DNS no prueba que el crawler sea falso.'
		);
	}

	public function test_dns_failure_on_forward_is_not_spoofing(): void {
		$this->use_dns(
			array( '66.249.66.1' => array( 'crawl-66-249-66-1.googlebot.com' ) ),
			null
		);

		$this->assertEquals( WPS_Crawler_Verifier::RESULT_UNVERIFIED, $this->verify_googlebot( '66.249.66.1' ) );
	}

	public function test_ip_without_ptr_is_spoofed(): void {
		$this->use_dns( array( '203.0.113.50' => array() ), array() );

		$this->assertEquals( WPS_Crawler_Verifier::RESULT_SPOOFED, $this->verify_googlebot( '203.0.113.50' ) );
	}

	public function test_ptr_outside_crawler_domains_is_spoofed(): void {
		$this->use_dns(
			array( '203.0.113.50' => array( 'crawl.evilgooglebot.com' ) ),
			array( 'crawl.evilgooglebot.com' => array( '203.0.113.50' ) )
		);

		$this->assertEquals( WPS_Crawler_Verifier::RESULT_SPOOFED, $this->verify_googlebot( '203.0.113.50' ) );
	}

	public function test_forged_ptr_that_does_not_resolve_back_is_spoofed(): void {
		// El dueño de una IP puede poner cualquier PTR; el forward lo desmiente.
		$this->use_dns(
			array( '203.0.113.50' => array( 'crawl-66-249-66-1.googlebot.com' ) ),
			array( 'crawl-66-249-66-1.googlebot.com' => array( '66.249.66.1' ) )
		);

		$this->assertEquals( WPS_Crawler_Verifier::RESULT_SPOOFED, $this->verify_googlebot( '203.0.113.50' ) );
	}

	public function test_arpa_names(): void {
		$this->assertEquals( '1.66.249.66.in-addr.arpa', WPS_Crawler_Verifier::arpa_name( '66.249.66.1' ) );
		$this->assertEquals(
			'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.1.0.8.4.0.6.8.4.1.0.0.2.ip6.arpa',
			WPS_Crawler_Verifier::arpa_name( '2001:4860:4801:10::1' )
		);
		$this->assertNull( WPS_Crawler_Verifier::arpa_name( 'no-es-ip' ) );
	}

	/**
	 * Instalar un resolver falso.
	 *
	 * @param array|null $ptr     IP => hostnames, o null para simular un fallo.
	 * @param array|null $forward Host => IPs, o null para simular un fallo.
	 */
	private function use_dns( ?array $ptr, ?array $forward ): void {
		WPS_Crawler_Verifier::get_instance()->set_resolver( new class( $ptr, $forward ) {
			private $ptr;
			private $forward;

			public function __construct( $ptr, $forward ) {
				$this->ptr     = $ptr;
				$this->forward = $forward;
			}

			public function ptr( string $ip ): ?array {
				return null === $this->ptr ? null : ( $this->ptr[ $ip ] ?? array() );
			}

			public function forward( string $host ): ?array {
				return null === $this->forward ? null : ( $this->forward[ $host ] ?? array() );
			}
		} );
	}

	private function verify_googlebot( string $ip ): string {
		return WPS_Crawler_Verifier::get_instance()->verify( $ip, $this->fixtures['crawler_uas']['googlebot'] );
	}

	/*──────────────────────────────────────────────
	 * Known crawler IDs
	 *──────────────────────────────────────────────*/

	public function test_get_known_crawler_ids(): void {
		$ids = WPS_Crawler_Verifier::get_known_crawler_ids();
		$this->assertContains( 'googlebot', $ids );
		$this->assertContains( 'bingbot', $ids );
		$this->assertContains( 'yandexbot', $ids );
		$this->assertContains( 'applebot', $ids );
	}

	/*──────────────────────────────────────────────
	 * Constants
	 *──────────────────────────────────────────────*/

	public function test_result_constants(): void {
		$this->assertEquals( 'legitimate', WPS_Crawler_Verifier::RESULT_LEGITIMATE );
		$this->assertEquals( 'spoofed', WPS_Crawler_Verifier::RESULT_SPOOFED );
		$this->assertEquals( 'unknown', WPS_Crawler_Verifier::RESULT_UNKNOWN );
		$this->assertEquals( 'unverified', WPS_Crawler_Verifier::RESULT_UNVERIFIED );
	}
}
