<?php
/**
 * Tests unitarios para WPS_Crawler_Verifier.
 */
class Test_WPS_Crawler_Verifier extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $fixtures;

	protected function setUp(): void {
		$this->fixtures = require dirname( __DIR__ ) . '/fixtures/ips.php';
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
	 * Verify (depende de DNS, puede fallar offline)
	 *──────────────────────────────────────────────*/

	public function test_verify_non_crawler_returns_unknown(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		$result   = $verifier->verify( '8.8.8.8', 'Mozilla/5.0 Normal Browser' );
		$this->assertEquals( WPS_Crawler_Verifier::RESULT_UNKNOWN, $result );
	}

	public function test_verify_spoofed_googlebot(): void {
		$verifier = WPS_Crawler_Verifier::get_instance();
		// Una IP aleatoria con UA de Googlebot → debería ser spoofed.
		$result = $verifier->verify( '203.0.113.50', $this->fixtures['crawler_uas']['googlebot'] );
		$this->assertEquals( WPS_Crawler_Verifier::RESULT_SPOOFED, $result );
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
	}
}
