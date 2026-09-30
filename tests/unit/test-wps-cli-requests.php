<?php
/**
 * Tests de la exención de consola y del propio servidor en las reglas de
 * métodos, User-Agent y Host (WP-CLI sin --url no define HTTP_HOST).
 */
class Test_WPS_Cli_Requests extends \PHPUnit\Framework\TestCase {

	/** @var array */
	private $server;

	protected function setUp(): void {
		$this->server = $_SERVER;
		unset( $_SERVER['SERVER_ADDR'], $_SERVER['LOCAL_ADDR'] );
	}

	protected function tearDown(): void {
		$_SERVER = $this->server;
		$this->set_cli( null );
	}

	public function test_phpunit_itself_runs_from_the_console(): void {
		$this->assertTrue( WPS_Request::is_cli() );
	}

	public function test_console_is_exempt_whatever_the_ip(): void {
		$this->set_cli( true );

		$this->assertTrue( WPS_Security_Hardener::is_exempt( '127.0.0.1' ) );
		$this->assertTrue( WPS_Security_Hardener::is_exempt( '0.0.0.0' ), 'Sin REMOTE_ADDR la IP queda en 0.0.0.0.' );
	}

	public function test_web_request_from_the_server_itself_is_exempt(): void {
		$this->set_cli( false );

		$this->assertTrue( WPS_Security_Hardener::is_exempt( '127.0.0.1' ) );
		$this->assertTrue( WPS_Security_Hardener::is_exempt( '::1' ) );
	}

	public function test_web_request_from_a_visitor_is_checked(): void {
		$this->set_cli( false );

		$this->assertFalse( WPS_Security_Hardener::is_exempt( '203.0.113.9' ) );
	}

	private function set_cli( ?bool $value ): void {
		$cli = new \ReflectionProperty( 'WPS_Request', 'cli' );
		$cli->setAccessible( true );
		$cli->setValue( null, $value );
	}
}
