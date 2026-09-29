<?php
/**
 * Tests de WPS_Request::body_values(): lo que los detectores analizan del
 * cuerpo de la petición.
 *
 * Antes sólo se analizaba $_POST, así que un cuerpo JSON (REST API, muchos
 * plugins) pasaba sin revisar.
 */
class Test_WPS_Request_Body extends \PHPUnit\Framework\TestCase {

	private $server_backup;
	private $post_backup;

	protected function setUp(): void {
		$this->server_backup = $_SERVER;
		$this->post_backup   = $_POST;
		$_POST               = array();
	}

	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$_POST   = $this->post_backup;
		$this->set_raw_body( null );
		$this->reset_request();
	}

	public function test_json_body_values_are_collected(): void {
		$values = $this->body( 'POST', 'application/json', '{"search":"hola","filters":{"tags":["a","b"]},"page":2}' );

		$this->assertSame( array( 'hola', 'a', 'b' ), $values );
	}

	public function test_sql_injection_in_json_is_detected(): void {
		$values = $this->body( 'POST', 'application/json; charset=utf-8', '{"search":"1 UNION SELECT user_pass FROM wp_users"}' );

		$this->assertNotNull( $this->first_detection( $values, array( 'WPS_Sqli_Detector', 'detect' ) ) );
	}

	public function test_xss_in_json_is_detected(): void {
		$values = $this->body( 'PUT', 'application/json', '{"content":"<script>alert(1)</script>"}' );

		$this->assertNotNull( $this->first_detection( $values, array( 'WPS_Xss_Detector', 'detect' ) ) );
	}

	public function test_vendor_json_content_types_are_parsed(): void {
		$values = $this->body( 'PATCH', 'application/merge-patch+json', '{"title":"x"}' );

		$this->assertSame( array( 'x' ), $values );
	}

	public function test_form_body_of_put_is_parsed(): void {
		// PHP sólo llena $_POST en POST.
		$values = $this->body( 'PUT', 'application/x-www-form-urlencoded', 'title=hola&content=%3Cscript%3E' );

		$this->assertSame( array( 'hola', '<script>' ), $values );
	}

	public function test_post_values_are_still_collected(): void {
		$_POST = array( 'comment' => 'texto', 'meta' => array( 'k' => 'v' ) );

		$this->assertSame( array( 'texto', 'v' ), $this->body( 'POST', 'multipart/form-data; boundary=x', '' ) );
	}

	public function test_get_requests_ignore_the_body(): void {
		$this->assertSame( array(), $this->body( 'GET', 'application/json', '{"a":"b"}' ) );
	}

	public function test_invalid_json_is_analyzed_as_text(): void {
		$values = $this->body( 'POST', 'application/json', '{"q":"1\' OR \'1\'=\'1"' );

		$this->assertCount( 1, $values );
		$this->assertNotNull( $this->first_detection( $values, array( 'WPS_Sqli_Detector', 'detect' ) ) );
	}

	public function test_oversized_json_is_analyzed_as_truncated_text(): void {
		$payload = '{"pad":"' . str_repeat( 'a', WPS_Request::BODY_MAX_BYTES ) . '","q":"x"}';

		$values = $this->body( 'POST', 'application/json', $payload );

		$this->assertCount( 1, $values );
		$this->assertSame( WPS_Request::BODY_MAX_BYTES, strlen( $values[0] ) );
	}

	public function test_padding_with_many_values_does_not_hide_a_payload(): void {
		$data        = array_fill( 0, WPS_Request::BODY_MAX_VALUES + 50, 'relleno' );
		$data['ult'] = '1 UNION SELECT user_pass FROM wp_users';

		$values = $this->body( 'POST', 'application/json', json_encode( $data ) );

		$this->assertCount( WPS_Request::BODY_MAX_VALUES + 1, $values );
		$this->assertNotNull(
			$this->first_detection( $values, array( 'WPS_Sqli_Detector', 'detect' ) ),
			'Un payload después de miles de valores basura tiene que analizarse igual.'
		);
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function body( string $method, string $content_type, string $raw ): array {
		$_SERVER['REQUEST_METHOD'] = $method;
		$_SERVER['REQUEST_URI']    = '/wp-json/wp/v2/posts';
		$_SERVER['REMOTE_ADDR']    = '45.33.32.156';
		$_SERVER['CONTENT_TYPE']   = $content_type;
		$this->set_raw_body( $raw );
		$this->reset_request();

		return WPS_Request::get_instance()->body_values();
	}

	private function first_detection( array $values, callable $detector ): ?string {
		foreach ( $values as $value ) {
			$match = $detector( $value );
			if ( $match ) {
				return $match;
			}
		}
		return null;
	}

	private function set_raw_body( ?string $raw ): void {
		$prop = new \ReflectionProperty( 'WPS_Request', 'raw_body' );
		$prop->setAccessible( true );
		$prop->setValue( null, $raw );
	}

	private function reset_request(): void {
		$prop = new \ReflectionProperty( 'WPS_Request', 'instance' );
		$prop->setAccessible( true );
		$prop->setValue( null, null );
	}
}
