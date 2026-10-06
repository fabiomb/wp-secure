<?php
/**
 * Tests del mapeo de registros de MaxMind GeoLite2.
 *
 * País y ASN vienen en bases separadas (o juntos en el servicio web City);
 * el resultado tiene que tener la misma forma que el de ipinfo.io.
 */
class Test_WPS_Ipdb_Maxmind extends \PHPUnit\Framework\TestCase {

	private function country_record(): array {
		return array(
			'continent'          => array( 'code' => 'SA' ),
			'country'            => array( 'iso_code' => 'AR', 'names' => array( 'en' => 'Argentina', 'es' => 'Argentina' ) ),
			'registered_country' => array( 'iso_code' => 'AR', 'names' => array( 'en' => 'Argentina' ) ),
		);
	}

	private function asn_record(): array {
		return array(
			'autonomous_system_number'       => 7303,
			'autonomous_system_organization' => 'Telecom Argentina S.A.',
		);
	}

	public function test_local_records_are_merged(): void {
		$result = WPS_Ipdb_Maxmind::map_local( $this->country_record(), $this->asn_record() );

		$this->assertSame(
			array(
				'country'      => 'AR',
				'country_name' => 'Argentina',
				'asn'          => 7303,
				'asn_name'     => 'Telecom Argentina S.A.',
			),
			$result
		);
	}

	public function test_missing_asn_database_keeps_country(): void {
		$result = WPS_Ipdb_Maxmind::map_local( $this->country_record(), null );

		$this->assertSame( 'AR', $result['country'] );
		$this->assertNull( $result['asn'] );
		$this->assertNull( $result['asn_name'] );
	}

	public function test_missing_country_database_keeps_asn(): void {
		$result = WPS_Ipdb_Maxmind::map_local( null, $this->asn_record() );

		$this->assertNull( $result['country'] );
		$this->assertSame( 7303, $result['asn'] );
	}

	public function test_registered_country_is_used_when_country_is_missing(): void {
		$result = WPS_Ipdb_Maxmind::map_local(
			array( 'registered_country' => array( 'iso_code' => 'us', 'names' => array( 'en' => 'United States' ) ) ),
			null
		);

		$this->assertSame( 'US', $result['country'] );
		$this->assertSame( 'United States', $result['country_name'] );
	}

	public function test_api_city_response_is_mapped(): void {
		$json = '{"city":{"names":{"en":"Buenos Aires"}},'
			. '"country":{"iso_code":"AR","names":{"en":"Argentina"}},'
			. '"traits":{"autonomous_system_number":7303,"autonomous_system_organization":"Telecom Argentina S.A.","ip_address":"181.1.1.1","network":"181.0.0.0/12"}}';

		$result = WPS_Ipdb_Maxmind::map_api( json_decode( $json, true ) );

		$this->assertSame( 'AR', $result['country'] );
		$this->assertSame( 'Argentina', $result['country_name'] );
		$this->assertSame( 7303, $result['asn'] );
		$this->assertSame( 'Telecom Argentina S.A.', $result['asn_name'] );
	}

	public function test_api_response_without_traits_has_no_asn(): void {
		$result = WPS_Ipdb_Maxmind::map_api( array( 'country' => array( 'iso_code' => 'BR' ) ) );

		$this->assertSame( 'BR', $result['country'] );
		$this->assertNull( $result['country_name'] );
		$this->assertNull( $result['asn'] );
	}

	public function test_auth_header_is_basic(): void {
		$this->assertSame( 'Basic ' . base64_encode( '42:abc' ), WPS_Ipdb_Maxmind::auth_header( '42', 'abc' ) );
	}

	public function test_download_errors_are_explained(): void {
		$this->assertStringContainsString( 'credenciales', WPS_Ipdb_Updater::explain_maxmind_error( 401 ) );
		$this->assertStringContainsString( 'License Key', WPS_Ipdb_Updater::explain_maxmind_error( 403 ) );
		$this->assertStringContainsString( 'limitó', WPS_Ipdb_Updater::explain_maxmind_error( 429 ) );
		$this->assertStringContainsString( '500', WPS_Ipdb_Updater::explain_maxmind_error( 500 ) );
	}
}
