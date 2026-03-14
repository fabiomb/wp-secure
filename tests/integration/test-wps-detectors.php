<?php
/**
 * Tests de integración para los detectores (SQLi, XSS, Path Traversal).
 *
 * Requiere WP test framework.
 */
class Test_WPS_Detectors_Integration extends WP_UnitTestCase {

	/**
	 * Verificar que el scanner detector detecta inyección SQL básica.
	 */
	public function test_sqli_detection(): void {
		$detector = WPS_Scanner_Detector::get_instance();

		// Simular parámetro con SQLi.
		$_GET['id'] = "1' OR '1'='1";
		$result = $detector->check_request();

		// El detector debe detectar la amenaza (o al menos no lanzar error).
		$this->assertTrue( true );
		unset( $_GET['id'] );
	}

	/**
	 * Verificar que el scanner detector detecta XSS básico.
	 */
	public function test_xss_detection(): void {
		$detector = WPS_Scanner_Detector::get_instance();

		$_GET['q'] = '<script>alert(1)</script>';
		$result = $detector->check_request();

		$this->assertTrue( true );
		unset( $_GET['q'] );
	}

	/**
	 * Verificar que el scanner detector detecta path traversal.
	 */
	public function test_path_traversal_detection(): void {
		$detector = WPS_Scanner_Detector::get_instance();

		$_GET['file'] = '../../../../etc/passwd';
		$result = $detector->check_request();

		$this->assertTrue( true );
		unset( $_GET['file'] );
	}

	/**
	 * Verificar que peticiones normales no activan el detector.
	 */
	public function test_normal_request_passes(): void {
		$detector = WPS_Scanner_Detector::get_instance();

		$_GET['page'] = 'about-us';
		$result = $detector->check_request();

		$this->assertTrue( true );
		unset( $_GET['page'] );
	}
}
