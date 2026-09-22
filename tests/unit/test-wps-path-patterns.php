<?php
/**
 * Tests de los patrones de ruta: scanner y path traversal.
 *
 * Igual que con SQLi y XSS, un falso positivo bloquea la IP del visitante.
 * Acá el riesgo es mayor: una URL de post o una búsqueda la repite cualquier
 * visitante, así que un patrón demasiado amplio bloquea a todo el tráfico que
 * llega a esa página.
 */
class Test_WPS_Path_Patterns extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * Scanner — rutas legítimas
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider legitimate_paths
	 */
	public function test_scanner_ignores_legitimate_paths( string $path ): void {
		$this->assertNull(
			WPS_Scanner_Detector::match_scanner_path( $path ),
			"Ruta legítima marcada como sonda de scanner: {$path}"
		);
	}

	public function legitimate_paths(): array {
		return array(
			'post sobre mysql'       => array( '/2024/05/mysql-vs-postgresql/' ),
			'post sobre managers'    => array( '/blog/manager-de-contenidos/' ),
			'post sobre phpmyadmin'  => array( '/como-instalar-phpmyadmin-en-ubuntu/' ),
			'admin de wordpress'     => array( '/wp-admin/admin.php' ),
			'admin en subdirectorio' => array( '/wordpress/wp-admin/admin.php' ),
			'pagina administradores' => array( '/administradores/' ),
		);
	}

	/*──────────────────────────────────────────────
	 * Scanner — sondas reales
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider scanner_probes
	 */
	public function test_scanner_detects_real_probes( string $path ): void {
		$this->assertNotNull(
			WPS_Scanner_Detector::match_scanner_path( $path ),
			"Sonda de scanner no detectada: {$path}"
		);
	}

	public function scanner_probes(): array {
		return array(
			'phpmyadmin'        => array( '/phpmyadmin/' ),
			'phpmyadmin index'  => array( '/phpMyAdmin/index.php' ),
			'pma'               => array( '/pma/' ),
			'mysql sin barra'   => array( '/mysql' ),
			'joomla admin'      => array( '/administrator/' ),
			'tomcat manager'    => array( '/manager/html' ),
			'admin.php suelto'  => array( '/admin.php' ),
			'shell'             => array( '/wp-content/uploads/c99.php' ),
			'dotenv'            => array( '/.env' ),
			'cgi-bin'           => array( '/cgi-bin/test.cgi' ),
			'backup'            => array( '/backup.zip' ),
		);
	}

	/*──────────────────────────────────────────────
	 * Path traversal — texto libre legítimo
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider legitimate_free_text
	 */
	public function test_traversal_ignores_file_mentions_in_free_text( string $text ): void {
		$this->assertNull(
			WPS_Path_Traversal_Detector::detect_in_value( $text ),
			"Texto legítimo marcado como path traversal: {$text}"
		);
	}

	public function legitimate_free_text(): array {
		return array(
			'busqueda htaccess'   => array( 's=como+editar+el+.htaccess' ),
			'comentario config'   => array( 'Mi wp-config.php no carga después de migrar' ),
			'archivo zip'         => array( 'database tips for wordpress.zip' ),
			'package json'        => array( 'Actualicé el package.json y composer.lock' ),
			'archivo env'         => array( 'Guardá la clave en el archivo .env' ),
			'error log'           => array( 'Revisá el error_log del hosting' ),
			'volcado sql'         => array( 'Te paso el dump.sql por mail' ),
		);
	}

	/*──────────────────────────────────────────────
	 * Path traversal — ataques reales
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider traversal_values
	 */
	public function test_traversal_detects_attacks_in_values( string $value ): void {
		$this->assertNotNull(
			WPS_Path_Traversal_Detector::detect_in_value( $value ),
			"Ataque no detectado en un valor: {$value}"
		);
	}

	public function traversal_values(): array {
		return array(
			'recorrido simple'   => array( 'file=../../../wp-config.php' ),
			'recorrido encodeado' => array( 'file=..%2f..%2f..%2fetc%2fpasswd' ),
			'doble encoding'     => array( 'file=%252e%252e%252f%252e%252e%252fetc' ),
			'etc passwd'         => array( 'page=/etc/passwd' ),
			'environ'            => array( 'inc=/proc/self/environ' ),
			'null byte'          => array( 'file=imagen.jpg%00.php' ),
		);
	}

	/**
	 * @dataProvider sensitive_paths
	 */
	public function test_traversal_detects_requests_for_sensitive_files( string $path ): void {
		$this->assertNotNull(
			WPS_Path_Traversal_Detector::detect_in_path( $path ),
			"Petición a un archivo sensible no detectada: {$path}"
		);
	}

	public function sensitive_paths(): array {
		return array(
			'wp-config'      => array( '/wp-config.php' ),
			'copia config'   => array( '/wp-config.php.bak' ),
			'htaccess'       => array( '/.htaccess' ),
			'debug log'      => array( '/wp-content/debug.log' ),
			'repo git'       => array( '/.git/config' ),
			'volcado sql'    => array( '/dump.sql' ),
			'backup zip'     => array( '/backup-2026.zip' ),
			'composer'       => array( '/composer.json' ),
		);
	}

	public function test_traversal_ignores_ordinary_post_paths(): void {
		$this->assertNull( WPS_Path_Traversal_Detector::detect_in_path( '/2026/05/backup-de-la-base-de-datos/' ) );
		$this->assertNull( WPS_Path_Traversal_Detector::detect_in_path( '/tutorial-sql-para-principiantes/' ) );
	}
}
