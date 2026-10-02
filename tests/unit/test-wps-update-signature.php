<?php
/**
 * Tests de la verificación de firma de los paquetes de actualización.
 *
 * Usan un par de claves generado en el test; la criptografía es la de
 * sodium (la extensión o sodium_compat de WordPress, si está a mano).
 */

// download_url(): los contenidos los fija cada test por URL.
if ( ! function_exists( 'download_url' ) ) {
	function download_url( $url, $timeout = 300 ) {
		if ( ! isset( $GLOBALS['wps_test_downloads'][ $url ] ) ) {
			return new WP_Error( 'http_404', 'Not Found' );
		}
		$file = tempnam( sys_get_temp_dir(), 'wps' );
		file_put_contents( $file, $GLOBALS['wps_test_downloads'][ $url ] );
		$GLOBALS['wps_test_download_files'][] = $file;
		return $file;
	}
}

class Test_WPS_Update_Signature extends \PHPUnit\Framework\TestCase {

	const PACKAGE = 'https://github.com/fabiomb/wp-secure/releases/download/v9.1.0/wp-secure-9.1.0.zip';

	/** @var string */
	private $secret;

	/** @var string */
	private $public;

	public static function setUpBeforeClass(): void {
		$compat = dirname( __DIR__, 5 ) . '/wp-includes/sodium_compat/autoload.php';
		if ( ! function_exists( 'sodium_crypto_sign_keypair' ) && is_file( $compat ) ) {
			require_once $compat;
		}
	}

	protected function setUp(): void {
		if ( ! function_exists( 'sodium_crypto_sign_keypair' ) ) {
			$this->markTestSkipped( 'Sin libsodium ni sodium_compat.' );
		}

		$pair         = sodium_crypto_sign_keypair();
		$this->secret = sodium_crypto_sign_secretkey( $pair );
		$this->public = base64_encode( sodium_crypto_sign_publickey( $pair ) );

		$GLOBALS['wps_test_downloads']      = array();
		$GLOBALS['wps_test_download_files'] = array();
		$GLOBALS['wpdb']->reset_queries();
	}

	protected function tearDown(): void {
		foreach ( $GLOBALS['wps_test_download_files'] ?? array() as $file ) {
			if ( is_file( $file ) ) {
				unlink( $file );
			}
		}
		$GLOBALS['wps_test_downloads'] = array();
	}

	/*──────────────────────────────────────────────
	 * Verificación
	 *──────────────────────────────────────────────*/

	public function test_valid_signature_names_the_key(): void {
		$keys = array( 'principal' => base64_encode( random_bytes( 32 ) ), 'emergencia' => $this->public );

		$this->assertSame( 'emergencia', WPS_Updater::verify( 'contenido', $this->sign( 'contenido' ), $keys ) );
	}

	public function test_altered_content_fails(): void {
		$this->assertNull( WPS_Updater::verify( 'contenido alterado', $this->sign( 'contenido' ), array( 'principal' => $this->public ) ) );
	}

	public function test_signature_in_base64_is_accepted(): void {
		$this->assertSame( 'principal', WPS_Updater::verify( 'contenido', base64_encode( $this->sign( 'contenido' ) ) . "\n", array( 'principal' => $this->public ) ) );
	}

	public function test_garbage_signature_or_key_fails_without_errors(): void {
		$this->assertNull( WPS_Updater::verify( 'contenido', 'no es una firma', array( 'principal' => $this->public ) ) );
		$this->assertNull( WPS_Updater::verify( 'contenido', $this->sign( 'contenido' ), array( 'principal' => 'clave-rota' ) ) );
	}

	public function test_embedded_keys_are_valid_ed25519_public_keys(): void {
		foreach ( WPS_Updater::PUBLIC_KEYS as $name => $key ) {
			$this->assertSame( 32, strlen( (string) base64_decode( $key, true ) ), "Clave {$name}." );
		}
	}

	/*──────────────────────────────────────────────
	 * Descarga
	 *──────────────────────────────────────────────*/

	public function test_signed_package_is_returned_for_install(): void {
		$GLOBALS['wps_test_downloads'][ self::PACKAGE ]          = 'zip firmado';
		$GLOBALS['wps_test_downloads'][ self::PACKAGE . '.sig' ] = $this->sign( 'zip firmado' );

		$file = $this->updater()->download_verified( false, self::PACKAGE );

		$this->assertIsString( $file );
		$this->assertSame( 'zip firmado', file_get_contents( $file ) );
	}

	public function test_package_without_signature_is_rejected(): void {
		$GLOBALS['wps_test_downloads'][ self::PACKAGE ] = 'zip sin firma';

		$result = $this->updater()->download_verified( false, self::PACKAGE );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'wps_update_signature', $result->get_error_code() );
		$this->assertFileDoesNotExist( $GLOBALS['wps_test_download_files'][0], 'El zip descargado se borra.' );
		$this->assertSame( 'update_rejected', $GLOBALS['wpdb']->inserts[0][1]['event_type'] );
	}

	public function test_tampered_package_is_rejected(): void {
		$GLOBALS['wps_test_downloads'][ self::PACKAGE ]          = 'zip alterado';
		$GLOBALS['wps_test_downloads'][ self::PACKAGE . '.sig' ] = $this->sign( 'zip original' );

		$this->assertInstanceOf( WP_Error::class, $this->updater()->download_verified( false, self::PACKAGE ) );
	}

	public function test_other_packages_are_left_to_wordpress(): void {
		$this->assertFalse( $this->updater()->download_verified( false, 'https://downloads.wordpress.org/plugin/akismet.zip' ) );
		$this->assertSame( '/ya/descargado.zip', $this->updater()->download_verified( '/ya/descargado.zip', self::PACKAGE ) );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function sign( string $data ): string {
		return sodium_crypto_sign_detached( $data, $this->secret );
	}

	private function updater(): WPS_Updater {
		return new class( WPS_Loader::get_instance(), $this->public ) extends WPS_Updater {
			private $key;

			public function __construct( WPS_Loader $loader, string $key ) {
				parent::__construct( $loader );
				$this->key = $key;
			}
			protected function public_keys(): array {
				return array( 'principal' => $this->key );
			}
		};
	}
}
