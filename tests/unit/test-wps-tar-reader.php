<?php
/**
 * Tests de la extracción del .mmdb de un .tar.gz de MaxMind.
 *
 * Los archivos se generan en el test con el formato ustar.
 */
class Test_WPS_Tar_Reader extends \PHPUnit\Framework\TestCase {

	/** @var string */
	private $dir;

	protected function setUp(): void {
		$this->dir = sys_get_temp_dir() . '/wps-tar-test-' . uniqid() . '/';
		mkdir( $this->dir );
	}

	protected function tearDown(): void {
		foreach ( (array) glob( $this->dir . '*' ) as $file ) {
			@unlink( $file );
		}
		@rmdir( $this->dir );
	}

	public function test_extracts_mmdb_from_maxmind_layout(): void {
		$archive = $this->archive( array(
			array( 'GeoLite2-Country_20260101/', '', '5' ),
			array( 'GeoLite2-Country_20260101/COPYRIGHT.txt', 'Copyright', '0' ),
			array( 'GeoLite2-Country_20260101/GeoLite2-Country.mmdb', 'contenido-mmdb', '0' ),
			array( 'GeoLite2-Country_20260101/LICENSE.txt', 'licencia', '0' ),
		) );

		WPS_Tar_Reader::extract( $archive, $this->dir . 'out.mmdb', '.mmdb', 1024 );

		$this->assertSame( 'contenido-mmdb', file_get_contents( $this->dir . 'out.mmdb' ) );
	}

	public function test_extracts_member_spanning_several_blocks(): void {
		$content = str_repeat( 'abcdefgh', 200 ); // 1600 bytes: 4 bloques.
		$archive = $this->archive( array(
			array( 'a/README.txt', str_repeat( 'x', 700 ), '0' ),
			array( 'a/base.mmdb', $content, '0' ),
		) );

		WPS_Tar_Reader::extract( $archive, $this->dir . 'out.mmdb', '.mmdb', 4096 );

		$this->assertSame( $content, file_get_contents( $this->dir . 'out.mmdb' ) );
	}

	public function test_gnu_long_name_is_supported(): void {
		$long    = str_repeat( 'd', 120 ) . '/GeoLite2-ASN.mmdb';
		$archive = $this->archive( array(
			array( '././@LongLink', $long . "\0", 'L' ),
			array( substr( $long, 0, 100 ), 'asn', '0' ),
		) );

		WPS_Tar_Reader::extract( $archive, $this->dir . 'out.mmdb', '.mmdb', 1024 );

		$this->assertSame( 'asn', file_get_contents( $this->dir . 'out.mmdb' ) );
	}

	public function test_archive_without_mmdb_is_rejected(): void {
		$archive = $this->archive( array(
			array( 'GeoLite2-Country_20260101/LICENSE.txt', 'licencia', '0' ),
		) );

		$this->expectException( \RuntimeException::class );
		WPS_Tar_Reader::extract( $archive, $this->dir . 'out.mmdb', '.mmdb', 1024 );
	}

	public function test_oversized_member_is_rejected(): void {
		$archive = $this->archive( array(
			array( 'a/base.mmdb', str_repeat( 'x', 2000 ), '0' ),
		) );

		try {
			WPS_Tar_Reader::extract( $archive, $this->dir . 'out.mmdb', '.mmdb', 1024 );
			$this->fail( 'Se aceptó un archivo más grande que el máximo.' );
		} catch ( \RuntimeException $e ) {
			$this->assertFileDoesNotExist( $this->dir . 'out.mmdb' );
		}
	}

	/**
	 * @dataProvider unsafe_names
	 */
	public function test_path_traversal_is_rejected( string $name ): void {
		$archive = $this->archive( array(
			array( $name, 'malicioso', '0' ),
		) );

		$this->expectException( \RuntimeException::class );
		WPS_Tar_Reader::extract( $archive, $this->dir . 'out.mmdb', '.mmdb', 1024 );
	}

	public function unsafe_names(): array {
		return array(
			'subir de directorio' => array( '../evil.mmdb' ),
			'en el medio'         => array( 'a/../../evil.mmdb' ),
			'ruta absoluta'       => array( '/etc/evil.mmdb' ),
		);
	}

	public function test_symlink_member_is_ignored(): void {
		$archive = $this->archive( array(
			array( 'a/link.mmdb', '', '2' ),
		) );

		$this->expectException( \RuntimeException::class );
		WPS_Tar_Reader::extract( $archive, $this->dir . 'out.mmdb', '.mmdb', 1024 );
	}

	public function test_non_tar_file_is_rejected(): void {
		$path = $this->dir . 'no-tar.tar.gz';
		file_put_contents( $path, gzencode( str_repeat( 'no es un tar ', 100 ) ) );

		$this->expectException( \RuntimeException::class );
		WPS_Tar_Reader::extract( $path, $this->dir . 'out.mmdb', '.mmdb', 1024 );
	}

	/**
	 * Generar un .tar.gz con los miembros indicados.
	 *
	 * @param array[] $members [ nombre, contenido, tipo ].
	 */
	private function archive( array $members ): string {
		$tar = '';
		foreach ( $members as $member ) {
			list( $name, $content, $type ) = $member;
			$tar .= $this->header( $name, strlen( $content ), $type );
			$tar .= $content . str_repeat( "\0", ( 512 - strlen( $content ) % 512 ) % 512 );
		}
		$tar .= str_repeat( "\0", 1024 );

		$path = $this->dir . 'archivo.tar.gz';
		file_put_contents( $path, gzencode( $tar ) );
		return $path;
	}

	private function header( string $name, int $size, string $type ): string {
		$header  = str_pad( substr( $name, 0, 100 ), 100, "\0" );
		$header .= str_pad( '0000644', 8, "\0" );
		$header .= str_pad( '0000000', 8, "\0" );
		$header .= str_pad( '0000000', 8, "\0" );
		$header .= str_pad( sprintf( '%011o', $size ), 12, "\0" );
		$header .= str_pad( sprintf( '%011o', 0 ), 12, "\0" );
		$header .= str_repeat( ' ', 8 ); // Checksum provisorio.
		$header .= $type;
		$header .= str_repeat( "\0", 100 );
		$header .= "ustar\0" . '00';
		$header  = str_pad( $header, 512, "\0" );

		$checksum = 0;
		for ( $i = 0; $i < 512; $i++ ) {
			$checksum += ord( $header[ $i ] );
		}

		return substr_replace( $header, sprintf( "%06o\0 ", $checksum ), 148, 8 );
	}
}
