<?php
/**
 * Tests del monitor de integridad de archivos.
 *
 * Los contenidos de prueba son inocuos a propósito: un archivo de test con
 * la firma de un webshell lo bloquea el antivirus del equipo de desarrollo.
 */
class Test_WPS_File_Integrity extends \PHPUnit\Framework\TestCase {

	/** @var string */
	private $dir;

	/** @var WPS_Integrity_Store */
	private $store;

	/** @var WPS_File_Integrity */
	private $integrity;

	protected function setUp(): void {
		$this->dir = str_replace( '\\', '/', sys_get_temp_dir() ) . '/wps-integrity-' . uniqid();
		mkdir( $this->dir . '/plugin/sub', 0777, true );
		file_put_contents( $this->dir . '/plugin/main.php', '<?php // original' );
		file_put_contents( $this->dir . '/plugin/sub/helper.php', '<?php // helper' );
		file_put_contents( $this->dir . '/plugin/readme.txt', 'no se vigila' );

		$GLOBALS['wps_test_options'] = array();
		$GLOBALS['wps_test_mails']   = array();

		$this->store     = $this->memory_store();
		$this->integrity = new WPS_File_Integrity( $this->loader(), $this->store );
		$this->integrity->set_areas( array( 'plugin:demo' => array( array( $this->dir . '/plugin', true ) ) ) );
	}

	protected function tearDown(): void {
		$files = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $this->dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $files as $file ) {
			$file->isDir() ? rmdir( $file->getPathname() ) : unlink( $file->getPathname() );
		}
		rmdir( $this->dir );
		$GLOBALS['wps_test_options'] = array();
	}

	/*──────────────────────────────────────────────
	 * Detección
	 *──────────────────────────────────────────────*/

	public function test_first_scan_only_takes_the_baseline(): void {
		$this->assertSame( array(), $this->scan() );
		$this->assertCount( 2, $this->store->rows, 'Sólo se vigilan archivos de código (.php), no el readme.' );
	}

	public function test_modified_added_and_deleted_files_are_reported(): void {
		$this->scan();

		file_put_contents( $this->dir . '/plugin/main.php', '<?php // contenido alterado' );
		file_put_contents( $this->dir . '/plugin/sub/nuevo.php', '<?php // archivo que no estaba' );
		unlink( $this->dir . '/plugin/sub/helper.php' );

		$changes = array_column( $this->scan(), 'status', 'path' );

		$this->assertSame( 'modified', $changes[ $this->dir . '/plugin/main.php' ] );
		$this->assertSame( 'added', $changes[ $this->dir . '/plugin/sub/nuevo.php' ] );
		$this->assertSame( 'deleted', $changes[ $this->dir . '/plugin/sub/helper.php' ] );
	}

	public function test_content_change_is_detected_even_if_the_date_is_restored(): void {
		$this->scan();
		$file  = $this->dir . '/plugin/main.php';
		$mtime = filemtime( $file );

		file_put_contents( $file, '<?php // alterado' );
		touch( $file, $mtime );

		$this->assertCount( 1, $this->scan(), 'El malware suele restaurar la fecha de modificación.' );
	}

	public function test_changes_are_reported_only_once(): void {
		$this->scan();
		file_put_contents( $this->dir . '/plugin/main.php', '<?php // cambio' );

		$this->assertCount( 1, $this->scan() );
		$this->assertCount( 0, $this->scan() );
		$this->assertCount( 1, $this->integrity->changes(), 'Sigue pendiente de revisión.' );
	}

	public function test_restored_file_is_no_longer_a_change(): void {
		$this->scan();
		file_put_contents( $this->dir . '/plugin/main.php', '<?php // cambio' );
		$this->scan();

		file_put_contents( $this->dir . '/plugin/main.php', '<?php // original' );
		$this->scan();

		$this->assertSame( array(), $this->integrity->changes() );
	}

	public function test_skipped_directories_are_not_watched(): void {
		mkdir( $this->dir . '/plugin/node_modules/x', 0777, true );
		file_put_contents( $this->dir . '/plugin/node_modules/x/build.php', '<?php' );

		$this->scan();

		$this->assertCount( 2, $this->store->rows );
	}

	/*──────────────────────────────────────────────
	 * Aceptar y nueva referencia
	 *──────────────────────────────────────────────*/

	public function test_accepted_changes_become_the_baseline(): void {
		$this->scan();
		file_put_contents( $this->dir . '/plugin/main.php', '<?php // cambio legítimo' );
		unlink( $this->dir . '/plugin/sub/helper.php' );
		$this->scan();

		$this->assertSame( 2, $this->integrity->accept( 'plugin:demo' ) );
		$this->assertSame( array(), $this->integrity->changes() );
		$this->assertSame( array(), $this->scan() );
	}

	public function test_rebaseline_after_an_update_clears_changes(): void {
		$this->scan();
		file_put_contents( $this->dir . '/plugin/main.php', '<?php // versión 2.0' );

		$this->integrity->rebaseline( 'plugin:demo' );

		$this->assertSame( array(), $this->scan() );
	}

	public function test_upgrades_map_to_their_areas(): void {
		$this->assertSame( array( 'core' ), WPS_File_Integrity::areas_for_upgrade( array( 'type' => 'core' ) ) );
		$this->assertSame(
			array( 'plugin:akismet', 'plugins' ),
			WPS_File_Integrity::areas_for_upgrade( array( 'type' => 'plugin', 'plugins' => array( 'akismet/akismet.php', 'hello.php' ) ) )
		);
		$this->assertSame( array( 'theme:twentytwentyfive' ), WPS_File_Integrity::areas_for_upgrade( array( 'type' => 'theme', 'themes' => array( 'twentytwentyfive' ) ) ) );
	}

	/*──────────────────────────────────────────────
	 * Pasadas completas
	 *──────────────────────────────────────────────*/

	public function test_full_pass_reports_by_mail_once(): void {
		$this->integrity->run( 0 );
		file_put_contents( $this->dir . '/plugin/main.php', '<?php // cambio' );

		$result = $this->integrity->run( 0 );

		$this->assertTrue( $result['done'] );
		$this->assertCount( 1, $result['changes'] );
		$this->assertCount( 1, $GLOBALS['wps_test_mails'] );
		$this->assertStringContainsString( 'main.php', $GLOBALS['wps_test_mails'][0]['message'] );
		$this->assertGreaterThan( 0, $GLOBALS['wps_test_options'][ WPS_File_Integrity::LAST_SCAN_OPTION ] );
	}

	public function test_pass_resumes_where_it_stopped(): void {
		$this->integrity->set_areas( array(
			'plugin:demo' => array( array( $this->dir . '/plugin', true ) ),
			'plugin:otro' => array( array( $this->dir . '/plugin/sub', true ) ),
		) );
		// Pasada interrumpida: sólo quedó pendiente la segunda área.
		$GLOBALS['wps_test_options'][ WPS_File_Integrity::STATE_OPTION ] = array( 'queue' => array( 'plugin:otro' ), 'changes' => array() );

		$result = $this->integrity->run( 0 );

		$this->assertTrue( $result['done'] );
		$this->assertSame( array( 'plugin:otro' ), array_values( array_unique( array_column( $this->store->rows, 'area' ) ) ) );
		$this->assertArrayNotHasKey( WPS_File_Integrity::STATE_OPTION, $GLOBALS['wps_test_options'] );
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function scan(): array {
		return $this->integrity->scan_area( 'plugin:demo', array( array( $this->dir . '/plugin', true ) ) );
	}

	private function loader(): WPS_Loader {
		$loader = WPS_Loader::get_instance();
		$cache  = new \ReflectionProperty( 'WPS_Loader', 'settings_cache' );
		$cache->setAccessible( true );
		$cache->setValue( $loader, array( 'notify_file_changes' => true, 'notify_email' => 'alertas@example.com' ) );

		$notifier = new \ReflectionProperty( 'WPS_Admin_Notifier', 'instance' );
		$notifier->setAccessible( true );
		$notifier->setValue( null, null );

		return $loader;
	}

	/**
	 * Store en memoria con la misma interfaz que el de base de datos.
	 */
	private function memory_store(): WPS_Integrity_Store {
		return new class() extends WPS_Integrity_Store {
			public $rows = array();

			public function rows_for_area( string $area ): array {
				return array_filter( $this->rows, function ( $row ) use ( $area ) {
					return $row['area'] === $area;
				} );
			}
			public function insert_many( array $rows ): void {
				foreach ( $rows as $row ) {
					$this->rows[ $row['path_hash'] ] = $row;
				}
			}
			public function update( string $path_hash, array $fields ): void {
				if ( isset( $this->rows[ $path_hash ] ) ) {
					$this->rows[ $path_hash ] = array_merge( $this->rows[ $path_hash ], $fields );
				}
			}
			public function delete( array $path_hashes ): void {
				foreach ( $path_hashes as $path_hash ) {
					unset( $this->rows[ $path_hash ] );
				}
			}
			public function delete_area( string $area ): void {
				$this->rows = array_filter( $this->rows, function ( $row ) use ( $area ) {
					return $row['area'] !== $area;
				} );
			}
			public function delete_areas_except( array $areas ): void {
				$this->rows = array_filter( $this->rows, function ( $row ) use ( $areas ) {
					return in_array( $row['area'], $areas, true );
				} );
			}
			public function changes( ?string $area = null ): array {
				return array_values( array_filter( $this->rows, function ( $row ) use ( $area ) {
					return 'ok' !== $row['status'] && ( null === $area || $row['area'] === $area );
				} ) );
			}
			public function count_files(): int {
				return count( $this->rows );
			}
		};
	}
}
