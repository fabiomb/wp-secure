<?php
defined( 'ABSPATH' ) || exit;

/**
 * Monitor de integridad de archivos.
 *
 * Toma una referencia (hash por archivo) del núcleo, de cada plugin, de cada
 * tema y de mu-plugins, y en cada escaneo informa los archivos modificados,
 * agregados o eliminados. Compara contenido, no fechas: el malware suele
 * restaurar la fecha de modificación del archivo que infecta.
 *
 * - Sin servicios externos: la comparación es contra la referencia local.
 * - Las actualizaciones de plugins, temas y núcleo vuelven a tomar la
 *   referencia del área afectada, así que no generan alarmas.
 * - Cada pasada tiene un límite de tiempo; si no termina, sigue un minuto
 *   después, para no superar el tiempo máximo de ejecución del hosting.
 */
class WPS_File_Integrity {

	/** Estado de la pasada en curso (áreas pendientes y cambios encontrados). */
	const STATE_OPTION = 'wps_integrity_state';

	/** Hora de la última pasada completa. */
	const LAST_SCAN_OPTION = 'wps_integrity_last_scan';

	/** Evento para continuar una pasada que no terminó. */
	const CONTINUE_HOOK = 'wps_integrity_continue';

	/** Segundos por pasada en el cron. */
	const TIME_BUDGET = 20;

	/** Archivos vigilados: código ejecutable y configuración del servidor. */
	const FILE_PATTERN = '/(\.(php\d?|phtml|phar|inc)|^\.htaccess|^\.user\.ini)$/i';

	/** Directorios que no se recorren. */
	const SKIP_DIRS = array( '.git', '.svn', 'node_modules' );

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Integrity_Store */
	private $store;

	/** @var array|null Áreas fijadas (tests). */
	private $areas = null;

	public function __construct( WPS_Loader $loader, ?WPS_Integrity_Store $store = null ) {
		$this->loader = $loader;
		$this->store  = $store ?? new WPS_Integrity_Store();
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		if ( ! $this->loader->get_setting( 'integrity_enabled', true ) ) {
			return;
		}

		add_action( 'wps_daily_maintenance', array( $this, 'run_scheduled' ) );
		add_action( self::CONTINUE_HOOK, array( $this, 'run_scheduled' ) );
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrade' ), 20, 2 );
	}

	/*──────────────────────────────────────────────
	 * Áreas y archivos
	 *──────────────────────────────────────────────*/

	/**
	 * @param array $areas Área => lista de [ruta, recursivo].
	 */
	public function set_areas( array $areas ): void {
		$this->areas = $areas;
	}

	/**
	 * Áreas vigiladas: núcleo, mu-plugins, cada plugin y cada tema.
	 *
	 * @return array<string, array> Área => lista de [ruta, recursivo].
	 */
	public function areas(): array {
		if ( null !== $this->areas ) {
			return $this->areas;
		}

		$areas = array(
			'core' => array(
				array( untrailingslashit( ABSPATH ), false ),
				array( ABSPATH . 'wp-admin', true ),
				array( ABSPATH . WPINC, true ),
			),
		);

		// Archivos sueltos de wp-content: los drop-ins (advanced-cache.php,
		// object-cache.php, db.php) son un escondite clásico de malware.
		$areas['wp-content'] = array( array( WP_CONTENT_DIR, false ) );

		if ( is_dir( WPMU_PLUGIN_DIR ) ) {
			$areas['mu-plugins'] = array( array( WPMU_PLUGIN_DIR, true ) );
		}

		$areas['plugins'] = array( array( WP_PLUGIN_DIR, false ) );
		foreach ( self::subdirs( WP_PLUGIN_DIR ) as $slug => $dir ) {
			$areas[ 'plugin:' . $slug ] = array( array( $dir, true ) );
		}

		foreach ( self::subdirs( get_theme_root() ) as $slug => $dir ) {
			$areas[ 'theme:' . $slug ] = array( array( $dir, true ) );
		}

		return $areas;
	}

	/**
	 * @return array<string, string> Nombre => ruta.
	 */
	private static function subdirs( string $dir ): array {
		$names = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $names ) ) {
			return array();
		}

		$found = array();
		foreach ( $names as $name ) {
			if ( '.' !== $name[0] && is_dir( $dir . '/' . $name ) ) {
				$found[ $name ] = $dir . '/' . $name;
			}
		}
		return $found;
	}

	/**
	 * Archivos vigilados de un área y su hash.
	 *
	 * @param array $roots Lista de [ruta, recursivo].
	 * @return array<string, array> Ruta => [hash, tamaño].
	 */
	public static function files( array $roots ): array {
		$files = array();

		foreach ( $roots as list( $root, $recursive ) ) {
			if ( ! is_dir( $root ) ) {
				continue;
			}

			$iterator = $recursive
				? new RecursiveIteratorIterator(
					new RecursiveCallbackFilterIterator(
						new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
						function ( $current ) {
							return ! ( $current->isDir() && in_array( $current->getFilename(), self::SKIP_DIRS, true ) );
						}
					)
				)
				: new FilesystemIterator( $root, FilesystemIterator::SKIP_DOTS );

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() || ! preg_match( self::FILE_PATTERN, $file->getFilename() ) ) {
					continue;
				}

				$path = wp_normalize_path( $file->getPathname() );
				$hash = @md5_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				if ( false !== $hash ) {
					$files[ $path ] = array( $hash, (int) $file->getSize() );
				}
			}
		}

		return $files;
	}

	/*──────────────────────────────────────────────
	 * Escaneo
	 *──────────────────────────────────────────────*/

	/**
	 * Comparar un área contra su referencia.
	 *
	 * La primera vez que se ve un área sólo se toma la referencia, sin avisar.
	 *
	 * @return array[] Cambios nuevos: path, area, status.
	 */
	public function scan_area( string $area, array $roots ): array {
		$now      = current_time( 'mysql', true );
		$current  = self::files( $roots );
		$existing = $this->store->rows_for_area( $area );

		if ( ! $existing ) {
			$this->store->insert_many( $this->rows( $area, $current, 'ok', null, $now ) );
			return array();
		}

		$changes = array();
		$added   = array();

		foreach ( $current as $path => list( $hash, $size ) ) {
			$path_hash = md5( $path );
			$row       = $existing[ $path_hash ] ?? null;
			unset( $existing[ $path_hash ] );

			if ( null === $row ) {
				$added[ $path ] = array( $hash, $size );
				$changes[]      = array( 'path' => $path, 'area' => $area, 'status' => 'added' );
				continue;
			}

			if ( 'added' === $row['status'] ) {
				continue; // Ya informado.
			}

			$matches_baseline = hash_equals( (string) $row['file_hash'], $hash );

			if ( $matches_baseline && 'ok' !== $row['status'] ) {
				// Restaurado: vuelve a coincidir con la referencia.
				$this->store->update( $path_hash, array( 'status' => 'ok', 'detected_at' => null ) );
			} elseif ( ! $matches_baseline && 'modified' !== $row['status'] ) {
				$this->store->update( $path_hash, array( 'status' => 'modified', 'detected_at' => $now ) );
				$changes[] = array( 'path' => $path, 'area' => $area, 'status' => 'modified' );
			}
		}

		if ( $added ) {
			$this->store->insert_many( $this->rows( $area, $added, 'added', $now, $now ) );
		}

		// Lo que queda en $existing ya no está en disco.
		$gone_added = array();
		foreach ( $existing as $path_hash => $row ) {
			if ( 'added' === $row['status'] ) {
				$gone_added[] = $path_hash; // Apareció y desapareció: nada que conservar.
			} elseif ( 'deleted' !== $row['status'] ) {
				$this->store->update( $path_hash, array( 'status' => 'deleted', 'detected_at' => $now ) );
				$changes[] = array( 'path' => $row['path'], 'area' => $area, 'status' => 'deleted' );
			}
		}
		$this->store->delete( $gone_added );

		return $changes;
	}

	/**
	 * Avanzar la pasada en curso, o empezar una, hasta agotar el tiempo.
	 *
	 * @param int $budget Segundos disponibles; 0 = sin límite.
	 * @return array{done: bool, changes: array[]} Cambios de la pasada, al terminarla.
	 */
	public function run( int $budget = self::TIME_BUDGET ): array {
		$start = microtime( true );
		$areas = $this->areas();
		$state = get_option( self::STATE_OPTION, array() );

		if ( empty( $state['queue'] ) ) {
			$state = array( 'queue' => array_keys( $areas ), 'changes' => array() );
		}

		// La primera lectura de miles de archivos (disco en frío, antivirus del
		// servidor) puede tardar bastante más que las siguientes. Donde el
		// hosting lo permite, se da margen para terminar el área en curso.
		if ( $budget > 0 && function_exists( 'set_time_limit' ) ) {
			@set_time_limit( max( (int) ini_get( 'max_execution_time' ), $budget + 120 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		while ( $state['queue'] ) {
			// El progreso se guarda antes de cada área: si PHP corta la
			// ejecución en medio de un área grande, la próxima pasada sigue
			// desde ahí en lugar de empezar de cero.
			update_option( self::STATE_OPTION, $state, false );

			$area = array_shift( $state['queue'] );
			if ( isset( $areas[ $area ] ) ) {
				$state['changes'] = array_merge( $state['changes'], $this->scan_area( $area, $areas[ $area ] ) );
			}

			if ( $budget > 0 && $state['queue'] && microtime( true ) - $start >= $budget ) {
				update_option( self::STATE_OPTION, $state, false );
				if ( function_exists( 'wp_next_scheduled' ) && ! wp_next_scheduled( self::CONTINUE_HOOK ) ) {
					wp_schedule_single_event( time() + 60, self::CONTINUE_HOOK );
				}
				return array( 'done' => false, 'changes' => array() );
			}
		}

		// Pasada completa.
		delete_option( self::STATE_OPTION );
		update_option( self::LAST_SCAN_OPTION, time(), false );
		$this->store->delete_areas_except( array_keys( $areas ) );

		if ( $state['changes'] ) {
			$this->report( $state['changes'] );
		}

		return array( 'done' => true, 'changes' => $state['changes'] );
	}

	/**
	 * Callback del cron (diario y continuación).
	 */
	public function run_scheduled(): void {
		if ( $this->loader->get_setting( 'integrity_enabled', true ) ) {
			$this->run();
		}
	}

	/*──────────────────────────────────────────────
	 * Referencia
	 *──────────────────────────────────────────────*/

	/**
	 * Volver a tomar la referencia de un área (tras una actualización).
	 */
	public function rebaseline( string $area ): void {
		$areas = $this->areas();
		$this->store->delete_area( $area );

		if ( isset( $areas[ $area ] ) ) {
			$this->scan_area( $area, $areas[ $area ] );
		}
	}

	/**
	 * Tras actualizar plugins, temas o el núcleo, la referencia de esas áreas
	 * se vuelve a tomar: los archivos cambiaron por un motivo legítimo.
	 *
	 * @param WP_Upgrader $upgrader   Instalador.
	 * @param array       $hook_extra Datos de la operación.
	 */
	public function on_upgrade( $upgrader, $hook_extra ): void {
		if ( 'update' !== ( $hook_extra['action'] ?? '' ) ) {
			return;
		}

		foreach ( self::areas_for_upgrade( (array) $hook_extra ) as $area ) {
			$this->rebaseline( $area );
		}
	}

	/**
	 * Áreas afectadas por una actualización.
	 *
	 * @return string[]
	 */
	public static function areas_for_upgrade( array $hook_extra ): array {
		switch ( $hook_extra['type'] ?? '' ) {
			case 'core':
				return array( 'core' );

			case 'plugin':
				$plugins = (array) ( $hook_extra['plugins'] ?? array() );
				if ( ! empty( $hook_extra['plugin'] ) ) {
					$plugins[] = $hook_extra['plugin'];
				}
				return array_values( array_unique( array_map( function ( $plugin ) {
					return false === strpos( $plugin, '/' ) ? 'plugins' : 'plugin:' . strtok( $plugin, '/' );
				}, $plugins ) ) );

			case 'theme':
				$themes = (array) ( $hook_extra['themes'] ?? array() );
				if ( ! empty( $hook_extra['theme'] ) ) {
					$themes[] = $hook_extra['theme'];
				}
				return array_values( array_unique( array_map( function ( $theme ) {
					return 'theme:' . $theme;
				}, $themes ) ) );
		}

		return array();
	}

	/**
	 * Aceptar los cambios: pasan a ser la nueva referencia.
	 *
	 * @param string|null $area Área, o null para todas.
	 * @return int Archivos aceptados.
	 */
	public function accept( ?string $area = null ): int {
		$now      = current_time( 'mysql', true );
		$accepted = 0;
		$deleted  = array();

		foreach ( $this->store->changes( $area ) as $row ) {
			$accepted++;

			if ( 'deleted' === $row['status'] || ! is_file( $row['path'] ) ) {
				$deleted[] = $row['path_hash'];
				continue;
			}

			$this->store->update( $row['path_hash'], array(
				'status'      => 'ok',
				'file_hash'   => (string) md5_file( $row['path'] ),
				'detected_at' => null,
				'checked_at'  => $now,
			) );
		}

		$this->store->delete( $deleted );

		return $accepted;
	}

	/**
	 * Cambios sin aceptar.
	 */
	public function changes( ?string $area = null ): array {
		return $this->store->changes( $area );
	}

	/**
	 * Resumen para el panel y WP-CLI.
	 */
	public function summary(): array {
		$state = get_option( self::STATE_OPTION, array() );

		return array(
			'files'       => $this->store->count_files(),
			'changes'     => count( $this->store->changes() ),
			'last_scan'   => (int) get_option( self::LAST_SCAN_OPTION, 0 ),
			'in_progress' => ! empty( $state['queue'] ),
		);
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	private function rows( string $area, array $files, string $status, ?string $detected_at, string $now ): array {
		$rows = array();
		foreach ( $files as $path => list( $hash, $size ) ) {
			$rows[] = array(
				'path_hash'   => md5( $path ),
				'path'        => $path,
				'area'        => $area,
				'file_hash'   => $hash,
				'size'        => $size,
				'status'      => $status,
				'detected_at' => $detected_at,
				'checked_at'  => $now,
			);
		}
		return $rows;
	}

	/**
	 * Registrar y avisar los cambios de una pasada.
	 *
	 * @param array[] $changes Cambios: path, area, status.
	 */
	private function report( array $changes ): void {
		WPS_Logger::get_instance()->event_immediate( WPS_Event_Types::FILE_CHANGED, array(
			'details' => array(
				'count'   => count( $changes ),
				'changes' => array_slice( $changes, 0, 50 ),
			),
		) );

		WPS_Admin_Notifier::get_instance( $this->loader )->notify_file_changes( $changes );
	}
}
