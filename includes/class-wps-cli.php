<?php
defined( 'ABSPATH' ) || exit;

/**
 * Comandos WP-CLI de WP Seguro.
 *
 * Sirven para recuperar el acceso sin pasar por el panel (desbloquearse,
 * agregarse a la whitelist, suspender el bloqueo) y para automatizar.
 *
 * ## EXAMPLES
 *
 *     wp wps status
 *     wp wps unblock 203.0.113.7
 *     wp wps whitelist add 203.0.113.7 --label="Oficina"
 *     wp wps unsafe-mode on
 */
class WPS_CLI {

	/**
	 * Estado del firewall.
	 *
	 * ## EXAMPLES
	 *
	 *     wp wps status
	 *
	 * @subcommand status
	 */
	public function status( $args, $assoc_args ): void {
		$loader  = WPS_Loader::get_instance();
		$blocker = WPS_Blocker::get_instance();
		$file    = WPS_DATA_DIR . 'wps-blocked-ips.php';

		$rows = array(
			array( 'item' => 'Versión', 'value' => WPS_VERSION ),
			array( 'item' => 'Capa 0 (auto_prepend_file)', 'value' => $loader->is_layer_enabled( 0 ) ? 'activada' : 'desactivada' ),
			array( 'item' => 'Archivo de la Capa 0', 'value' => is_file( $file ) ? gmdate( 'Y-m-d H:i:s', (int) filemtime( $file ) ) . ' UTC' : 'no existe' ),
			array( 'item' => 'Cargador de la Capa 0', 'value' => WPS_Activator::prepend_loader_path() ),
			array( 'item' => 'Capa 1 (MU-plugin)', 'value' => is_file( WPMU_PLUGIN_DIR . '/wps-firewall-muplugin.php' ) ? 'instalada' : 'no instalada' ),
			array( 'item' => 'Modo Inseguro', 'value' => get_option( 'wps_unsafe_mode', false ) ? 'ACTIVO (no se bloquea)' : 'inactivo' ),
			array( 'item' => 'WPS_DISABLE_BLOCKING', 'value' => ( defined( 'WPS_DISABLE_BLOCKING' ) && WPS_DISABLE_BLOCKING ) ? 'ACTIVO (no se bloquea)' : 'no definido' ),
			array( 'item' => 'Bloqueos activos', 'value' => (string) $blocker->get_active_blocks( 1, 1 )['total'] ),
			array( 'item' => 'Entradas en whitelist', 'value' => (string) count( WPS_Whitelist::get_instance()->get_all() ) ),
		);

		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $rows, array( 'item', 'value' ) );
	}

	/**
	 * Bloquear una IP o un rango CIDR.
	 *
	 * ## OPTIONS
	 *
	 * <target>
	 * : IP o rango CIDR.
	 *
	 * [--minutes=<minutes>]
	 * : Duración. Sin este parámetro, el bloqueo es permanente.
	 *
	 * [--reason=<reason>]
	 * : Motivo.
	 *
	 * ## EXAMPLES
	 *
	 *     wp wps block 203.0.113.7 --minutes=60
	 *     wp wps block 198.51.100.0/24 --reason="Scanner"
	 */
	public function block( $args, $assoc_args ): void {
		$target  = trim( (string) ( $args[0] ?? '' ) );
		$minutes = isset( $assoc_args['minutes'] ) ? max( 1, (int) $assoc_args['minutes'] ) : null;
		$reason  = (string) ( $assoc_args['reason'] ?? 'Bloqueo desde WP-CLI' );
		$blocker = WPS_Blocker::get_instance();

		if ( WPS_Ip_Utils::is_valid_cidr( $target ) ) {
			$id = $blocker->block_cidr( $target, 'manual', $reason, $minutes );
		} elseif ( WPS_Ip_Utils::is_valid_ip( $target ) ) {
			$id = $blocker->block_ip( $target, 'manual', $reason, $minutes );
		} else {
			\WP_CLI::error( sprintf( '«%s» no es una IP ni un rango CIDR válido.', $target ) );
			return;
		}

		if ( ! $id ) {
			\WP_CLI::error( sprintf( 'No se pudo bloquear %s (¿está en la whitelist?).', $target ) );
			return;
		}

		\WP_CLI::success( sprintf( 'Bloqueado %s %s.', $target, $minutes ? "por {$minutes} minutos" : 'de forma permanente' ) );
	}

	/**
	 * Levantar los bloqueos de una IP o un rango CIDR.
	 *
	 * Con una IP se levantan también los bloqueos de rango que la contienen
	 * (en IPv6, los bloqueos automáticos son de red).
	 *
	 * ## OPTIONS
	 *
	 * <target>
	 * : IP o rango CIDR.
	 *
	 * ## EXAMPLES
	 *
	 *     wp wps unblock 203.0.113.7
	 */
	public function unblock( $args, $assoc_args ): void {
		$target = trim( (string) ( $args[0] ?? '' ) );

		if ( ! WPS_Ip_Utils::is_valid_ip( $target ) && ! WPS_Ip_Utils::is_valid_cidr( $target ) ) {
			\WP_CLI::error( sprintf( '«%s» no es una IP ni un rango CIDR válido.', $target ) );
			return;
		}

		$count = WPS_Blocker::get_instance()->unblock_covering( $target );

		if ( 0 === $count ) {
			\WP_CLI::warning( sprintf( '%s no tenía bloqueos activos.', $target ) );
			return;
		}

		\WP_CLI::success( sprintf( 'Se levantaron %d bloqueo(s) de %s.', $count, $target ) );
	}

	/**
	 * Listar los bloqueos activos.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv o yaml.
	 * ---
	 * default: table
	 * ---
	 */
	public function blocks( $args, $assoc_args ): void {
		$result = WPS_Blocker::get_instance()->get_active_blocks( 1, 1000 );

		$items = array_map( function ( $row ) {
			return array(
				'id'      => $row['id'],
				'target'  => $row['ip_address'] ?: $row['cidr'],
				'type'    => $row['block_type'],
				'expires' => $row['expires_at'] ? $row['expires_at'] . ' UTC' : 'permanente',
				'hits'    => $row['hit_count'],
				'reason'  => $row['reason'],
			);
		}, $result['items'] );

		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $items, array( 'id', 'target', 'type', 'expires', 'hits', 'reason' ) );
	}

	/**
	 * Administrar la whitelist.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : add, remove o list.
	 *
	 * [<target>]
	 * : IP o rango CIDR (para add y remove).
	 *
	 * [--label=<label>]
	 * : Etiqueta (para add).
	 *
	 * [--type=<type>]
	 * : global o login (para add).
	 * ---
	 * default: global
	 * ---
	 *
	 * [--format=<format>]
	 * : table, json, csv o yaml (para list).
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp wps whitelist add 203.0.113.7 --label="Oficina"
	 *     wp wps whitelist remove 203.0.113.7
	 *     wp wps whitelist list
	 */
	public function whitelist( $args, $assoc_args ): void {
		$action    = (string) ( $args[0] ?? '' );
		$target    = trim( (string) ( $args[1] ?? '' ) );
		$whitelist = WPS_Whitelist::get_instance();

		switch ( $action ) {
			case 'add':
				$type  = in_array( $assoc_args['type'] ?? 'global', array( 'global', 'login' ), true ) ? ( $assoc_args['type'] ?? 'global' ) : 'global';
				$label = (string) ( $assoc_args['label'] ?? 'Agregado desde WP-CLI' );

				if ( WPS_Ip_Utils::is_valid_cidr( $target ) ) {
					$id = $whitelist->add_cidr( $target, $label, $type );
				} elseif ( WPS_Ip_Utils::is_valid_ip( $target ) ) {
					$id = $whitelist->add_ip( $target, $label, $type );
				} else {
					\WP_CLI::error( sprintf( '«%s» no es una IP ni un rango CIDR válido.', $target ) );
					return;
				}

				if ( ! $id ) {
					\WP_CLI::error( sprintf( 'No se pudo agregar %s (¿ya estaba en la whitelist?).', $target ) );
					return;
				}

				\WP_CLI::success( sprintf( '%s agregado a la whitelist (%s).', $target, $type ) );
				return;

			case 'remove':
				$count = '' !== $target ? $whitelist->remove_value( $target ) : 0;
				if ( 0 === $count ) {
					\WP_CLI::warning( sprintf( '%s no estaba en la whitelist.', $target ) );
					return;
				}
				\WP_CLI::success( sprintf( '%s quitado de la whitelist.', $target ) );
				return;

			case 'list':
				$items = array_map( function ( $row ) {
					return array(
						'id'     => $row['id'],
						'target' => $row['ip_address'] ?: $row['cidr'],
						'type'   => $row['whitelist_type'],
						'label'  => $row['label'],
					);
				}, $whitelist->get_all() );

				\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $items, array( 'id', 'target', 'type', 'label' ) );
				return;
		}

		\WP_CLI::error( 'Acción desconocida. Usá add, remove o list.' );
	}

	/**
	 * Monitor de integridad de archivos.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : scan, status o accept.
	 *
	 * [<area>]
	 * : Área a aceptar (p. ej. core, plugin:akismet). Sin área, accept acepta todo.
	 *
	 * [--format=<format>]
	 * : table, json, csv o yaml (para status).
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp wps integrity scan
	 *     wp wps integrity status
	 *     wp wps integrity accept plugin:akismet
	 */
	public function integrity( $args, $assoc_args ): void {
		$action    = (string) ( $args[0] ?? '' );
		$integrity = new WPS_File_Integrity( WPS_Loader::get_instance() );

		switch ( $action ) {
			case 'scan':
				// Sin límite de tiempo: en la consola no hay timeout de PHP.
				$result = $integrity->run( 0 );
				if ( $result['changes'] ) {
					\WP_CLI::warning( sprintf( 'Escaneo completo: %d cambios nuevos.', count( $result['changes'] ) ) );
				} else {
					\WP_CLI::success( 'Escaneo completo: sin cambios nuevos.' );
				}
				return;

			case 'status':
				$items = array_map( function ( $row ) {
					return array( 'area' => $row['area'], 'status' => $row['status'], 'path' => $row['path'], 'detected' => $row['detected_at'] );
				}, $integrity->changes() );

				$summary = $integrity->summary();
				\WP_CLI::line( sprintf(
					'Archivos vigilados: %d · Cambios sin revisar: %d · Último escaneo: %s',
					$summary['files'],
					$summary['changes'],
					$summary['last_scan'] ? gmdate( 'Y-m-d H:i', $summary['last_scan'] ) . ' UTC' : 'nunca'
				) );

				if ( $items ) {
					\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $items, array( 'area', 'status', 'path', 'detected' ) );
				}
				return;

			case 'accept':
				$area     = isset( $args[1] ) ? (string) $args[1] : null;
				$accepted = $integrity->accept( $area );
				\WP_CLI::success( sprintf( 'Se aceptaron %d cambios como la nueva referencia.', $accepted ) );
				return;
		}

		\WP_CLI::error( 'Acción desconocida. Usá scan, status o accept.' );
	}

	/**
	 * Chequeo de endurecimiento del sitio.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : table, json, csv o yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp wps hardening
	 */
	public function hardening( $args, $assoc_args ): void {
		$results = ( new WPS_Hardening_Check( WPS_Loader::get_instance() ) )->run( true );

		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $results, array( 'status', 'label', 'message' ) );

		$counts = WPS_Hardening_Check::counts( $results );
		\WP_CLI::line( sprintf( 'Problemas: %d · Mejorables: %d · Correctos: %d', $counts['fail'], $counts['warn'], $counts['pass'] ) );
		\WP_CLI::line( 'Nota: «Errores de PHP visibles» refleja la configuración de PHP de la consola, que puede diferir de la web.' );
	}

	/**
	 * Regenerar el archivo de la Capa 0 desde la base de datos.
	 *
	 * @subcommand sync-layer0
	 */
	public function sync_layer0( $args, $assoc_args ): void {
		WPS_Activator::sync_blocked_ips_file();

		if ( ! WPS_Loader::get_instance()->is_layer_enabled( 0 ) ) {
			\WP_CLI::warning( 'La Capa 0 está desactivada: no hay archivo que generar (y se eliminó el que hubiera).' );
			return;
		}

		\WP_CLI::success( 'Archivo de la Capa 0 regenerado.' );
	}

	/**
	 * Activar o desactivar el Modo Inseguro (detectar sin bloquear).
	 *
	 * ## OPTIONS
	 *
	 * <state>
	 * : on u off.
	 *
	 * ## EXAMPLES
	 *
	 *     wp wps unsafe-mode on
	 *
	 * @subcommand unsafe-mode
	 */
	public function unsafe_mode( $args, $assoc_args ): void {
		$state = strtolower( (string) ( $args[0] ?? '' ) );

		if ( ! in_array( $state, array( 'on', 'off' ), true ) ) {
			\WP_CLI::error( 'Indicá on u off.' );
			return;
		}

		update_option( 'wps_unsafe_mode', 'on' === $state, false );

		WPS_Logger::get_instance()->event_immediate( WPS_Event_Types::SETTINGS_CHANGED, array(
			'details' => array(
				'action'      => 'unsafe_mode_toggled',
				'unsafe_mode' => 'on' === $state,
				'via'         => 'wp-cli',
			),
		), WPS_Event_Types::SEVERITY_INFO );

		WPS_Admin_Notifier::get_instance( WPS_Loader::get_instance() )->notify_settings_change(
			get_current_user_id(),
			'on' === $state ? 'Modo Inseguro activado desde WP-CLI (el firewall no bloquea)' : 'Modo Inseguro desactivado desde WP-CLI'
		);

		\WP_CLI::success( 'on' === $state
			? 'Modo Inseguro activado: el firewall sólo detecta y registra.'
			: 'Modo Inseguro desactivado: el firewall bloquea normalmente.' );
	}
}
