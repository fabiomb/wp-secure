<?php
defined( 'ABSPATH' ) || exit;

/**
 * Detector de herramientas de escaneo de seguridad.
 *
 * Identifica escáneres conocidos (WPScan, Nikto, sqlmap, etc.) por
 * User-Agent y por patrones de acceso típicos de scanners (plugins
 * y temas no instalados, rutas de configuración comunes).
 */
class WPS_Scanner_Detector {

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Logger */
	private $logger;

	/** @var WPS_Blocker */
	private $blocker;

	/**
	 * Patrones de User-Agent de herramientas de escaneo conocidas.
	 *
	 * @var array
	 */
	private static $ua_patterns = array(
		'/\bWPScan\b/i',
		'/\bNikto\b/i',
		'/\bsqlmap\b/i',
		'/\bAcunetix\b/i',
		'/\bNessus\b/i',
		'/\bOpenVAS\b/i',
		'/\bBurp\s*Suite\b/i',
		'/\bDirBuster\b/i',
		'/\bDirsearch\b/i',
		'/\bGobuster\b/i',
		'/\bwfuzz\b/i',
		'/\bffuf\b/i',
		'/\bhydra\b/i',
		'/\bmedusa\b/i',
		'/\bnuclei\b/i',
		'/\bZAP\b/',
		'/\bw3af\b/i',
		'/\barachni\b/i',
		'/\bhavij\b/i',
		'/\bvega\b/i',
		'/\bsitemap.*generator/i',
		'/\bmasscan\b/i',
		'/\bnmap\b/i',
		'/\bcensys\b/i',
		'/\bshodan\b/i',
	);

	/**
	 * Rutas de escaneo comunes que indican enumeración de vulnerabilidades.
	 *
	 * @var array
	 */
	private static $scanner_paths = array(
		// Paneles de administración comunes (no WordPress).
		'/\/(?:phpmyadmin|pma|mysql|myadmin|phpMyAdmin)\b/i',
		'/\/(?:administrator|admin\.php|manager)\b/i',
		// Shells / backdoors.
		'/\/(?:c99|r57|wso|shell|b374k|alfa|mini)\.(php|txt)\b/i',
		// Config / env files.
		'/\/(?:config\.bak|config\.old|config\.save)\b/i',
		'/\/\.(env|aws|docker|kube)\b/i',
		// Common vulnerability paths.
		'/\/(?:cgi-bin|cgi|fcgi)\//i',
		// Typical scanner probes.
		'/\/(?:test|testing|temp|tmp|old|backup|bak|copy)\.(php|html?|zip|sql)\b/i',
	);

	public function __construct( WPS_Loader $loader ) {
		$this->loader  = $loader;
		$this->logger  = WPS_Logger::get_instance();
		$this->blocker = WPS_Blocker::get_instance();
	}

	/**
	 * Registrar hooks.
	 */
	public function init(): void {
		add_action( 'init', array( $this, 'check_request' ), 2 );
	}

	/**
	 * Analizar la petición actual.
	 */
	public function check_request(): void {
		if ( is_admin() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$request = WPS_Request::get_instance();
		$ip      = $request->ip();

		if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
			return;
		}

		// Eximido por regla personalizada.
		if ( WPS_Custom_Rules::is_exempt( 'scanner' ) ) {
			return;
		}

		if ( 'static' === $request->visitor_type() ) {
			return;
		}

		// Verificar si es un crawler legítimo antes de analizar (R10).
		if ( $this->loader->get_setting( 'crawler_rdns_enabled', true ) ) {
			$verifier  = WPS_Crawler_Verifier::get_instance();
			$crawler_id = $verifier->identify_crawler_ua( $request->user_agent() );

			if ( null !== $crawler_id ) {
				$result = $verifier->verify( $ip, $request->user_agent() );

				if ( WPS_Crawler_Verifier::RESULT_LEGITIMATE === $result ) {
					// Crawler verificado → no aplicar reglas de scanner.
					return;
				}

				if ( WPS_Crawler_Verifier::RESULT_SPOOFED === $result ) {
					// Crawler falsificado → bloquear directamente.
					$this->logger->event_immediate( WPS_Event_Types::CRAWLER_SPOOFED, array(
						'ip_address'  => $ip,
						'request_uri' => $request->uri(),
						'user_agent'  => $request->user_agent(),
						'details'     => array(
							'crawler_id' => $crawler_id,
						),
					) );

					$minutes = (int) $this->loader->get_setting( 'rate_block_minutes', 15 );
					$this->blocker->block_ip(
						$ip,
						'auto_crawler_spoof',
						sprintf( 'Crawler falsificado: %s', $crawler_id ),
						$minutes
					);
					$this->blocker->send_block_response( 'Acceso denegado' );
				}
			}
		}

		$detection = $this->detect_scanner( $request );

		if ( $detection ) {
			$this->handle_detection( $ip, $request, $detection );
		}
	}

	/**
	 * Detectar si la petición proviene de un scanner.
	 *
	 * @return array|null Array con type y pattern si es scanner.
	 */
	private function detect_scanner( WPS_Request $request ): ?array {
		$user_agent = $request->user_agent();
		$uri        = rawurldecode( $request->uri() );

		// 1. Verificar User-Agent contra patrones conocidos.
		if ( $user_agent ) {
			foreach ( self::$ua_patterns as $pattern ) {
				if ( preg_match( $pattern, $user_agent ) ) {
					return array(
						'type'    => 'user_agent',
						'pattern' => $pattern,
						'value'   => $user_agent,
					);
				}
			}
		}

		// No analizar URIs de taxonomías de WordPress (tags, categorías, etc.)
		// para evitar falsos positivos con slugs que coinciden con patrones.
		$is_content_path = $request->is_wp_content_path();

		// 2. Verificar rutas de escaneo (solo si no es una URL de contenido WP).
		if ( ! $is_content_path ) {
			foreach ( self::$scanner_paths as $pattern ) {
				if ( preg_match( $pattern, $uri ) ) {
					return array(
						'type'    => 'scanner_path',
						'pattern' => $pattern,
						'value'   => $uri,
					);
				}
			}
		}

		// 3. Acceso a plugins no instalados.
		if ( preg_match( '/\/wp-content\/plugins\/([^\/]+)\//', $uri, $matches ) ) {
			$plugin_slug = sanitize_file_name( $matches[1] );
			$plugin_dir  = WP_PLUGIN_DIR . '/' . $plugin_slug;
			if ( ! is_dir( $plugin_dir ) ) {
				return array(
					'type'    => 'nonexistent_plugin',
					'pattern' => $plugin_slug,
					'value'   => $uri,
				);
			}
		}

		// 4. Acceso a temas no instalados.
		if ( preg_match( '/\/wp-content\/themes\/([^\/]+)\//', $uri, $matches ) ) {
			$theme_slug = sanitize_file_name( $matches[1] );
			$theme_dir  = get_theme_root() . '/' . $theme_slug;
			if ( ! is_dir( $theme_dir ) ) {
				return array(
					'type'    => 'nonexistent_theme',
					'pattern' => $theme_slug,
					'value'   => $uri,
				);
			}
		}

		return null;
	}

	/**
	 * Manejar detección de scanner.
	 */
	private function handle_detection( string $ip, WPS_Request $request, array $detection ): void {
		$block_mode = $this->loader->get_setting( 'critical_block_mode', 'temporary' );
		$minutes    = 'permanent' === $block_mode
			? null
			: (int) $this->loader->get_setting( 'rate_block_minutes', 15 );

		$this->logger->event_immediate( WPS_Event_Types::SCANNER_DETECTED, array(
			'ip_address'  => $ip,
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => $detection,
		) );

		$this->blocker->block_ip(
			$ip,
			'auto_scanner',
			sprintf( 'Scanner detectado: %s', $detection['type'] ),
			$minutes
		);

		$this->blocker->send_block_response( 'Acceso denegado' );
	}
}
