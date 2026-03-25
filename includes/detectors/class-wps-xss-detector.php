<?php
defined( 'ABSPATH' ) || exit;

/**
 * Detector de ataques XSS (Cross-Site Scripting).
 *
 * Analiza QUERY_STRING, POST body y URI buscando patrones
 * de inyección de scripts. Excluye administradores en wp-admin.
 */
class WPS_Xss_Detector {

	/** @var WPS_Loader */
	private $loader;

	/** @var WPS_Logger */
	private $logger;

	/** @var WPS_Blocker */
	private $blocker;

	/**
	 * Patrones de detección XSS.
	 *
	 * @var array
	 */
	private static $patterns = array(
		// Script tags.
		'/<\s*script\b/i',
		'/<\s*\/\s*script\s*>/i',
		// Event handlers.
		'/\bon(?:error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown|mouseout|mouseenter|mouseleave|dblclick|contextmenu|resize|unload|beforeunload)\s*=/i',
		// JavaScript protocol.
		'/javascript\s*:/i',
		// VBScript protocol.
		'/vbscript\s*:/i',
		// Data URI with script content.
		'/data\s*:\s*text\/html/i',
		// Expression (IE legacy).
		'/expression\s*\(/i',
		// Eval / Function constructor.
		'/\beval\s*\(/i',
		'/\bFunction\s*\(/i',
		// document object access.
		'/\bdocument\s*\.\s*(?:cookie|domain|write|location|referrer)\b/i',
		// window object abuse.
		'/\bwindow\s*\.\s*(?:location|open|eval|execScript)\b/i',
		// innerHTML / outerHTML.
		'/\.(?:innerHTML|outerHTML)\s*=/i',
		// SVG onload.
		'/<\s*svg\b[^>]*\bonload\s*=/i',
		// IMG onerror.
		'/<\s*img\b[^>]*\bon(?:error|load)\s*=/i',
		// IFRAME / OBJECT / EMBED injection.
		'/<\s*(?:iframe|object|embed|applet|form|input|button|textarea|select)\b/i',
		// fromCharCode obfuscation.
		'/String\s*\.\s*fromCharCode\s*\(/i',
		// atob / btoa base64 abuse.
		'/\b(?:atob|btoa)\s*\(/i',
		// Set-Cookie via meta.
		'/<\s*meta\b[^>]*http-equiv\s*=\s*["\']?set-cookie/i',
		// Style-based XSS.
		'/<\s*style\b[^>]*>.*?(?:expression|javascript|vbscript|url\s*\()/is',
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
	 * Analizar la petición actual en busca de XSS.
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
		if ( WPS_Custom_Rules::is_exempt( 'xss' ) ) {
			return;
		}

		if ( 'static' === $request->visitor_type() ) {
			return;
		}

		$matched = $this->scan_request( $request );

		if ( $matched ) {
			$this->handle_detection( $ip, $request, $matched );
		}
	}

	/**
	 * Escanear inputs de la petición.
	 *
	 * @return string|null Patrón que coincidió.
	 */
	private function scan_request( WPS_Request $request ): ?string {
		$inputs = $this->collect_inputs( $request );

		foreach ( $inputs as $input ) {
			if ( empty( $input ) ) {
				continue;
			}

			$decoded = $this->decode_input( $input );
			$pattern = $this->match_patterns( $decoded );
			if ( $pattern ) {
				return $pattern;
			}
		}

		return null;
	}

	/**
	 * Recopilar los inputs a analizar.
	 */
	private function collect_inputs( WPS_Request $request ): array {
		$inputs = array();

		// URI: omitir si es una ruta de contenido WP (tags, categorías, etc.)
		// para evitar falsos positivos con slugs de contenido publicado.
		if ( ! $request->is_wp_content_path() ) {
			$inputs[] = $request->uri();
		}

		// Query string.
		$inputs[] = $request->query_string();

		// POST parameters.
		if ( 'POST' === $request->method() && ! empty( $_POST ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			foreach ( $_POST as $value ) {
				if ( is_string( $value ) ) {
					$inputs[] = $value;
				} elseif ( is_array( $value ) ) {
					array_walk_recursive( $value, function ( $v ) use ( &$inputs ) {
						if ( is_string( $v ) ) {
							$inputs[] = $v;
						}
					} );
				}
			}
		}

		// GET parameters (valores individuales).
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		foreach ( $_GET as $value ) {
			if ( is_string( $value ) ) {
				$inputs[] = $value;
			} elseif ( is_array( $value ) ) {
				array_walk_recursive( $value, function ( $v ) use ( &$inputs ) {
					if ( is_string( $v ) ) {
						$inputs[] = $v;
					}
				} );
			}
		}

		return $inputs;
	}

	/**
	 * Decodificar para detectar evasión por encoding.
	 */
	private function decode_input( string $input ): string {
		$decoded = rawurldecode( rawurldecode( $input ) );
		$decoded = str_replace( "\0", '', $decoded );
		$decoded = html_entity_decode( $decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		// Decode Unicode escapes like \u003c → <.
		$decoded = preg_replace_callback( '/\\\\u([0-9a-fA-F]{4})/', function ( $m ) {
			return mb_chr( hexdec( $m[1] ), 'UTF-8' );
		}, $decoded );

		return $decoded;
	}

	/**
	 * Evaluar patrones contra un input.
	 *
	 * @return string|null El patrón que coincidió.
	 */
	private function match_patterns( string $input ): ?string {
		if ( strlen( $input ) < 4 ) {
			return null;
		}

		foreach ( self::$patterns as $pattern ) {
			if ( preg_match( $pattern, $input ) ) {
				return $pattern;
			}
		}

		return null;
	}

	/**
	 * Manejar detección de XSS.
	 */
	private function handle_detection( string $ip, WPS_Request $request, string $pattern ): void {
		$block_mode = $this->loader->get_setting( 'critical_block_mode', 'temporary' );
		$minutes    = 'permanent' === $block_mode
			? null
			: (int) $this->loader->get_setting( 'rate_block_minutes', 15 );

		$this->logger->event_immediate( WPS_Event_Types::XSS_DETECTED, array(
			'ip_address'  => $ip,
			'request_uri' => $request->uri(),
			'user_agent'  => $request->user_agent(),
			'details'     => array(
				'pattern' => $pattern,
				'method'  => $request->method(),
			),
		) );

		$this->blocker->block_ip(
			$ip,
			'auto_xss',
			'Patrón de XSS detectado',
			$minutes
		);

		$this->blocker->send_block_response( 'XSS detectado' );
	}
}
