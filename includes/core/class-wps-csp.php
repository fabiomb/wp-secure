<?php
defined( 'ABSPATH' ) || exit;

/**
 * Content-Security-Policy: política, reportes de violaciones y armador.
 *
 * Una CSP aplicada de entrada rompe casi cualquier sitio WordPress (scripts
 * de plugins, fuentes, analíticas, videos embebidos). Por eso el camino es:
 *
 * 1. Enviarla en modo reporte (`Content-Security-Policy-Report-Only`): el
 *    navegador no bloquea nada, sólo informa lo que habría bloqueado.
 * 2. Juntar esos reportes en el propio sitio, sin servicios externos.
 * 3. Armar una política sugerida que agrega los orígenes reportados, para
 *    revisarla y, recién entonces, aplicarla.
 */
class WPS_Csp {

	/** Reportes agrupados por directiva y origen. */
	const REPORTS_OPTION = 'wps_csp_reports';

	/** Parámetro de la URL que recibe los reportes. */
	const REPORT_PARAM = 'wps_csp_report';

	/** Máximo de combinaciones directiva-origen guardadas. */
	const MAX_REPORTS = 200;

	/** Segundos durante los que un reporte repetido no se vuelve a escribir. */
	const THROTTLE = 600;

	/** Tamaño máximo del cuerpo de un reporte. */
	const MAX_BODY_BYTES = 65536;

	/** Nombre del endpoint en `Reporting-Endpoints` / `report-to`. */
	const ENDPOINT_NAME = 'wps-csp';

	/**
	 * Política base para WordPress: restringe lo que casi ningún sitio usa
	 * (plugins de objeto, `<base>`, formularios a otros dominios, ser
	 * embebido) y deja scripts y estilos en línea, que WordPress y la mayoría
	 * de los temas necesitan.
	 */
	const BASE_POLICY = array(
		'default-src'     => array( "'self'" ),
		'script-src'      => array( "'self'", "'unsafe-inline'", "'unsafe-eval'" ),
		'style-src'       => array( "'self'", "'unsafe-inline'" ),
		'img-src'         => array( "'self'", 'data:' ),
		'font-src'        => array( "'self'", 'data:' ),
		'connect-src'     => array( "'self'" ),
		'frame-src'       => array( "'self'" ),
		'media-src'       => array( "'self'" ),
		'object-src'      => array( "'none'" ),
		'base-uri'        => array( "'self'" ),
		'form-action'     => array( "'self'" ),
		'frame-ancestors' => array( "'self'" ),
	);

	/** Palabras clave de `blocked-uri` y su fuente equivalente en la política. */
	const KEYWORD_SOURCES = array(
		'inline'    => "'unsafe-inline'",
		'eval'      => "'unsafe-eval'",
		'wasm-eval' => "'wasm-unsafe-eval'",
		'data'      => 'data:',
		'blob'      => 'blob:',
		'self'      => "'self'",
	);

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Modo configurado: off, report o enforce.
	 */
	public function mode(): string {
		$mode = (string) $this->loader->get_setting( 'csp_mode', 'off' );
		return in_array( $mode, array( 'report', 'enforce' ), true ) ? $mode : 'off';
	}

	/**
	 * Política configurada, o la base si no hay una.
	 */
	public function policy(): string {
		$policy = self::normalize( (string) $this->loader->get_setting( 'csp_policy', '' ) );
		return '' !== $policy ? $policy : self::build( self::BASE_POLICY );
	}

	/**
	 * Headers de la CSP según el modo, con el destino de los reportes.
	 *
	 * @return array<string, string>
	 */
	public function headers(): array {
		$mode = $this->mode();
		if ( 'off' === $mode ) {
			return array();
		}

		$url  = self::report_url();
		$name = 'enforce' === $mode ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';

		return array(
			$name                 => $this->policy() . '; report-uri ' . $url . '; report-to ' . self::ENDPOINT_NAME,
			'Reporting-Endpoints' => self::ENDPOINT_NAME . '="' . $url . '"',
		);
	}

	public static function report_url(): string {
		return add_query_arg( self::REPORT_PARAM, '1', home_url( '/' ) );
	}

	/*──────────────────────────────────────────────
	 * Política como texto
	 *──────────────────────────────────────────────*/

	/**
	 * @return array<string, string[]> Directiva => fuentes.
	 */
	public static function parse( string $policy ): array {
		$directives = array();

		foreach ( preg_split( '/[;\r\n]+/', $policy ) as $part ) {
			$tokens = preg_split( '/\s+/', trim( $part ), -1, PREG_SPLIT_NO_EMPTY );
			if ( ! $tokens ) {
				continue;
			}

			$name = strtolower( array_shift( $tokens ) );

			// El destino de los reportes lo agrega el plugin.
			if ( ! preg_match( '/^[a-z-]+$/', $name ) || in_array( $name, array( 'report-uri', 'report-to' ), true ) ) {
				continue;
			}

			$directives[ $name ] = array_values( array_unique( array_merge( $directives[ $name ] ?? array(), $tokens ) ) );
		}

		return $directives;
	}

	public static function build( array $directives ): string {
		$parts = array();
		foreach ( $directives as $name => $sources ) {
			$parts[] = trim( $name . ' ' . implode( ' ', $sources ) );
		}
		return implode( '; ', $parts );
	}

	/**
	 * Política escrita a mano (una directiva por línea o separadas por `;`)
	 * en una sola línea válida para un header.
	 */
	public static function normalize( string $policy ): string {
		return self::build( self::parse( $policy ) );
	}

	/*──────────────────────────────────────────────
	 * Reportes
	 *──────────────────────────────────────────────*/

	/**
	 * Recibir un reporte del navegador (en `init`, antes de los detectores).
	 *
	 * El cuerpo de un reporte repite la URL de la página y lo bloqueado; si
	 * pasara por los detectores de la Capa 2, un visitante legítimo podría
	 * quedar bloqueado por la URL de un script de terceros. Sólo se guarda la
	 * directiva, el origen y la ruta de la página, validados.
	 */
	public function maybe_handle_report(): void {
		if ( empty( $_GET[ self::REPORT_PARAM ] ) || 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return;
		}

		if ( 'off' !== $this->mode() ) {
			$body = (string) file_get_contents( 'php://input', false, null, 0, self::MAX_BODY_BYTES );
			$this->record( self::extract_reports( $body ), time() );
		}

		status_header( 204 );
		exit;
	}

	/**
	 * Reportes de un cuerpo en formato `report-uri` o Reporting API.
	 *
	 * @return array[] Lista de [directive, source, page].
	 */
	public static function extract_reports( string $body ): array {
		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return array();
		}

		$raw = array();

		// report-uri: {"csp-report": {...}}
		if ( isset( $data['csp-report'] ) && is_array( $data['csp-report'] ) ) {
			$report = $data['csp-report'];
			$raw[]  = array(
				$report['effective-directive'] ?? ( $report['violated-directive'] ?? '' ),
				$report['blocked-uri'] ?? '',
				$report['document-uri'] ?? '',
			);
		}

		// Reporting API: [{"type": "csp-violation", "body": {...}}, ...]
		if ( isset( $data[0] ) ) {
			foreach ( array_slice( $data, 0, 20 ) as $entry ) {
				if ( is_array( $entry ) && 'csp-violation' === ( $entry['type'] ?? '' ) && is_array( $entry['body'] ?? null ) ) {
					$raw[] = array(
						$entry['body']['effectiveDirective'] ?? '',
						$entry['body']['blockedURL'] ?? '',
						$entry['body']['documentURL'] ?? '',
					);
				}
			}
		}

		$reports = array();
		foreach ( $raw as list( $directive, $blocked, $page ) ) {
			$directive = self::normalize_directive( is_string( $directive ) ? $directive : '' );
			$source    = self::normalize_source( is_string( $blocked ) ? $blocked : '' );

			if ( null !== $directive && null !== $source ) {
				$reports[] = array( $directive, $source, self::page_path( is_string( $page ) ? $page : '' ) );
			}
		}

		return $reports;
	}

	/**
	 * `script-src-elem` → `script-src`; null si no es una directiva.
	 */
	public static function normalize_directive( string $directive ): ?string {
		$directive = strtolower( trim( strtok( $directive, ' ' ) ?: '' ) );
		$directive = (string) preg_replace( '/-(elem|attr)$/', '', $directive );

		return preg_match( '/^[a-z]+(-[a-z]+)*-src$|^(base-uri|form-action|frame-ancestors)$/', $directive ) ? $directive : null;
	}

	/**
	 * Fuente de política para lo bloqueado: un origen (`https://cdn.example.com`)
	 * o una palabra clave (`'unsafe-inline'`). Null si no se reconoce.
	 */
	public static function normalize_source( string $blocked ): ?string {
		$blocked = strtolower( trim( $blocked ) );

		if ( isset( self::KEYWORD_SOURCES[ $blocked ] ) ) {
			return self::KEYWORD_SOURCES[ $blocked ];
		}

		$parts = wp_parse_url( $blocked );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) ) {
			return null;
		}

		if ( in_array( $parts['scheme'], array( 'data', 'blob' ), true ) ) {
			return $parts['scheme'] . ':';
		}

		if ( ! in_array( $parts['scheme'], array( 'http', 'https', 'wss', 'ws' ), true )
			|| empty( $parts['host'] ) || ! preg_match( '/^[a-z0-9.-]+$/', $parts['host'] ) ) {
			return null;
		}

		return $parts['scheme'] . '://' . $parts['host'] . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );
	}

	private static function page_path( string $url ): string {
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		return substr( (string) preg_replace( '/[^A-Za-z0-9\/._~%-]/', '', $path ), 0, 200 );
	}

	/**
	 * Guardar reportes agrupados por directiva y origen.
	 *
	 * Un sitio con una violación en cada página enviaría un reporte por
	 * visita: uno repetido se vuelve a escribir sólo cada THROTTLE segundos, y
	 * las combinaciones nuevas se descartan pasado MAX_REPORTS.
	 *
	 * @param array[] $reports Lista de [directive, source, page].
	 */
	public function record( array $reports, int $now ): void {
		if ( ! $reports ) {
			return;
		}

		$stored  = $this->reports();
		$changed = false;

		foreach ( $reports as list( $directive, $source, $page ) ) {
			$key = $directive . ' ' . $source;

			if ( isset( $stored[ $key ] ) ) {
				if ( $now - $stored[ $key ]['last'] < self::THROTTLE ) {
					continue;
				}
				$stored[ $key ]['count']++;
				$stored[ $key ]['last'] = $now;
				$stored[ $key ]['page'] = $page;
			} elseif ( count( $stored ) < self::MAX_REPORTS ) {
				$stored[ $key ] = array(
					'directive' => $directive,
					'source'    => $source,
					'count'     => 1,
					'first'     => $now,
					'last'      => $now,
					'page'      => $page,
				);
			} else {
				continue;
			}

			$changed = true;
		}

		if ( $changed ) {
			update_option( self::REPORTS_OPTION, $stored, false );
		}
	}

	/**
	 * @return array<string, array> Clave => directive, source, count, first, last, page.
	 */
	public function reports(): array {
		$stored = get_option( self::REPORTS_OPTION, array() );
		return is_array( $stored ) ? $stored : array();
	}

	public function clear_reports(): void {
		delete_option( self::REPORTS_OPTION );
	}

	/**
	 * Política actual más los orígenes reportados.
	 *
	 * Un reporte de una directiva que la política no tiene (p. ej. `worker-src`)
	 * se había resuelto con `default-src`: se agrega la directiva con lo que
	 * tenía `default-src` más el origen reportado.
	 */
	public function suggested(): string {
		$directives = self::parse( $this->policy() );
		$default    = $directives['default-src'] ?? array( "'self'" );

		foreach ( $this->reports() as $report ) {
			$name = $report['directive'];

			if ( ! isset( $directives[ $name ] ) ) {
				$directives[ $name ] = $default;
			}
			if ( in_array( "'none'", $directives[ $name ], true ) ) {
				$directives[ $name ] = array();
			}
			if ( ! in_array( $report['source'], $directives[ $name ], true ) ) {
				$directives[ $name ][] = $report['source'];
			}
		}

		return self::build( $directives );
	}
}
