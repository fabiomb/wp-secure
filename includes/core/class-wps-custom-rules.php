<?php
defined( 'ABSPATH' ) || exit;

/**
 * Motor de reglas manuales personalizadas.
 *
 * Permite al administrador definir reglas del tipo:
 *   IF (condición 1) AND/OR (condición 2) … THEN (acción)
 *
 * Condiciones soportadas:
 *   - uri_contains      : La URI contiene un string.
 *   - uri_equals        : La URI es exactamente un string.
 *   - uri_regex         : La URI coincide con una expresión regular.
 *   - user_agent_contains : El User-Agent contiene un string.
 *   - user_agent_regex  : El User-Agent coincide con una regex.
 *   - ip_equals         : La IP es exactamente un valor.
 *   - ip_cidr           : La IP pertenece a un rango CIDR.
 *   - method_equals     : El método HTTP es exactamente un valor.
 *   - header_contains   : Una cabecera HTTP contiene un string.
 *   - query_contains    : El query string contiene un string.
 *   - country_equals    : El país de la IP es uno específico.
 *
 * Acciones soportadas:
 *   - block_permanent : Bloqueo permanente de la IP.
 *   - block_temporary : Bloqueo temporal (duración configurable en minutos).
 *   - whitelist       : Agregar la IP a la whitelist.
 *   - log_only        : Solo registrar el evento sin acción.
 */
class WPS_Custom_Rules {

	/** @var WPS_Custom_Rules|null */
	private static $instance = null;

	/** @var WPS_Db */
	private $db;

	/** @var array|null Cache de reglas activas. */
	private $rules_cache = null;

	/** @var array Detectores eximidos para la petición actual. */
	private static $exemptions = array();

	private function __construct() {
		$this->db = WPS_Db::get_instance();
	}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/*──────────────────────────────────────────────
	 * CRUD
	 *──────────────────────────────────────────────*/

	/**
	 * Crear una nueva regla.
	 *
	 * @param array $data {
	 *     @type string $name           Nombre descriptivo de la regla.
	 *     @type string $description    Descripción opcional.
	 *     @type array  $conditions     Array de condiciones.
	 *     @type string $action_type    Tipo de acción (block_permanent|block_temporary|whitelist|log_only).
	 *     @type int    $action_duration Duración en minutos (solo para block_temporary).
	 *     @type int    $priority       Prioridad (menor = evalúa primero).
	 *     @type bool   $is_active      Estado activo/inactivo.
	 * }
	 * @return int|false ID de la regla o false en error.
	 */
	public function create( array $data ) {
		$validated = $this->validate_rule_data( $data );
		if ( ! $validated ) {
			return false;
		}

		$result = $this->db->insert( 'custom_rules', array(
			'name'            => $validated['name'],
			'description'     => $validated['description'],
			'conditions'      => wp_json_encode( $validated['conditions'] ),
			'action_type'     => $validated['action_type'],
			'action_duration' => $validated['action_duration'],
			'action_params'   => $validated['action_params'],
			'is_active'       => $validated['is_active'] ? 1 : 0,
			'priority'        => $validated['priority'],
		) );

		if ( $result ) {
			$this->rules_cache = null;
		}

		return $result;
	}

	/**
	 * Actualizar una regla existente.
	 */
	public function update( int $id, array $data ): bool {
		$validated = $this->validate_rule_data( $data );
		if ( ! $validated ) {
			return false;
		}

		$result = $this->db->update(
			'custom_rules',
			array(
				'name'            => $validated['name'],
				'description'     => $validated['description'],
				'conditions'      => wp_json_encode( $validated['conditions'] ),
				'action_type'     => $validated['action_type'],
				'action_duration' => $validated['action_duration'],
				'action_params'   => $validated['action_params'],
				'is_active'       => $validated['is_active'] ? 1 : 0,
				'priority'        => $validated['priority'],
			),
			array( 'id' => $id )
		);

		$this->rules_cache = null;

		return $result > 0;
	}

	/**
	 * Eliminar una regla.
	 */
	public function delete( int $id ): bool {
		$result = $this->db->delete( 'custom_rules', array( 'id' => $id ) );
		$this->rules_cache = null;
		return $result > 0;
	}

	/**
	 * Obtener una regla por ID.
	 */
	public function get( int $id ): ?array {
		$table = WPS_Db_Schema::table( 'custom_rules' );
		$row   = $this->db->get_row(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT * FROM {$table} WHERE id = %d",
			$id
		);

		if ( $row ) {
			$row['conditions'] = json_decode( $row['conditions'], true );
		}

		return $row;
	}

	/**
	 * Obtener todas las reglas (paginadas).
	 */
	public function get_all( int $page = 1, int $per_page = 50 ): array {
		$table  = WPS_Db_Schema::table( 'custom_rules' );
		$offset = ( $page - 1 ) * $per_page;

		$total = (int) $this->db->get_var(
			"SELECT COUNT(*) FROM {$table}"
		);

		$items = $this->db->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT * FROM {$table} ORDER BY priority ASC, id ASC LIMIT %d OFFSET %d",
			$per_page,
			$offset
		);

		foreach ( $items as &$item ) {
			$item['conditions'] = json_decode( $item['conditions'], true );
		}

		return array(
			'items'    => $items,
			'total'    => $total,
			'pages'    => $per_page > 0 ? (int) ceil( $total / $per_page ) : 1,
			'page'     => $page,
			'per_page' => $per_page,
		);
	}

	/**
	 * Activar/desactivar una regla.
	 */
	public function toggle( int $id ): bool {
		$rule = $this->get( $id );
		if ( ! $rule ) {
			return false;
		}

		$new_status = $rule['is_active'] ? 0 : 1;
		$result     = $this->db->update(
			'custom_rules',
			array( 'is_active' => $new_status ),
			array( 'id' => $id )
		);

		$this->rules_cache = null;

		return $result > 0;
	}

	/*──────────────────────────────────────────────
	 * Evaluación de reglas
	 *──────────────────────────────────────────────*/

	/**
	 * Obtener todas las reglas activas (con cache).
	 */
	public function get_active_rules(): array {
		if ( null !== $this->rules_cache ) {
			return $this->rules_cache;
		}

		$table = WPS_Db_Schema::table( 'custom_rules' );
		$rows  = $this->db->get_results(
			"SELECT * FROM {$table} WHERE is_active = 1 ORDER BY priority ASC, id ASC"
		);

		foreach ( $rows as &$row ) {
			$row['conditions'] = json_decode( $row['conditions'], true );
		}

		$this->rules_cache = $rows;
		return $this->rules_cache;
	}

	/**
	 * Evaluar todas las reglas activas contra la petición actual.
	 *
	 * @param WPS_Request $request Petición HTTP actual.
	 * @param array       $context Contexto adicional (country_code, asn, etc.).
	 * @return array|null La primera regla que coincide, o null si ninguna coincide.
	 */
	public function evaluate( WPS_Request $request, array $context = array() ): ?array {
		$rules = $this->get_active_rules();

		foreach ( $rules as $rule ) {
			if ( $this->matches_rule( $rule, $request, $context ) ) {
				// Incrementar hit_count.
				$this->increment_hits( (int) $rule['id'] );
				return $rule;
			}
		}

		return null;
	}

	/**
	 * Evaluar una petición y ejecutar la acción de la primera regla que coincida.
	 *
	 * Las reglas con acción `exempt` se procesan primero para registrar eximiciones
	 * de detectores. Luego se evalúan las demás reglas en orden de prioridad.
	 *
	 * @param WPS_Request $request Petición HTTP actual.
	 * @param array       $context Contexto adicional.
	 */
	public function evaluate_and_act( WPS_Request $request, array $context = array() ): void {
		$rules  = $this->get_active_rules();
		$logger = WPS_Logger::get_instance();
		$ip     = $request->ip();

		// Fase 1: Recolectar eximiciones (reglas 'exempt' que coincidan).
		foreach ( $rules as $rule ) {
			if ( 'exempt' !== $rule['action_type'] ) {
				continue;
			}
			if ( $this->matches_rule( $rule, $request, $context ) ) {
				$this->increment_hits( (int) $rule['id'] );
				$this->register_exemption( $rule );

				$logger->event_immediate( WPS_Event_Types::CUSTOM_RULE_MATCHED, array(
					'ip_address'  => $ip,
					'request_uri' => $request->uri(),
					'user_agent'  => $request->user_agent(),
					'details'     => array(
						'rule_id'     => $rule['id'],
						'rule_name'   => $rule['name'],
						'action_type' => 'exempt',
						'exempt_detectors' => $rule['action_params'] ?? '',
					),
				) );
			}
		}

		// Fase 2: Evaluar reglas de acción (no-exempt) en orden de prioridad.
		foreach ( $rules as $rule ) {
			if ( 'exempt' === $rule['action_type'] ) {
				continue;
			}
			if ( ! $this->matches_rule( $rule, $request, $context ) ) {
				continue;
			}

			$this->increment_hits( (int) $rule['id'] );

			$logger->event_immediate( WPS_Event_Types::CUSTOM_RULE_MATCHED, array(
				'ip_address'  => $ip,
				'request_uri' => $request->uri(),
				'user_agent'  => $request->user_agent(),
				'details'     => array(
					'rule_id'     => $rule['id'],
					'rule_name'   => $rule['name'],
					'action_type' => $rule['action_type'],
				),
			) );

			switch ( $rule['action_type'] ) {
				case 'block_permanent':
					$blocker = WPS_Blocker::get_instance();
					$blocker->block_ip(
						$ip,
						'custom_rule',
						sprintf( 'Regla personalizada: %s', $rule['name'] ),
						null
					);
					$blocker->send_block_response();
					break;

				case 'block_temporary':
					$minutes = max( 1, (int) $rule['action_duration'] );
					$blocker = WPS_Blocker::get_instance();
					$blocker->block_ip(
						$ip,
						'custom_rule',
						sprintf( 'Regla personalizada: %s', $rule['name'] ),
						$minutes
					);
					$blocker->send_block_response();
					break;

				case 'whitelist':
					$whitelist = WPS_Whitelist::get_instance();
					$whitelist->add_ip(
						$ip,
						sprintf( 'Auto: regla %s', $rule['name'] ),
						'global'
					);
					break;

				case 'log_only':
				default:
					// Solo se registró el evento arriba.
					break;
			}

			return; // Ejecutar solo la primera regla de acción que coincida.
		}
	}

	/**
	 * Registrar eximiciones de detectores desde una regla exempt.
	 */
	private function register_exemption( array $rule ): void {
		$params = $rule['action_params'] ?? '';
		if ( is_string( $params ) ) {
			$detectors = json_decode( $params, true );
		} else {
			$detectors = $params;
		}

		if ( ! is_array( $detectors ) ) {
			return;
		}

		foreach ( $detectors as $detector ) {
			$detector = sanitize_key( $detector );
			if ( '' !== $detector ) {
				self::$exemptions[ $detector ] = true;
			}
		}
	}

	/**
	 * Verificar si un detector está eximido para la petición actual.
	 *
	 * @param string $detector_id Identificador del detector (restapi, sqli, xss, etc.).
	 */
	public static function is_exempt( string $detector_id ): bool {
		return ! empty( self::$exemptions[ $detector_id ] );
	}

	/**
	 * Obtener lista de detectores disponibles para eximición.
	 */
	public static function get_detector_options(): array {
		return array(
			'restapi'   => __( 'REST API (acceso público)', 'wp-secure' ),
			'sqli'      => __( 'Inyección SQL (SQLi)', 'wp-secure' ),
			'xss'       => __( 'Cross-Site Scripting (XSS)', 'wp-secure' ),
			'traversal' => __( 'Path Traversal', 'wp-secure' ),
			'scanner'   => __( 'Scanner / Bot', 'wp-secure' ),
			'login'     => __( 'Protección de Login', 'wp-secure' ),
			'xmlrpc'    => __( 'XML-RPC', 'wp-secure' ),
		);
	}

	/*──────────────────────────────────────────────
	 * Evaluación de condiciones
	 *──────────────────────────────────────────────*/

	/**
	 * Verificar si una regla coincide con la petición.
	 *
	 * El formato de condiciones es:
	 * [
	 *   { "field": "...", "operator": "...", "value": "...", "logic": "AND|OR" },
	 *   ...
	 * ]
	 *
	 * La primera condición siempre es el punto de partida.
	 * Las siguientes se encadenan con AND u OR respecto al resultado acumulado.
	 */
	private function matches_rule( array $rule, WPS_Request $request, array $context ): bool {
		$conditions = $rule['conditions'] ?? array();
		if ( empty( $conditions ) || ! is_array( $conditions ) ) {
			return false;
		}

		$result = null;

		foreach ( $conditions as $i => $condition ) {
			$match = $this->evaluate_condition( $condition, $request, $context );
			$logic = strtoupper( $condition['logic'] ?? 'AND' );

			if ( 0 === $i || null === $result ) {
				// Primera condición.
				$result = $match;
			} elseif ( 'OR' === $logic ) {
				$result = $result || $match;
			} else {
				// AND (default).
				$result = $result && $match;
			}
		}

		return (bool) $result;
	}

	/**
	 * Evaluar una condición individual.
	 */
	private function evaluate_condition( array $condition, WPS_Request $request, array $context ): bool {
		$field    = $condition['field'] ?? '';
		$operator = $condition['operator'] ?? 'contains';
		$value    = $condition['value'] ?? '';

		if ( '' === $field || '' === $value ) {
			return false;
		}

		$subject = $this->get_field_value( $field, $request, $context );

		switch ( $operator ) {
			case 'contains':
				return false !== stripos( $subject, $value );

			case 'not_contains':
				return false === stripos( $subject, $value );

			case 'equals':
				return 0 === strcasecmp( $subject, $value );

			case 'not_equals':
				return 0 !== strcasecmp( $subject, $value );

			case 'starts_with':
				return 0 === stripos( $subject, $value );

			case 'ends_with':
				$len = strlen( $value );
				if ( 0 === $len ) {
					return true;
				}
				return 0 === substr_compare( $subject, $value, -$len, $len, true );

			case 'regex':
				return $this->safe_regex_match( $value, $subject );

			case 'cidr':
				return WPS_Ip_Utils::ip_in_cidr( $subject, $value );

			default:
				return false;
		}
	}

	/**
	 * Obtener el valor del campo de la petición para evaluar.
	 */
	private function get_field_value( string $field, WPS_Request $request, array $context ): string {
		switch ( $field ) {
			case 'uri':
				return $request->uri();

			case 'user_agent':
				return $request->user_agent();

			case 'ip':
				return $request->ip();

			case 'method':
				return $request->method();

			case 'query_string':
				return $request->query_string();

			case 'referer':
				return $request->referer();

			case 'host':
				return $request->host();

			case 'country':
				return $context['country_code'] ?? '';

			case 'visitor_type':
				return $request->visitor_type();

			default:
				// Buscar en headers si el campo empieza con "header:".
				if ( 0 === strpos( $field, 'header:' ) ) {
					$header_name = substr( $field, 7 );
					$headers     = $request->headers();
					return $headers[ $header_name ] ?? '';
				}
				return '';
		}
	}

	/**
	 * Ejecutar regex de forma segura con timeout implícito.
	 */
	private function safe_regex_match( string $pattern, string $subject ): bool {
		// Asegurar delimitadores.
		if ( '' === $pattern ) {
			return false;
		}

		// Si el usuario no proporcionó delimitadores, agregarlos.
		$first = $pattern[0];
		$valid_delimiters = array( '/', '#', '~', '!', '@' );
		if ( ! in_array( $first, $valid_delimiters, true ) ) {
			$pattern = '/' . str_replace( '/', '\\/', $pattern ) . '/i';
		}

		// Limitar backtracking para evitar ReDoS.
		$old_limit = ini_get( 'pcre.backtrack_limit' );
		ini_set( 'pcre.backtrack_limit', '10000' ); // phpcs:ignore WordPress.PHP.IniSet

		$result = @preg_match( $pattern, $subject );

		ini_set( 'pcre.backtrack_limit', $old_limit ); // phpcs:ignore WordPress.PHP.IniSet

		return 1 === $result;
	}

	/*──────────────────────────────────────────────
	 * Helpers
	 *──────────────────────────────────────────────*/

	/**
	 * Incrementar el contador de hits de una regla.
	 */
	private function increment_hits( int $id ): void {
		$table = WPS_Db_Schema::table( 'custom_rules' );
		$this->db->query(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"UPDATE {$table} SET hit_count = hit_count + 1 WHERE id = %d",
			$id
		);
	}

	/**
	 * Validar y sanitizar datos de una regla.
	 *
	 * @return array|false Datos validados o false si son inválidos.
	 */
	private function validate_rule_data( array $data ) {
		$name = trim( $data['name'] ?? '' );
		if ( '' === $name ) {
			return false;
		}

		$conditions = $data['conditions'] ?? array();
		if ( empty( $conditions ) || ! is_array( $conditions ) ) {
			return false;
		}

		$valid_fields = array(
			'uri', 'user_agent', 'ip', 'method', 'query_string',
			'referer', 'host', 'country', 'visitor_type',
		);
		$valid_operators = array(
			'contains', 'not_contains', 'equals', 'not_equals',
			'starts_with', 'ends_with', 'regex', 'cidr',
		);
		$valid_actions = array( 'block_permanent', 'block_temporary', 'whitelist', 'log_only', 'exempt' );
		$valid_logics  = array( 'AND', 'OR' );

		// Validar cada condición.
		$sanitized_conditions = array();
		foreach ( $conditions as $cond ) {
			$field    = $cond['field'] ?? '';
			$operator = $cond['operator'] ?? '';
			$value    = $cond['value'] ?? '';
			$logic    = strtoupper( $cond['logic'] ?? 'AND' );

			// Permitir campos "header:*".
			$field_valid = in_array( $field, $valid_fields, true )
				|| ( 0 === strpos( $field, 'header:' ) && strlen( $field ) > 7 );

			if ( ! $field_valid || ! in_array( $operator, $valid_operators, true ) ) {
				return false;
			}

			if ( '' === $value ) {
				return false;
			}

			if ( ! in_array( $logic, $valid_logics, true ) ) {
				$logic = 'AND';
			}

			// Validar regex sintácticamente.
			if ( 'regex' === $operator ) {
				$test_pattern = $value;
				$first = $test_pattern[0] ?? '';
				$valid_delimiters = array( '/', '#', '~', '!', '@' );
				if ( ! in_array( $first, $valid_delimiters, true ) ) {
					$test_pattern = '/' . str_replace( '/', '\\/', $test_pattern ) . '/i';
				}
				if ( false === @preg_match( $test_pattern, '' ) ) {
					return false;
				}
			}

			// Validar CIDR.
			if ( 'cidr' === $operator && ! WPS_Ip_Utils::is_valid_cidr( $value ) ) {
				return false;
			}

			$sanitized_conditions[] = array(
				'field'    => sanitize_text_field( $field ),
				'operator' => $operator,
				'value'    => sanitize_text_field( $value ),
				'logic'    => $logic,
			);
		}

		$action_type = $data['action_type'] ?? '';
		if ( ! in_array( $action_type, $valid_actions, true ) ) {
			return false;
		}

		$action_duration = null;
		if ( 'block_temporary' === $action_type ) {
			$action_duration = max( 1, absint( $data['action_duration'] ?? 15 ) );
		}

		// Parámetros de acción adicionales (para exempt: lista de detectores).
		$action_params = null;
		if ( 'exempt' === $action_type ) {
			$raw_params    = $data['action_params'] ?? array();
			$valid_detectors = array_keys( self::get_detector_options() );
			$clean_params  = array();
			if ( is_array( $raw_params ) ) {
				foreach ( $raw_params as $det ) {
					$det = sanitize_key( $det );
					if ( in_array( $det, $valid_detectors, true ) ) {
						$clean_params[] = $det;
					}
				}
			}
			if ( empty( $clean_params ) ) {
				return false; // exempt sin detectores no es válido.
			}
			$action_params = wp_json_encode( $clean_params );
		}

		return array(
			'name'            => sanitize_text_field( $name ),
			'description'     => sanitize_text_field( $data['description'] ?? '' ),
			'conditions'      => $sanitized_conditions,
			'action_type'     => $action_type,
			'action_duration' => $action_duration,
			'action_params'   => $action_params,
			'is_active'       => ! empty( $data['is_active'] ),
			'priority'        => absint( $data['priority'] ?? 10 ),
		);
	}

	/**
	 * Tipos de campo disponibles y sus etiquetas.
	 */
	public static function get_field_options(): array {
		return array(
			'uri'          => __( 'URI de la petición', 'wp-secure' ),
			'user_agent'   => __( 'User-Agent', 'wp-secure' ),
			'ip'           => __( 'Dirección IP', 'wp-secure' ),
			'method'       => __( 'Método HTTP', 'wp-secure' ),
			'query_string' => __( 'Query String', 'wp-secure' ),
			'referer'      => __( 'Referer', 'wp-secure' ),
			'host'         => __( 'Host', 'wp-secure' ),
			'country'      => __( 'País (código ISO)', 'wp-secure' ),
			'visitor_type' => __( 'Tipo de visitante', 'wp-secure' ),
		);
	}

	/**
	 * Tipos de operador disponibles y sus etiquetas.
	 */
	public static function get_operator_options(): array {
		return array(
			'contains'     => __( 'Contiene', 'wp-secure' ),
			'not_contains' => __( 'No contiene', 'wp-secure' ),
			'equals'       => __( 'Es igual a', 'wp-secure' ),
			'not_equals'   => __( 'No es igual a', 'wp-secure' ),
			'starts_with'  => __( 'Empieza con', 'wp-secure' ),
			'ends_with'    => __( 'Termina con', 'wp-secure' ),
			'regex'        => __( 'Coincide con regex', 'wp-secure' ),
			'cidr'         => __( 'Está en rango CIDR', 'wp-secure' ),
		);
	}

	/**
	 * Tipos de acción disponibles y sus etiquetas.
	 */
	public static function get_action_options(): array {
		return array(
			'block_permanent' => __( 'Bloqueo permanente', 'wp-secure' ),
			'block_temporary' => __( 'Bloqueo temporal', 'wp-secure' ),
			'whitelist'       => __( 'Agregar a whitelist', 'wp-secure' ),
			'log_only'        => __( 'Solo registrar (log)', 'wp-secure' ),
			'exempt'          => __( 'Eximir de detección', 'wp-secure' ),
		);
	}
}
