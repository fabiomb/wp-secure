<?php
defined( 'ABSPATH' ) || exit;

/**
 * Panel de gestión de reglas personalizadas.
 */
class WPS_Admin_Custom_Rules {

	/** @var WPS_Loader */
	private $loader;

	public function __construct( WPS_Loader $loader ) {
		$this->loader = $loader;
	}

	/**
	 * Renderizar la página principal de reglas personalizadas.
	 */
	public function render(): void {
		$message   = null;
		$edit_rule = null;

		// Procesar acciones y obtener estado.
		$action_result = $this->handle_actions();
		if ( is_array( $action_result ) && isset( $action_result['edit_rule'] ) ) {
			$edit_rule = $action_result['edit_rule'];
		} elseif ( is_array( $action_result ) ) {
			$message = $action_result;
		}

		$engine  = WPS_Custom_Rules::get_instance();
		$page    = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		$result  = $engine->get_all( $page, 50 );
		?>
		<div class="wrap wps-wrap">
			<h1><?php esc_html_e( 'WP Seguro — Reglas Personalizadas', 'wp-secure' ); ?></h1>

			<?php if ( $message ) : ?>
				<div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible">
					<p><?php echo esc_html( $message['text'] ); ?></p>
				</div>
			<?php endif; ?>

			<p class="description">
				<?php esc_html_e( 'Define reglas de detección personalizadas basadas en condiciones de la petición HTTP. Cada regla evalúa una o más condiciones encadenadas con AND/OR y ejecuta una acción.', 'wp-secure' ); ?>
			</p>

			<?php if ( $edit_rule ) : ?>
				<!-- Formulario de edición (visible) -->
				<?php $this->render_rule_form( $edit_rule ); ?>
			<?php else : ?>
				<a href="#wps-custom-rule-form" class="page-title-action" id="wps-toggle-add-rule" style="margin: 15px 0; display: inline-block;">
					<?php esc_html_e( 'Nueva Regla', 'wp-secure' ); ?>
				</a>

				<!-- Formulario de regla (oculto) -->
				<?php $this->render_rule_form(); ?>
			<?php endif; ?>

			<!-- Lista de reglas existentes -->
			<?php $this->render_rules_table( $result ); ?>
		</div>
		<?php
	}

	/**
	 * Formulario para crear/editar regla.
	 */
	private function render_rule_form( ?array $edit_rule = null ): void {
		$is_edit  = ! empty( $edit_rule );
		$rule     = $edit_rule ?? array(
			'id'              => 0,
			'name'            => '',
			'description'     => '',
			'conditions'      => array( array( 'field' => 'uri', 'operator' => 'contains', 'value' => '', 'logic' => 'AND' ) ),
			'action_type'     => 'block_temporary',
			'action_duration' => 15,
			'is_active'       => true,
			'priority'        => 10,
		);

		$fields    = WPS_Custom_Rules::get_field_options();
		$operators = WPS_Custom_Rules::get_operator_options();
		$actions   = WPS_Custom_Rules::get_action_options();
		?>
		<div id="wps-custom-rule-form" class="wps-section" style="<?php echo $is_edit ? '' : 'display:none;'; ?>">
			<h2><?php echo $is_edit ? esc_html__( 'Editar Regla', 'wp-secure' ) : esc_html__( 'Nueva Regla', 'wp-secure' ); ?></h2>
			<form method="post" id="wps-rule-form">
				<?php wp_nonce_field( 'wps_custom_rule', 'wps_rule_nonce' ); ?>
				<input type="hidden" name="wps_action" value="<?php echo $is_edit ? 'edit_rule' : 'add_rule'; ?>" />
				<?php if ( $is_edit ) : ?>
					<input type="hidden" name="wps_rule_id" value="<?php echo esc_attr( $rule['id'] ); ?>" />
				<?php endif; ?>

				<table class="form-table">
					<tr>
						<th><label for="wps-rule-name"><?php esc_html_e( 'Nombre', 'wp-secure' ); ?></label></th>
						<td>
							<input type="text" id="wps-rule-name" name="wps_rule_name" class="regular-text"
								   value="<?php echo esc_attr( $rule['name'] ); ?>" required />
							<p class="description"><?php esc_html_e( 'Nombre descriptivo para identificar esta regla.', 'wp-secure' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><label for="wps-rule-desc"><?php esc_html_e( 'Descripción', 'wp-secure' ); ?></label></th>
						<td>
							<input type="text" id="wps-rule-desc" name="wps_rule_description" class="large-text"
								   value="<?php echo esc_attr( $rule['description'] ); ?>" />
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Condiciones (IF)', 'wp-secure' ); ?></th>
						<td>
							<div id="wps-conditions-container">
								<?php
								$conditions = $rule['conditions'];
								if ( empty( $conditions ) ) {
									$conditions = array( array( 'field' => 'uri', 'operator' => 'contains', 'value' => '', 'logic' => 'AND' ) );
								}
								foreach ( $conditions as $i => $cond ) :
									?>
									<div class="wps-condition-row" data-index="<?php echo esc_attr( $i ); ?>">
										<?php if ( $i > 0 ) : ?>
											<select name="wps_conditions[<?php echo esc_attr( $i ); ?>][logic]" class="wps-condition-logic">
												<option value="AND" <?php selected( ( $cond['logic'] ?? 'AND' ), 'AND' ); ?>>AND</option>
												<option value="OR" <?php selected( ( $cond['logic'] ?? 'AND' ), 'OR' ); ?>>OR</option>
											</select>
										<?php else : ?>
											<input type="hidden" name="wps_conditions[0][logic]" value="AND" />
											<span class="wps-condition-logic-label">IF</span>
										<?php endif; ?>

										<select name="wps_conditions[<?php echo esc_attr( $i ); ?>][field]" class="wps-condition-field">
											<?php foreach ( $fields as $fkey => $flabel ) : ?>
												<option value="<?php echo esc_attr( $fkey ); ?>" <?php selected( ( $cond['field'] ?? '' ), $fkey ); ?>>
													<?php echo esc_html( $flabel ); ?>
												</option>
											<?php endforeach; ?>
										</select>

										<select name="wps_conditions[<?php echo esc_attr( $i ); ?>][operator]" class="wps-condition-operator">
											<?php foreach ( $operators as $okey => $olabel ) : ?>
												<option value="<?php echo esc_attr( $okey ); ?>" <?php selected( ( $cond['operator'] ?? '' ), $okey ); ?>>
													<?php echo esc_html( $olabel ); ?>
												</option>
											<?php endforeach; ?>
										</select>

										<input type="text" name="wps_conditions[<?php echo esc_attr( $i ); ?>][value]"
											   class="regular-text wps-condition-value"
											   value="<?php echo esc_attr( $cond['value'] ?? '' ); ?>"
											   placeholder="<?php esc_attr_e( 'Valor a comparar', 'wp-secure' ); ?>" required />

										<?php if ( $i > 0 ) : ?>
											<button type="button" class="button wps-remove-condition" title="<?php esc_attr_e( 'Eliminar condición', 'wp-secure' ); ?>">
												<span class="dashicons dashicons-no-alt"></span>
											</button>
										<?php endif; ?>
									</div>
								<?php endforeach; ?>
							</div>
							<button type="button" class="button" id="wps-add-condition">
								<span class="dashicons dashicons-plus-alt2" style="vertical-align: text-top;"></span>
								<?php esc_html_e( 'Agregar condición', 'wp-secure' ); ?>
							</button>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Acción (THEN)', 'wp-secure' ); ?></th>
						<td>
							<select name="wps_rule_action" id="wps-rule-action">
								<?php foreach ( $actions as $akey => $alabel ) : ?>
									<option value="<?php echo esc_attr( $akey ); ?>" <?php selected( ( $rule['action_type'] ?? '' ), $akey ); ?>>
										<?php echo esc_html( $alabel ); ?>
									</option>
								<?php endforeach; ?>
							</select>

							<span id="wps-duration-wrap" style="<?php echo 'block_temporary' === ( $rule['action_type'] ?? '' ) ? '' : 'display:none;'; ?>">
								<input type="number" name="wps_rule_duration" id="wps-rule-duration"
									   value="<?php echo esc_attr( $rule['action_duration'] ?? 15 ); ?>"
									   min="1" max="525600" style="width: 80px;" />
								<span><?php esc_html_e( 'minutos', 'wp-secure' ); ?></span>
							</span>

							<?php
							$detectors      = WPS_Custom_Rules::get_detector_options();
							$current_params = array();
							if ( $is_edit && 'exempt' === ( $rule['action_type'] ?? '' ) && ! empty( $rule['action_params'] ) ) {
								$decoded = is_string( $rule['action_params'] ) ? json_decode( $rule['action_params'], true ) : $rule['action_params'];
								if ( is_array( $decoded ) ) {
									$current_params = $decoded;
								}
							}
							?>
							<div id="wps-exempt-wrap" style="<?php echo 'exempt' === ( $rule['action_type'] ?? '' ) ? '' : 'display:none;'; ?>margin-top:8px;">
								<p class="description" style="margin-bottom:6px;"><?php esc_html_e( 'Detectores a eximir (la petición no será penalizada por estos detectores si la regla coincide):', 'wp-secure' ); ?></p>
								<?php foreach ( $detectors as $det_key => $det_label ) : ?>
									<label style="display:inline-block;margin-right:12px;margin-bottom:4px;">
										<input type="checkbox" name="wps_rule_exempt_detectors[]" value="<?php echo esc_attr( $det_key ); ?>"
											<?php checked( in_array( $det_key, $current_params, true ) ); ?> />
										<?php echo esc_html( $det_label ); ?>
									</label>
								<?php endforeach; ?>
							</div>
						</td>
					</tr>
					<tr>
						<th><label for="wps-rule-priority"><?php esc_html_e( 'Prioridad', 'wp-secure' ); ?></label></th>
						<td>
							<input type="number" id="wps-rule-priority" name="wps_rule_priority"
								   value="<?php echo esc_attr( $rule['priority'] ?? 10 ); ?>"
								   min="1" max="999" style="width: 80px;" />
							<p class="description"><?php esc_html_e( 'Menor número = mayor prioridad. Las reglas se evalúan en orden de prioridad.', 'wp-secure' ); ?></p>
						</td>
					</tr>
					<tr>
						<th><?php esc_html_e( 'Estado', 'wp-secure' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="wps_rule_active" value="1"
									<?php checked( $rule['is_active'] ?? true ); ?> />
								<?php esc_html_e( 'Activa', 'wp-secure' ); ?>
							</label>
						</td>
					</tr>
				</table>

				<p class="submit">
					<button type="submit" class="button button-primary">
						<?php echo $is_edit ? esc_html__( 'Guardar Cambios', 'wp-secure' ) : esc_html__( 'Crear Regla', 'wp-secure' ); ?>
					</button>
					<?php if ( $is_edit ) : ?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-rules' ) ); ?>" class="button">
							<?php esc_html_e( 'Cancelar', 'wp-secure' ); ?>
						</a>
					<?php endif; ?>
				</p>
			</form>
		</div>

		<!-- Template para nuevas condiciones (usado por JS) -->
		<script type="text/html" id="tmpl-wps-condition-row">
			<div class="wps-condition-row" data-index="{{data.index}}">
				<select name="wps_conditions[{{data.index}}][logic]" class="wps-condition-logic">
					<option value="AND">AND</option>
					<option value="OR">OR</option>
				</select>

				<select name="wps_conditions[{{data.index}}][field]" class="wps-condition-field">
					<?php foreach ( $fields as $fkey => $flabel ) : ?>
						<option value="<?php echo esc_attr( $fkey ); ?>"><?php echo esc_html( $flabel ); ?></option>
					<?php endforeach; ?>
				</select>

				<select name="wps_conditions[{{data.index}}][operator]" class="wps-condition-operator">
					<?php foreach ( $operators as $okey => $olabel ) : ?>
						<option value="<?php echo esc_attr( $okey ); ?>"><?php echo esc_html( $olabel ); ?></option>
					<?php endforeach; ?>
				</select>

				<input type="text" name="wps_conditions[{{data.index}}][value]"
					   class="regular-text wps-condition-value" placeholder="<?php esc_attr_e( 'Valor a comparar', 'wp-secure' ); ?>" required />

				<button type="button" class="button wps-remove-condition" title="<?php esc_attr_e( 'Eliminar condici\u00f3n', 'wp-secure' ); ?>">
					<span class="dashicons dashicons-no-alt"></span>
				</button>
			</div>
		</script>
		<?php
	}

	/**
	 * Tabla de reglas existentes.
	 */
	private function render_rules_table( array $result ): void {
		$items = $result['items'];
		$actions_map = WPS_Custom_Rules::get_action_options();
		?>
		<table class="wp-list-table widefat fixed striped wps-rules-table">
			<thead>
				<tr>
					<th style="width:5%;"><?php esc_html_e( 'ID', 'wp-secure' ); ?></th>
					<th style="width:5%;"><?php esc_html_e( 'Prio', 'wp-secure' ); ?></th>
					<th style="width:18%;"><?php esc_html_e( 'Nombre', 'wp-secure' ); ?></th>
					<th style="width:30%;"><?php esc_html_e( 'Condiciones', 'wp-secure' ); ?></th>
					<th style="width:14%;"><?php esc_html_e( 'Acción', 'wp-secure' ); ?></th>
					<th style="width:6%;"><?php esc_html_e( 'Hits', 'wp-secure' ); ?></th>
					<th style="width:7%;"><?php esc_html_e( 'Estado', 'wp-secure' ); ?></th>
					<th style="width:15%;"><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $items ) ) : ?>
					<tr>
						<td colspan="8" style="text-align:center;padding:20px;">
							<?php esc_html_e( 'No hay reglas personalizadas definidas.', 'wp-secure' ); ?>
						</td>
					</tr>
				<?php else : ?>
					<?php foreach ( $items as $rule ) : ?>
						<tr>
							<td><?php echo esc_html( $rule['id'] ); ?></td>
							<td><?php echo esc_html( $rule['priority'] ); ?></td>
							<td>
								<strong><?php echo esc_html( $rule['name'] ); ?></strong>
								<?php if ( ! empty( $rule['description'] ) ) : ?>
									<br><small class="description"><?php echo esc_html( $rule['description'] ); ?></small>
								<?php endif; ?>
							</td>
							<td>
								<?php echo wp_kses_post( $this->format_conditions( $rule['conditions'] ) ); ?>
							</td>
							<td>
								<?php
								$action_label = $actions_map[ $rule['action_type'] ] ?? $rule['action_type'];
								$badge_class  = $this->get_action_badge_class( $rule['action_type'] );
								echo '<span class="wps-badge ' . esc_attr( $badge_class ) . '">' . esc_html( $action_label ) . '</span>';
								if ( 'block_temporary' === $rule['action_type'] && $rule['action_duration'] ) {
									echo '<br><small>' . esc_html( $rule['action_duration'] ) . ' min</small>';
								}
								if ( 'exempt' === $rule['action_type'] && ! empty( $rule['action_params'] ) ) {
									$det_list = is_string( $rule['action_params'] ) ? json_decode( $rule['action_params'], true ) : $rule['action_params'];
									if ( is_array( $det_list ) ) {
										echo '<br><small>' . esc_html( implode( ', ', $det_list ) ) . '</small>';
									}
								}
								?>
							</td>
							<td><?php echo esc_html( number_format_i18n( $rule['hit_count'] ) ); ?></td>
							<td>
								<?php if ( $rule['is_active'] ) : ?>
									<span class="wps-badge wps-badge-ok"><?php esc_html_e( 'Activa', 'wp-secure' ); ?></span>
								<?php else : ?>
									<span class="wps-badge wps-badge-muted"><?php esc_html_e( 'Inactiva', 'wp-secure' ); ?></span>
								<?php endif; ?>
							</td>
							<td>
								<?php
								$edit_url   = wp_nonce_url(
									admin_url( 'admin.php?page=wp-secure-rules&wps_action=edit&rule_id=' . $rule['id'] ),
									'wps_edit_rule_' . $rule['id']
								);
								$toggle_url = wp_nonce_url(
									admin_url( 'admin.php?page=wp-secure-rules&wps_action=toggle&rule_id=' . $rule['id'] ),
									'wps_toggle_rule_' . $rule['id']
								);
								$delete_url = wp_nonce_url(
									admin_url( 'admin.php?page=wp-secure-rules&wps_action=delete_rule&rule_id=' . $rule['id'] ),
									'wps_delete_rule_' . $rule['id']
								);
								?>
								<a href="<?php echo esc_url( $edit_url ); ?>" class="button button-small" title="<?php esc_attr_e( 'Editar', 'wp-secure' ); ?>">
									<span class="dashicons dashicons-edit" style="font-size:14px;line-height:1.8;"></span>
								</a>
								<a href="<?php echo esc_url( $toggle_url ); ?>" class="button button-small" title="<?php echo $rule['is_active'] ? esc_attr__( 'Desactivar', 'wp-secure' ) : esc_attr__( 'Activar', 'wp-secure' ); ?>">
									<span class="dashicons <?php echo $rule['is_active'] ? 'dashicons-hidden' : 'dashicons-visibility'; ?>" style="font-size:14px;line-height:1.8;"></span>
								</a>
								<a href="<?php echo esc_url( $delete_url ); ?>" class="button button-small"
								   data-wps-confirm="<?php esc_attr_e( '¿Eliminar esta regla?', 'wp-secure' ); ?>"
								   title="<?php esc_attr_e( 'Eliminar', 'wp-secure' ); ?>">
									<span class="dashicons dashicons-trash" style="font-size:14px;line-height:1.8;color:#d63638;"></span>
								</a>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>

		<?php if ( $result['pages'] > 1 ) : ?>
			<div class="tablenav bottom">
				<div class="tablenav-pages">
					<?php
					echo wp_kses_post( paginate_links( array(
						'base'    => add_query_arg( 'paged', '%#%' ),
						'format'  => '',
						'current' => $result['page'],
						'total'   => $result['pages'],
						'type'    => 'plain',
					) ) );
					?>
				</div>
			</div>
		<?php endif; ?>
		<?php
	}

	/**
	 * Formatear condiciones para mostrar en la tabla.
	 */
	private function format_conditions( ?array $conditions ): string {
		if ( empty( $conditions ) ) {
			return '<em>' . esc_html__( 'Sin condiciones', 'wp-secure' ) . '</em>';
		}

		$fields    = WPS_Custom_Rules::get_field_options();
		$operators = WPS_Custom_Rules::get_operator_options();
		$parts     = array();

		foreach ( $conditions as $i => $cond ) {
			$logic = '';
			if ( $i > 0 ) {
				$logic = '<strong>' . esc_html( $cond['logic'] ?? 'AND' ) . '</strong> ';
			}

			$field_label = $fields[ $cond['field'] ] ?? $cond['field'];
			$op_label    = $operators[ $cond['operator'] ] ?? $cond['operator'];
			$value       = esc_html( $cond['value'] );

			$parts[] = $logic . esc_html( $field_label ) . ' <em>' . esc_html( $op_label ) . '</em> <code>' . $value . '</code>';
		}

		return implode( '<br>', $parts );
	}

	/**
	 * CSS class para el badge de acción.
	 */
	private function get_action_badge_class( string $action_type ): string {
		switch ( $action_type ) {
			case 'block_permanent':
				return 'wps-badge-danger';
			case 'block_temporary':
				return 'wps-badge-warning';
			case 'whitelist':
				return 'wps-badge-ok';
			case 'exempt':
				return 'wps-badge-pending';
			case 'log_only':
			default:
				return 'wps-badge-info';
		}
	}

	/**
	 * Procesar acciones (crear, editar, eliminar, toggle).
	 */
	private function handle_actions(): ?array {
		// Acción por GET (editar, toggle, eliminar).
		$get_action = sanitize_text_field( wp_unslash( $_GET['wps_action'] ?? '' ) );
		$rule_id    = absint( $_GET['rule_id'] ?? 0 );

		if ( 'edit' === $get_action && $rule_id ) {
			if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_edit_rule_' . $rule_id ) ) {
				return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
			}
			$engine = WPS_Custom_Rules::get_instance();
			$rule   = $engine->get( $rule_id );
			if ( $rule ) {
				return array( 'edit_rule' => $rule );
			}
			return array( 'type' => 'error', 'text' => __( 'Regla no encontrada.', 'wp-secure' ) );
		}

		if ( 'toggle' === $get_action && $rule_id ) {
			if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_toggle_rule_' . $rule_id ) ) {
				return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
			}
			$engine = WPS_Custom_Rules::get_instance();
			if ( $engine->toggle( $rule_id ) ) {
				return array( 'type' => 'success', 'text' => __( 'Estado de la regla actualizado.', 'wp-secure' ) );
			}
			return array( 'type' => 'error', 'text' => __( 'No se pudo cambiar el estado.', 'wp-secure' ) );
		}

		if ( 'delete_rule' === $get_action && $rule_id ) {
			if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_delete_rule_' . $rule_id ) ) {
				return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
			}
			$engine = WPS_Custom_Rules::get_instance();
			if ( $engine->delete( $rule_id ) ) {
				return array( 'type' => 'success', 'text' => __( 'Regla eliminada.', 'wp-secure' ) );
			}
			return array( 'type' => 'error', 'text' => __( 'No se pudo eliminar la regla.', 'wp-secure' ) );
		}

		// Acciones por POST (crear, editar).
		$post_action = sanitize_text_field( wp_unslash( $_POST['wps_action'] ?? '' ) );
		if ( ! in_array( $post_action, array( 'add_rule', 'edit_rule' ), true ) ) {
			return null;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_rule_nonce'] ?? '' ) ), 'wps_custom_rule' ) ) {
			return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return array( 'type' => 'error', 'text' => __( 'Sin permisos.', 'wp-secure' ) );
		}

		$rule_data = $this->parse_form_data();
		$engine    = WPS_Custom_Rules::get_instance();

		if ( 'add_rule' === $post_action ) {
			$result = $engine->create( $rule_data );
			if ( $result ) {
				return array( 'type' => 'success', 'text' => __( 'Regla creada correctamente.', 'wp-secure' ) );
			}
			return array( 'type' => 'error', 'text' => __( 'No se pudo crear la regla. Verifica que los datos sean válidos.', 'wp-secure' ) );
		}

		if ( 'edit_rule' === $post_action ) {
			$edit_id = absint( $_POST['wps_rule_id'] ?? 0 );
			if ( $edit_id && $engine->update( $edit_id, $rule_data ) ) {
				return array( 'type' => 'success', 'text' => __( 'Regla actualizada correctamente.', 'wp-secure' ) );
			}
			return array( 'type' => 'error', 'text' => __( 'No se pudo actualizar la regla.', 'wp-secure' ) );
		}

		return null;
	}

	/**
	 * Parsear datos del formulario POST en array.
	 */
	private function parse_form_data(): array {
		$conditions_raw = $_POST['wps_conditions'] ?? array();
		$conditions     = array();

		if ( is_array( $conditions_raw ) ) {
			foreach ( $conditions_raw as $cond ) {
				if ( ! is_array( $cond ) ) {
					continue;
				}
				$conditions[] = array(
					'field'    => sanitize_text_field( $cond['field'] ?? '' ),
					'operator' => sanitize_text_field( $cond['operator'] ?? 'contains' ),
					'value'    => sanitize_text_field( $cond['value'] ?? '' ),
					'logic'    => sanitize_text_field( strtoupper( $cond['logic'] ?? 'AND' ) ),
				);
			}
		}

		return array(
			'name'            => sanitize_text_field( wp_unslash( $_POST['wps_rule_name'] ?? '' ) ),
			'description'     => sanitize_text_field( wp_unslash( $_POST['wps_rule_description'] ?? '' ) ),
			'conditions'      => $conditions,
			'action_type'     => sanitize_text_field( wp_unslash( $_POST['wps_rule_action'] ?? '' ) ),
			'action_duration' => absint( $_POST['wps_rule_duration'] ?? 15 ),
			'action_params'   => isset( $_POST['wps_rule_exempt_detectors'] ) && is_array( $_POST['wps_rule_exempt_detectors'] )
				? array_map( 'sanitize_key', $_POST['wps_rule_exempt_detectors'] )
				: array(),
			'is_active'       => ! empty( $_POST['wps_rule_active'] ),
			'priority'        => absint( $_POST['wps_rule_priority'] ?? 10 ),
		);
	}
}
