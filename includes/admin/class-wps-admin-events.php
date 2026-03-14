<?php
defined( 'ABSPATH' ) || exit;

/**
 * Visor de eventos de seguridad.
 */
class WPS_Admin_Events {

    /** @var WPS_Loader */
    private $loader;

    public function __construct( WPS_Loader $loader ) {
        $this->loader = $loader;
    }

    /**
     * Renderizar la página de eventos.
     */
    public function render(): void {
        $page     = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
        $severity = isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : '';
        $etype    = isset( $_GET['event_type'] ) ? sanitize_text_field( wp_unslash( $_GET['event_type'] ) ) : '';
        $ip       = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
        $result   = $this->get_events( $page, 30, $severity, $etype, $ip );
        ?>
        <div class="wrap wps-wrap">
            <h1><?php esc_html_e( 'WP Seguro — Eventos de Seguridad', 'wp-secure' ); ?></h1>

            <!-- Filtros -->
            <div class="wps-section">
                <form method="get" class="wps-filters-form">
                    <input type="hidden" name="page" value="wp-secure-events" />

                    <label for="wps-filter-severity"><?php esc_html_e( 'Severidad:', 'wp-secure' ); ?></label>
                    <select id="wps-filter-severity" name="severity">
                        <option value=""><?php esc_html_e( 'Todas', 'wp-secure' ); ?></option>
                        <option value="info" <?php selected( $severity, 'info' ); ?>><?php esc_html_e( 'Info', 'wp-secure' ); ?></option>
                        <option value="warning" <?php selected( $severity, 'warning' ); ?>><?php esc_html_e( 'Warning', 'wp-secure' ); ?></option>
                        <option value="critical" <?php selected( $severity, 'critical' ); ?>><?php esc_html_e( 'Critical', 'wp-secure' ); ?></option>
                    </select>

                    <label for="wps-filter-type"><?php esc_html_e( 'Tipo:', 'wp-secure' ); ?></label>
                    <select id="wps-filter-type" name="event_type">
                        <option value=""><?php esc_html_e( 'Todos', 'wp-secure' ); ?></option>
                        <?php foreach ( $this->get_event_types() as $value => $label ) : ?>
                            <option value="<?php echo esc_attr( $value ); ?>" <?php selected( $etype, $value ); ?>>
                                <?php echo esc_html( $label ); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>

                    <label for="wps-filter-ip"><?php esc_html_e( 'IP:', 'wp-secure' ); ?></label>
                    <input type="text" id="wps-filter-ip" name="ip" value="<?php echo esc_attr( $ip ); ?>"
                           placeholder="<?php esc_attr_e( 'Filtrar por IP', 'wp-secure' ); ?>" class="regular-text" />

                    <?php submit_button( __( 'Filtrar', 'wp-secure' ), 'secondary', 'submit', false ); ?>

                    <?php if ( $severity || $etype || $ip ) : ?>
                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-events' ) ); ?>" class="button">
                            <?php esc_html_e( 'Limpiar filtros', 'wp-secure' ); ?>
                        </a>
                    <?php endif; ?>

                    <?php if ( $ip && WPS_Ip_Utils::is_valid_ip( $ip ) ) : ?>
                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-traffic&ip=' . urlencode( $ip ) ) ); ?>" class="button" title="<?php esc_attr_e( 'Ver detalle completo de esta IP', 'wp-secure' ); ?>">
                            <span class="dashicons dashicons-visibility" style="font-size:16px;width:16px;height:16px;vertical-align:text-top;"></span>
                            <?php esc_html_e( 'Detalle IP', 'wp-secure' ); ?>
                        </a>
                    <?php endif; ?>
                </form>
            </div>

            <!-- Tabla de eventos -->
            <div class="wps-section">
                <div class="wps-table-summary">
                    <?php
                    printf(
                        /* translators: %d: number of events */
                        esc_html__( 'Mostrando %d eventos', 'wp-secure' ),
                        $result['total']
                    );
                    ?>
                </div>

                <table class="wps-table widefat striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Severidad', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'IP', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'URI', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Detalles', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if ( empty( $result['items'] ) ) : ?>
                        <tr>
                            <td colspan="7" class="wps-no-data">
                                <?php esc_html_e( 'No se encontraron eventos con los filtros aplicados.', 'wp-secure' ); ?>
                            </td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $result['items'] as $event ) : ?>
                            <tr class="wps-severity-<?php echo esc_attr( $event['severity'] ); ?>">
                                <td>
                                    <span title="<?php echo esc_attr( $event['created_at'] ); ?>">
                                        <?php echo esc_html( wp_date( 'Y-m-d H:i:s', strtotime( $event['created_at'] ) ) ); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="wps-badge wps-badge-<?php echo esc_attr( $event['severity'] ); ?>">
                                        <?php echo esc_html( ucfirst( $event['severity'] ) ); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html( WPS_Event_Types::label( $event['event_type'] ) ); ?></td>
                                <td>
                                    <?php if ( $event['ip_address'] ) : ?>
                                        <code>
                                            <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-events&ip=' . urlencode( $event['ip_address'] ) ) ); ?>">
                                                <?php echo esc_html( $event['ip_address'] ); ?>
                                            </a>
                                        </code>
                                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-traffic&ip=' . urlencode( $event['ip_address'] ) ) ); ?>" class="button button-small" style="margin-left:4px;padding:0 4px;min-height:24px;line-height:22px;" title="<?php esc_attr_e( 'Ver detalle IP', 'wp-secure' ); ?>">
                                            <span class="dashicons dashicons-visibility" style="font-size:14px;width:14px;height:14px;line-height:1.6;"></span>
                                        </a>
                                    <?php else : ?>
                                        —
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ( $event['request_uri'] ) : ?>
                                        <span title="<?php echo esc_attr( $event['request_uri'] ); ?>">
                                            <?php echo esc_html( mb_strimwidth( $event['request_uri'], 0, 60, '...' ) ); ?>
                                        </span>
                                    <?php else : ?>
                                        —
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php
                                    if ( $event['details'] ) {
                                        $details = json_decode( $event['details'], true );
                                        if ( is_array( $details ) ) {
                                            $parts = array();
                                            foreach ( $details as $k => $v ) {
                                                if ( is_bool( $v ) ) {
                                                    $v = $v ? 'sí' : 'no';
                                                }
                                                $parts[] = esc_html( $k ) . ': ' . esc_html( is_string( $v ) ? $v : wp_json_encode( $v ) );
                                            }
                                            echo '<small>' . implode( ' | ', $parts ) . '</small>'; // phpcs:ignore WordPress.Security.EscapeOutput
                                        }
                                    } else {
                                        echo '—';
                                    }
                                    ?>
                                </td>
                                <td>
                                    <?php if ( $event['ip_address'] ) : ?>
                                        <a href="<?php echo esc_url( wp_nonce_url(
                                            admin_url( 'admin.php?page=wp-secure-events&wps_action=block_ip&block_ip=' . urlencode( $event['ip_address'] ) ),
                                            'wps_block_from_events_' . $event['ip_address']
                                        ) ); ?>" class="button button-small" data-wps-confirm="<?php esc_attr_e( '¿Bloquear esta IP permanentemente?', 'wp-secure' ); ?>" title="<?php esc_attr_e( 'Bloquear IP', 'wp-secure' ); ?>">
                                            <span class="dashicons dashicons-shield" style="font-size:14px;width:14px;height:14px;line-height:1.8;"></span>
                                        </a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>

                <?php $this->render_pagination( $result, $severity, $etype, $ip ); ?>
            </div>
        </div>
        <?php

        // Procesar bloqueo rápido desde eventos.
        $this->handle_block_from_events();
    }

    /**
     * Obtener eventos paginados con filtros.
     */
    private function get_events( int $page, int $per_page, string $severity, string $etype, string $ip ): array {
        $db     = WPS_Db::get_instance();
        $table  = WPS_Db_Schema::table( 'security_events' );
        $offset = ( $page - 1 ) * $per_page;

        $where  = array( '1=1' );
        $params = array();

        if ( $severity && in_array( $severity, array( 'info', 'warning', 'critical' ), true ) ) {
            $where[]  = 'severity = %s';
            $params[] = $severity;
        }

        if ( $etype ) {
            $where[]  = 'event_type = %s';
            $params[] = $etype;
        }

        if ( $ip && WPS_Ip_Utils::is_valid_ip( $ip ) ) {
            $where[]  = 'ip_address = %s';
            $params[] = $ip;
        }

        $where_sql = implode( ' AND ', $where );

        // Total.
        $count_query = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
        $total = (int) ( $params
            ? $db->get_var( $count_query, ...$params )
            : $db->get_var( $count_query )
        );

        // Resultados.
        $params[] = $per_page;
        $params[] = $offset;
        $data_query = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY created_at DESC LIMIT %d OFFSET %d";
        $items = $db->get_results( $data_query, ...$params );

        return array(
            'items'    => $items,
            'total'    => $total,
            'pages'    => (int) ceil( $total / $per_page ),
            'page'     => $page,
            'per_page' => $per_page,
        );
    }

    /**
     * Bloqueo rápido de IP desde la lista de eventos.
     */
    private function handle_block_from_events(): void {
        if ( ! isset( $_GET['wps_action'] ) || 'block_ip' !== $_GET['wps_action'] ) {
            return;
        }

        $block_ip = isset( $_GET['block_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['block_ip'] ) ) : '';
        if ( ! $block_ip || ! WPS_Ip_Utils::is_valid_ip( $block_ip ) ) {
            return;
        }

        if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_block_from_events_' . $block_ip ) ) {
            return;
        }

        $blocker = WPS_Blocker::get_instance();
        $blocker->block_ip( $block_ip, 'manual', __( 'Bloqueado desde visor de eventos', 'wp-secure' ) );

        wp_safe_redirect( admin_url( 'admin.php?page=wp-secure-events' ) );
        exit;
    }

    /**
     * Lista de tipos de evento para el filtro.
     */
    private function get_event_types(): array {
        return array(
            WPS_Event_Types::LOGIN_FAILED       => WPS_Event_Types::label( WPS_Event_Types::LOGIN_FAILED ),
            WPS_Event_Types::LOGIN_BLOCKED       => WPS_Event_Types::label( WPS_Event_Types::LOGIN_BLOCKED ),
            WPS_Event_Types::LOGIN_SUCCESS       => WPS_Event_Types::label( WPS_Event_Types::LOGIN_SUCCESS ),
            WPS_Event_Types::XMLRPC_BLOCKED      => WPS_Event_Types::label( WPS_Event_Types::XMLRPC_BLOCKED ),
            WPS_Event_Types::IP_BLOCKED          => WPS_Event_Types::label( WPS_Event_Types::IP_BLOCKED ),
            WPS_Event_Types::MANUAL_BLOCK        => WPS_Event_Types::label( WPS_Event_Types::MANUAL_BLOCK ),
            WPS_Event_Types::MANUAL_UNBLOCK      => WPS_Event_Types::label( WPS_Event_Types::MANUAL_UNBLOCK ),
            WPS_Event_Types::SETTINGS_CHANGED    => WPS_Event_Types::label( WPS_Event_Types::SETTINGS_CHANGED ),
        );
    }

    /**
     * Paginación con filtros mantenidos.
     */
    private function render_pagination( array $result, string $severity, string $etype, string $ip ): void {
        if ( $result['pages'] <= 1 ) {
            return;
        }

        $base_url = admin_url( 'admin.php?page=wp-secure-events' );
        $args     = array();
        if ( $severity ) {
            $args['severity'] = $severity;
        }
        if ( $etype ) {
            $args['event_type'] = $etype;
        }
        if ( $ip ) {
            $args['ip'] = $ip;
        }

        echo '<div class="wps-pagination">';
        for ( $i = 1; $i <= $result['pages']; $i++ ) {
            $args['paged'] = $i;
            $class = ( $i === $result['page'] ) ? 'button button-primary' : 'button';
            printf(
                '<a href="%s" class="%s">%d</a> ',
                esc_url( add_query_arg( $args, $base_url ) ),
                esc_attr( $class ),
                $i
            );
        }
        echo '</div>';
    }
}
