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
        $ip       = isset( $_GET['ip'] ) ? WPS_Ip_Utils::strip_port( sanitize_text_field( wp_unslash( $_GET['ip'] ) ) ) : '';
        $uri      = isset( $_GET['uri'] ) ? sanitize_text_field( wp_unslash( $_GET['uri'] ) ) : '';
        $result   = $this->get_events( $page, 30, $severity, $etype, $ip, $uri );
        $blocked_map = $this->get_blocked_status_map( $result['items'] );
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
                                        <?php
                                        $block_status = $blocked_map[ $event['ip_address'] ] ?? null;
                                        if ( $block_status ) :
                                            $is_permanent = empty( $block_status['expires_at'] );
                                            $icon_class   = $is_permanent ? 'wps-block-permanent' : 'wps-block-temporary';
                                            $icon_title   = $is_permanent
                                                ? __( 'IP bloqueada permanentemente', 'wp-secure' )
                                                : sprintf(
                                                    /* translators: %s: expiration date */
                                                    __( 'IP bloqueada temporalmente hasta %s', 'wp-secure' ),
                                                    wp_date( 'Y-m-d H:i', strtotime( $block_status['expires_at'] ) )
                                                );
                                        ?>
                                            <span class="dashicons dashicons-lock <?php echo esc_attr( $icon_class ); ?>" title="<?php echo esc_attr( $icon_title ); ?>"></span>
                                        <?php endif; ?>
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

                                    <?php
                                    // Crear una regla desde este evento, para
                                    // atacar el patrón y no la IP de turno.
                                    if ( ! empty( $event['request_uri'] )
                                        && null !== WPS_Custom_Rules::suggest_condition_from_uri( $event['request_uri'] ) ) :
                                        ?>
                                        <a href="<?php echo esc_url( WPS_Admin_Patterns::new_rule_url( $event['request_uri'] ) ); ?>"
                                           class="button button-small" title="<?php esc_attr_e( 'Crear una regla a partir de esta ruta', 'wp-secure' ); ?>">
                                            <span class="dashicons dashicons-filter" style="font-size:14px;width:14px;height:14px;line-height:1.8;"></span>
                                        </a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>

                <?php $this->render_pagination( $result, $severity, $etype, $ip, $uri ); ?>
            </div>
        </div>
        <?php
    }

    /**
     * Obtener eventos paginados con filtros.
     */
    private function get_events( int $page, int $per_page, string $severity, string $etype, string $ip, string $uri = '' ): array {
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

        if ( '' !== $uri ) {
            // Coincidencia por prefijo: la ruta llega desde la vista de
            // patrones, ya sin query string.
            $where[]  = 'request_uri LIKE %s';
            $params[] = $db->esc_like( $uri ) . '%';
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
     * Obtener mapa de estado de bloqueo para las IPs de los eventos.
     *
     * @param array $items Eventos con campo ip_address.
     * @return array Mapa IP => row del bloqueo activo (o vacío si no está bloqueada).
     */
    private function get_blocked_status_map( array $items ): array {
        $ips = array();
        foreach ( $items as $event ) {
            if ( ! empty( $event['ip_address'] ) ) {
                $ips[ $event['ip_address'] ] = true;
            }
        }

        if ( empty( $ips ) ) {
            return array();
        }

        $db    = WPS_Db::get_instance();
        $table = WPS_Db_Schema::table( 'blocked_ips' );
        $unique_ips = array_keys( $ips );
        $placeholders = implode( ',', array_fill( 0, count( $unique_ips ), '%s' ) );

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $db->get_results(
            "SELECT ip_address, expires_at FROM {$table}
             WHERE ip_address IN ({$placeholders})
             AND is_active = 1
             AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
            ...$unique_ips
        );

        $map = array();
        foreach ( $rows as $row ) {
            $map[ $row['ip_address'] ] = $row;
        }

        return $map;
    }

    /**
     * Bloqueo rápido de IP desde la lista de eventos.
     *
     * Corre en admin_init, antes de que WordPress emita nada: al ejecutarse
     * durante el render la redirección posterior fallaba con las cabeceras ya
     * enviadas y la tabla quedaba mostrando el estado anterior al bloqueo.
     */
    public function handle_block_from_events(): void {
        if ( ! isset( $_GET['page'] ) || 'wp-secure-events' !== $_GET['page'] ) {
            return;
        }

        if ( ! isset( $_GET['wps_action'] ) || 'block_ip' !== $_GET['wps_action'] ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $block_ip = isset( $_GET['block_ip'] ) ? WPS_Ip_Utils::strip_port( sanitize_text_field( wp_unslash( $_GET['block_ip'] ) ) ) : '';
        if ( ! $block_ip || ! WPS_Ip_Utils::is_valid_ip( $block_ip ) ) {
            return;
        }

        if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_block_from_events_' . $block_ip ) ) {
            return;
        }

        $blocker = WPS_Blocker::get_instance();
        $blocker->block_ip( $block_ip, 'manual', __( 'Bloqueado desde visor de eventos', 'wp-secure' ) );

        $redirect_args = array( 'page' => 'wp-secure-events' );
        foreach ( array( 'paged', 'severity', 'event_type', 'ip', 'uri' ) as $param ) {
            if ( ! empty( $_GET[ $param ] ) ) {
                $redirect_args[ $param ] = sanitize_text_field( wp_unslash( $_GET[ $param ] ) );
            }
        }
        wp_safe_redirect( add_query_arg( $redirect_args, admin_url( 'admin.php' ) ) );
        exit;
    }

    /**
     * Lista de tipos de evento para el filtro.
     *
     * Se deriva de los tipos que el plugin realmente registra, para que no
     * queden detecciones (scanner, SQLi, XSS, reglas personalizadas) sin
     * posibilidad de filtrar.
     */
    private function get_event_types(): array {
        $types = array();

        foreach ( WPS_Event_Types::all() as $type ) {
            $types[ $type ] = WPS_Event_Types::label( $type );
        }

        asort( $types );

        return $types;
    }

    /**
     * Paginación con filtros mantenidos.
     *
     * Muestra una ventana alrededor de la página actual: con decenas de miles
     * de eventos, imprimir un botón por página generaba listas de cientos de
     * enlaces.
     */
    private function render_pagination( array $result, string $severity, string $etype, string $ip, string $uri = '' ): void {
        $total_pages = (int) $result['pages'];
        if ( $total_pages <= 1 ) {
            return;
        }

        $current  = (int) $result['page'];
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
        if ( $uri ) {
            $args['uri'] = $uri;
        }

        $link = function ( int $page, string $label, bool $is_current = false ) use ( $args, $base_url ): void {
            $args['paged'] = $page;
            printf(
                '<a href="%s" class="%s">%s</a> ',
                esc_url( add_query_arg( $args, $base_url ) ),
                esc_attr( $is_current ? 'button button-primary' : 'button' ),
                esc_html( $label )
            );
        };

        $window = 2;
        $from   = max( 1, $current - $window );
        $to     = min( $total_pages, $current + $window );

        echo '<div class="wps-pagination">';

        if ( $current > 1 ) {
            $link( $current - 1, __( '« Anterior', 'wp-secure' ) );
        }

        if ( $from > 1 ) {
            $link( 1, '1' );
            if ( $from > 2 ) {
                echo '<span class="wps-pagination-gap">…</span> ';
            }
        }

        for ( $i = $from; $i <= $to; $i++ ) {
            $link( $i, (string) $i, $i === $current );
        }

        if ( $to < $total_pages ) {
            if ( $to < $total_pages - 1 ) {
                echo '<span class="wps-pagination-gap">…</span> ';
            }
            $link( $total_pages, (string) $total_pages );
        }

        if ( $current < $total_pages ) {
            $link( $current + 1, __( 'Siguiente »', 'wp-secure' ) );
        }

        echo '</div>';
    }
}
