<?php
defined( 'ABSPATH' ) || exit;

/**
 * Patrones de ataque recurrentes.
 *
 * El visor de eventos muestra hechos sueltos: una IP, una URI, una hora. Para
 * decidir una regla hace falta la otra vista — qué rutas se repiten, desde
 * cuántas IPs distintas y desde cuándo. Esta pantalla agrupa los eventos por
 * ruta para que un patrón de cientos de intentos se resuelva con una regla en
 * vez de con un bloqueo de IP por vez.
 */
class WPS_Admin_Patterns {

    /** @var WPS_Loader */
    private $loader;

    /** Períodos disponibles para el análisis, en días. */
    private const PERIODS = array( 1, 7, 30 );

    public function __construct( WPS_Loader $loader ) {
        $this->loader = $loader;
    }

    /**
     * Renderizar la página de patrones.
     */
    public function render(): void {
        $days      = $this->requested_days();
        $min_hits  = isset( $_GET['min_hits'] ) ? max( 2, absint( $_GET['min_hits'] ) ) : 5;
        $patterns  = $this->get_patterns( $days, $min_hits );
        $rules     = WPS_Custom_Rules::get_instance()->get_active_rules();
        ?>
        <div class="wrap wps-wrap">
            <h1><?php esc_html_e( 'WP Seguro — Patrones Recurrentes', 'wp-secure' ); ?></h1>

            <p class="description">
                <?php esc_html_e( 'Rutas que aparecen repetidamente en los eventos de seguridad, agrupadas. Un patrón con muchas IPs distintas es un barrido automatizado: conviene resolverlo con una regla y no bloqueando IP por IP.', 'wp-secure' ); ?>
            </p>

            <div class="wps-section">
                <form method="get" class="wps-filters-form">
                    <input type="hidden" name="page" value="wp-secure-patterns" />

                    <label for="wps-pattern-days"><?php esc_html_e( 'Período:', 'wp-secure' ); ?></label>
                    <select id="wps-pattern-days" name="days">
                        <?php foreach ( self::PERIODS as $period ) : ?>
                            <option value="<?php echo esc_attr( $period ); ?>" <?php selected( $days, $period ); ?>>
                                <?php
                                printf(
                                    /* translators: %d: number of days */
                                    esc_html( _n( 'Último %d día', 'Últimos %d días', $period, 'wp-secure' ) ),
                                    (int) $period
                                );
                                ?>
                            </option>
                        <?php endforeach; ?>
                    </select>

                    <label for="wps-pattern-min"><?php esc_html_e( 'Mínimo de intentos:', 'wp-secure' ); ?></label>
                    <input type="number" id="wps-pattern-min" name="min_hits" value="<?php echo esc_attr( $min_hits ); ?>"
                           min="2" max="1000" class="small-text" />

                    <?php submit_button( __( 'Aplicar', 'wp-secure' ), 'secondary', 'submit', false ); ?>
                </form>
            </div>

            <div class="wps-section">
                <table class="wps-table widefat striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Ruta', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Intentos', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'IPs distintas', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Último', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if ( empty( $patterns ) ) : ?>
                        <tr>
                            <td colspan="5" class="wps-no-data">
                                <?php esc_html_e( 'No hay patrones recurrentes en este período. Buena señal.', 'wp-secure' ); ?>
                            </td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $patterns as $pattern ) : ?>
                            <?php
                            $path      = (string) $pattern['path'];
                            $covered   = WPS_Custom_Rules::path_is_covered( $path, $rules );
                            $condition = WPS_Custom_Rules::suggest_condition_from_uri( $path );
                            ?>
                            <tr>
                                <td>
                                    <code title="<?php echo esc_attr( $path ); ?>">
                                        <?php echo esc_html( mb_strimwidth( $path, 0, 70, '…' ) ); ?>
                                    </code>
                                </td>
                                <td><strong><?php echo esc_html( number_format_i18n( (int) $pattern['hits'] ) ); ?></strong></td>
                                <td>
                                    <?php echo esc_html( number_format_i18n( (int) $pattern['unique_ips'] ) ); ?>
                                    <?php if ( (int) $pattern['unique_ips'] >= 10 ) : ?>
                                        <span class="wps-badge wps-badge-warning"><?php esc_html_e( 'barrido', 'wp-secure' ); ?></span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span title="<?php echo esc_attr( $pattern['last_seen'] ); ?>">
                                        <?php echo esc_html( wp_date( 'Y-m-d H:i', strtotime( $pattern['last_seen'] ) ) ); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php if ( $covered ) : ?>
                                        <span class="wps-badge wps-badge-info"><?php esc_html_e( 'Ya cubierto por una regla', 'wp-secure' ); ?></span>
                                    <?php elseif ( null === $condition ) : ?>
                                        <span class="description"><?php esc_html_e( 'Ruta demasiado genérica para una regla', 'wp-secure' ); ?></span>
                                    <?php else : ?>
                                        <a href="<?php echo esc_url( self::new_rule_url( $path ) ); ?>" class="button button-primary button-small">
                                            <?php esc_html_e( 'Crear regla', 'wp-secure' ); ?>
                                        </a>
                                        <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-events&uri=' . rawurlencode( $path ) ) ); ?>" class="button button-small">
                                            <?php esc_html_e( 'Ver eventos', 'wp-secure' ); ?>
                                        </a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    /**
     * URL para abrir el formulario de reglas precargado con una ruta.
     */
    public static function new_rule_url( string $path ): string {
        return wp_nonce_url(
            add_query_arg(
                array(
                    'page'       => 'wp-secure-rules',
                    'wps_action' => 'new_from_event',
                    'field'      => 'uri',
                    'value'      => rawurlencode( $path ),
                ),
                admin_url( 'admin.php' )
            ),
            'wps_new_rule_from_event'
        );
    }

    /**
     * URL para crear una regla a partir del User-Agent de un evento.
     */
    public static function new_rule_url_for_user_agent( string $user_agent ): string {
        return wp_nonce_url(
            add_query_arg(
                array(
                    'page'       => 'wp-secure-rules',
                    'wps_action' => 'new_from_event',
                    'field'      => 'user_agent',
                    'value'      => rawurlencode( $user_agent ),
                ),
                admin_url( 'admin.php' )
            ),
            'wps_new_rule_from_event'
        );
    }

    /**
     * Período solicitado, acotado a los valores permitidos.
     */
    private function requested_days(): int {
        $days = isset( $_GET['days'] ) ? absint( $_GET['days'] ) : 7;

        return in_array( $days, self::PERIODS, true ) ? $days : 7;
    }

    /**
     * Agrupar eventos por ruta.
     *
     * @param int $days     Ventana de análisis.
     * @param int $min_hits Mínimo de intentos para considerarlo patrón.
     */
    private function get_patterns( int $days, int $min_hits ): array {
        $db    = WPS_Db::get_instance();
        $table = WPS_Db_Schema::table( 'security_events' );

        // El query string cambia en cada intento, así que se agrupa por la ruta.
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return $db->get_results(
            "SELECT
                SUBSTRING_INDEX(request_uri, '?', 1) AS path,
                COUNT(*) AS hits,
                COUNT(DISTINCT ip_address) AS unique_ips,
                MAX(created_at) AS last_seen
             FROM {$table}
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
               AND request_uri IS NOT NULL
               AND request_uri <> ''
             GROUP BY path
             HAVING hits >= %d
             ORDER BY hits DESC
             LIMIT 100",
            $days,
            $min_hits
        );
    }
}
