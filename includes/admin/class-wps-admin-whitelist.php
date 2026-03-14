<?php
defined( 'ABSPATH' ) || exit;

/**
 * Panel de gestión de la whitelist.
 */
class WPS_Admin_Whitelist {

    /** @var WPS_Loader */
    private $loader;

    public function __construct( WPS_Loader $loader ) {
        $this->loader = $loader;
    }

    /**
     * Renderizar la página de whitelist.
     */
    public function render(): void {
        $whitelist = WPS_Whitelist::get_instance();
        $page      = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
        $filter    = isset( $_GET['type'] ) ? sanitize_text_field( wp_unslash( $_GET['type'] ) ) : '';
        $result    = $whitelist->get_paginated( $page, 20, $filter );
        $message   = $this->handle_actions();
        $request   = WPS_Request::get_instance();
        ?>
        <div class="wrap wps-wrap">
            <h1>
                <?php esc_html_e( 'WP Seguro — Whitelist', 'wp-secure' ); ?>
                <a href="#wps-add-whitelist-form" class="page-title-action" id="wps-toggle-add-whitelist">
                    <?php esc_html_e( 'Agregar IP', 'wp-secure' ); ?>
                </a>
            </h1>

            <?php if ( $message ) : ?>
                <div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible">
                    <p><?php echo esc_html( $message['text'] ); ?></p>
                </div>
            <?php endif; ?>

            <!-- Filtros -->
            <div class="wps-filters">
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-whitelist' ) ); ?>"
                   class="button <?php echo empty( $filter ) ? 'button-primary' : ''; ?>">
                    <?php esc_html_e( 'Todas', 'wp-secure' ); ?>
                </a>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-whitelist&type=global' ) ); ?>"
                   class="button <?php echo 'global' === $filter ? 'button-primary' : ''; ?>">
                    <?php esc_html_e( 'Global', 'wp-secure' ); ?>
                </a>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-whitelist&type=login' ) ); ?>"
                   class="button <?php echo 'login' === $filter ? 'button-primary' : ''; ?>">
                    <?php esc_html_e( 'Login', 'wp-secure' ); ?>
                </a>
            </div>

            <!-- Formulario para agregar -->
            <div id="wps-add-whitelist-form" class="wps-section" style="display:none;">
                <h2><?php esc_html_e( 'Agregar IP a la Whitelist', 'wp-secure' ); ?></h2>
                <form method="post">
                    <?php wp_nonce_field( 'wps_whitelist_add', 'wps_whitelist_nonce' ); ?>
                    <input type="hidden" name="wps_action" value="whitelist_add" />
                    <table class="form-table">
                        <tr>
                            <th><label for="wps-wl-ip"><?php esc_html_e( 'IP o CIDR', 'wp-secure' ); ?></label></th>
                            <td>
                                <input type="text" id="wps-wl-ip" name="wps_ip" class="regular-text"
                                       placeholder="<?php echo esc_attr( $request->ip() ); ?>" required />
                                <p class="description">
                                    <?php
                                    printf(
                                        /* translators: %s: current IP address */
                                        esc_html__( 'Tu IP actual: %s', 'wp-secure' ),
                                        '<code>' . esc_html( $request->ip() ) . '</code>'
                                    );
                                    ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="wps-wl-label"><?php esc_html_e( 'Etiqueta', 'wp-secure' ); ?></label></th>
                            <td>
                                <input type="text" id="wps-wl-label" name="wps_label" class="regular-text"
                                       placeholder="<?php esc_attr_e( 'Mi oficina', 'wp-secure' ); ?>" required />
                            </td>
                        </tr>
                        <tr>
                            <th><label for="wps-wl-type"><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></label></th>
                            <td>
                                <select id="wps-wl-type" name="wps_type">
                                    <option value="global"><?php esc_html_e( 'Global — No se bloquea nunca', 'wp-secure' ); ?></option>
                                    <option value="login"><?php esc_html_e( 'Login — Permitir login desde esta IP', 'wp-secure' ); ?></option>
                                </select>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button( __( 'Agregar a Whitelist', 'wp-secure' ), 'primary', 'submit', true ); ?>
                </form>
            </div>

            <!-- Tabla de whitelist -->
            <div class="wps-section">
                <table class="wps-table widefat striped">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'IP / CIDR', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Etiqueta', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
                            <th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php if ( empty( $result['items'] ) ) : ?>
                        <tr>
                            <td colspan="5" class="wps-no-data">
                                <?php esc_html_e( 'No hay entradas en la whitelist.', 'wp-secure' ); ?>
                            </td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $result['items'] as $entry ) : ?>
                            <tr>
                                <td><code><?php echo esc_html( $entry['ip_address'] ?: $entry['cidr'] ?: '—' ); ?></code></td>
                                <td><?php echo esc_html( $entry['label'] ); ?></td>
                                <td>
                                    <span class="wps-badge wps-badge-<?php echo esc_attr( 'login' === $entry['whitelist_type'] ? 'warning' : 'ok' ); ?>">
                                        <?php echo esc_html( 'login' === $entry['whitelist_type'] ? __( 'Login', 'wp-secure' ) : __( 'Global', 'wp-secure' ) ); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html( wp_date( 'Y-m-d H:i', strtotime( $entry['created_at'] ) ) ); ?></td>
                                <td>
                                    <a href="<?php echo esc_url( wp_nonce_url(
                                        admin_url( 'admin.php?page=wp-secure-whitelist&wps_action=remove&entry_id=' . $entry['id'] . ( $filter ? '&type=' . $filter : '' ) ),
                                        'wps_whitelist_remove_' . $entry['id']
                                    ) ); ?>" class="button button-small button-link-delete" data-wps-confirm="<?php esc_attr_e( '¿Eliminar esta entrada de la whitelist?', 'wp-secure' ); ?>">
                                        <?php esc_html_e( 'Eliminar', 'wp-secure' ); ?>
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                    </tbody>
                </table>

                <?php $this->render_pagination( $result, $filter ); ?>
            </div>
        </div>
        <?php
    }

    /**
     * Procesar acciones (agregar/eliminar).
     */
    private function handle_actions(): ?array {
        $whitelist = WPS_Whitelist::get_instance();

        // Eliminar.
        if ( isset( $_GET['wps_action'] ) && 'remove' === $_GET['wps_action'] ) {
            $entry_id = absint( $_GET['entry_id'] ?? 0 );
            if ( $entry_id && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_whitelist_remove_' . $entry_id ) ) {
                if ( $whitelist->remove( $entry_id ) ) {
                    return array( 'type' => 'success', 'text' => __( 'Entrada eliminada de la whitelist.', 'wp-secure' ) );
                }
            }
            return array( 'type' => 'error', 'text' => __( 'Error al eliminar.', 'wp-secure' ) );
        }

        // Agregar.
        if ( isset( $_POST['wps_action'] ) && 'whitelist_add' === $_POST['wps_action'] ) {
            if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_whitelist_nonce'] ?? '' ) ), 'wps_whitelist_add' ) ) {
                return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
            }

            $ip    = sanitize_text_field( wp_unslash( $_POST['wps_ip'] ?? '' ) );
            $label = sanitize_text_field( wp_unslash( $_POST['wps_label'] ?? '' ) );
            $type  = sanitize_text_field( wp_unslash( $_POST['wps_type'] ?? 'global' ) );

            if ( ! in_array( $type, array( 'global', 'login' ), true ) ) {
                $type = 'global';
            }

            if ( false !== strpos( $ip, '/' ) ) {
                $result = $whitelist->add_cidr( $ip, $label, $type );
            } else {
                $result = $whitelist->add_ip( $ip, $label, $type );
            }

            if ( $result ) {
                return array( 'type' => 'success', 'text' => sprintf( __( 'IP %s agregada a la whitelist.', 'wp-secure' ), $ip ) );
            }

            return array( 'type' => 'error', 'text' => __( 'No se pudo agregar. Verifique que la IP sea válida y no esté ya en la whitelist.', 'wp-secure' ) );
        }

        return null;
    }

    /**
     * Paginación.
     */
    private function render_pagination( array $result, string $filter ): void {
        if ( $result['pages'] <= 1 ) {
            return;
        }

        $base_url = admin_url( 'admin.php?page=wp-secure-whitelist' . ( $filter ? '&type=' . $filter : '' ) );
        echo '<div class="wps-pagination">';
        for ( $i = 1; $i <= $result['pages']; $i++ ) {
            $class = ( $i === $result['page'] ) ? 'button button-primary' : 'button';
            printf(
                '<a href="%s" class="%s">%d</a> ',
                esc_url( add_query_arg( 'paged', $i, $base_url ) ),
                esc_attr( $class ),
                $i
            );
        }
        echo '</div>';
    }
}
