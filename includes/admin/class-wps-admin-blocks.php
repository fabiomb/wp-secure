<?php
defined( 'ABSPATH' ) || exit;

/**
 * Panel de gestión de bloqueos.
 *
 * Incluye tabs para IPs bloqueadas, países bloqueados y ASNs bloqueados.
 */
class WPS_Admin_Blocks {

    /** @var WPS_Loader */
    private $loader;

    public function __construct( WPS_Loader $loader ) {
        $this->loader = $loader;
    }

    /**
     * Renderizar la página de bloqueos con tabs.
     */
    public function render(): void {
        $active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'ips';
        if ( ! in_array( $active_tab, array( 'ips', 'countries', 'asns' ), true ) ) {
            $active_tab = 'ips';
        }

        $message = $this->handle_actions();
        ?>
        <div class="wrap wps-wrap">
            <h1><?php esc_html_e( 'WP Seguro — Bloqueos Activos', 'wp-secure' ); ?></h1>

            <?php if ( $message ) : ?>
                <div class="notice notice-<?php echo esc_attr( $message['type'] ); ?> is-dismissible">
                    <p><?php echo esc_html( $message['text'] ); ?></p>
                </div>
            <?php endif; ?>

            <!-- Tabs -->
            <nav class="nav-tab-wrapper wps-tabs">
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-blocks&tab=ips' ) ); ?>"
                   class="nav-tab <?php echo 'ips' === $active_tab ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-admin-site-alt3"></span>
                    <?php esc_html_e( 'IPs Bloqueadas', 'wp-secure' ); ?>
                </a>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-blocks&tab=countries' ) ); ?>"
                   class="nav-tab <?php echo 'countries' === $active_tab ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-flag"></span>
                    <?php esc_html_e( 'Países', 'wp-secure' ); ?>
                </a>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-blocks&tab=asns' ) ); ?>"
                   class="nav-tab <?php echo 'asns' === $active_tab ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-networking"></span>
                    <?php esc_html_e( 'ASN / Proveedor', 'wp-secure' ); ?>
                </a>
            </nav>

            <?php
            switch ( $active_tab ) {
                case 'countries':
                    $this->render_countries_tab();
                    break;
                case 'asns':
                    $this->render_asns_tab();
                    break;
                default:
                    $this->render_ips_tab();
                    break;
            }
            ?>
        </div>
        <?php
    }

    /*──────────────────────────────────────────────
     * Tab: IPs Bloqueadas
     *──────────────────────────────────────────────*/

    private function render_ips_tab(): void {
        $blocker = WPS_Blocker::get_instance();
        $page    = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
        $result  = $blocker->get_active_blocks( $page, 20 );
        ?>

        <a href="#wps-add-block-form" class="page-title-action" id="wps-toggle-add-block" style="margin: 15px 0; display: inline-block;">
            <?php esc_html_e( 'Bloquear IP', 'wp-secure' ); ?>
        </a>
        <button type="button" class="page-title-action wps-ajax-action" data-action="wps_clean_expired_blocks" data-wps-confirm="<?php esc_attr_e( '¿Limpiar todos los bloqueos expirados?', 'wp-secure' ); ?>" style="margin: 15px 0; display: inline-block;">
            <span class="dashicons dashicons-trash" style="vertical-align:text-top;font-size:16px;"></span>
            <?php esc_html_e( 'Limpiar Expirados', 'wp-secure' ); ?>
        </button>
        <button type="button" class="page-title-action wps-ajax-action" data-action="wps_sync_blocked_ips" data-wps-confirm="<?php esc_attr_e( '¿Sincronizar el archivo de Capa 0 con la base de datos?', 'wp-secure' ); ?>" style="margin: 15px 0; display: inline-block;">
            <span class="dashicons dashicons-update" style="vertical-align:text-top;font-size:16px;"></span>
            <?php esc_html_e( 'Sincronizar Capa 0', 'wp-secure' ); ?>
        </button>

        <!-- Formulario para bloqueo manual -->
        <div id="wps-add-block-form" class="wps-section" style="display:none;">
            <h2><?php esc_html_e( 'Bloquear IP o Rango', 'wp-secure' ); ?></h2>
            <form method="post">
                <?php wp_nonce_field( 'wps_block_ip', 'wps_block_nonce' ); ?>
                <input type="hidden" name="wps_action" value="block_ip" />
                <table class="form-table">
                    <tr>
                        <th><label for="wps-block-ip"><?php esc_html_e( 'IP o CIDR', 'wp-secure' ); ?></label></th>
                        <td>
                            <input type="text" id="wps-block-ip" name="wps_ip" class="regular-text"
                                   placeholder="192.168.1.100 o 192.168.1.0/24" required />
                            <p class="description"><?php esc_html_e( 'IP individual o rango en notación CIDR.', 'wp-secure' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="wps-block-reason"><?php esc_html_e( 'Razón', 'wp-secure' ); ?></label></th>
                        <td>
                            <input type="text" id="wps-block-reason" name="wps_reason" class="regular-text"
                                   placeholder="Actividad sospechosa" required />
                        </td>
                    </tr>
                    <tr>
                        <th><label for="wps-block-duration"><?php esc_html_e( 'Duración', 'wp-secure' ); ?></label></th>
                        <td>
                            <select id="wps-block-duration" name="wps_duration">
                                <option value="0"><?php esc_html_e( 'Permanente', 'wp-secure' ); ?></option>
                                <option value="15"><?php esc_html_e( '15 minutos', 'wp-secure' ); ?></option>
                                <option value="60"><?php esc_html_e( '1 hora', 'wp-secure' ); ?></option>
                                <option value="1440"><?php esc_html_e( '24 horas', 'wp-secure' ); ?></option>
                                <option value="10080"><?php esc_html_e( '7 días', 'wp-secure' ); ?></option>
                                <option value="43200"><?php esc_html_e( '30 días', 'wp-secure' ); ?></option>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button( __( 'Bloquear', 'wp-secure' ), 'primary', 'submit', true ); ?>
            </form>
        </div>

        <!-- Tabla de bloqueos activos -->
        <div class="wps-section">
            <table class="wps-table widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'IP / Rango', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Tipo', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Razón', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Expira', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Hits', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if ( empty( $result['items'] ) ) : ?>
                    <tr>
                        <td colspan="7" class="wps-no-data">
                            <?php esc_html_e( 'No hay IPs bloqueadas actualmente.', 'wp-secure' ); ?>
                        </td>
                    </tr>
                <?php else : ?>
                    <?php foreach ( $result['items'] as $block ) : ?>
                        <tr>
                            <td>
                                <?php
                                $display_ip = $block['ip_address'] ?: $block['cidr'] ?: '—';
                                if ( ! empty( $block['ip_address'] ) ) : ?>
                                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-traffic&ip=' . urlencode( $block['ip_address'] ) ) ); ?>">
                                        <code><?php echo esc_html( $display_ip ); ?></code>
                                    </a>
                                <?php else : ?>
                                    <code><?php echo esc_html( $display_ip ); ?></code>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="wps-badge wps-badge-<?php echo esc_attr( $this->type_badge( $block['block_type'] ) ); ?>">
                                    <?php echo esc_html( $this->type_label( $block['block_type'] ) ); ?>
                                </span>
                            </td>
                            <td><?php echo esc_html( $block['reason'] ); ?></td>
                            <td><?php echo esc_html( wp_date( 'Y-m-d H:i', strtotime( $block['blocked_at'] ) ) ); ?></td>
                            <td>
                                <?php if ( $block['expires_at'] ) : ?>
                                    <?php echo esc_html( wp_date( 'Y-m-d H:i', strtotime( $block['expires_at'] ) ) ); ?>
                                <?php else : ?>
                                    <strong><?php esc_html_e( 'Permanente', 'wp-secure' ); ?></strong>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html( number_format_i18n( (int) $block['hit_count'] ) ); ?></td>
                            <td>
                                <?php if ( ! empty( $block['ip_address'] ) ) : ?>
                                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-traffic&ip=' . urlencode( $block['ip_address'] ) ) ); ?>" class="button button-small" title="<?php esc_attr_e( 'Ver detalle', 'wp-secure' ); ?>">
                                        <span class="dashicons dashicons-visibility" style="font-size:14px;line-height:1.8;"></span>
                                    </a>
                                <?php endif; ?>
                                <a href="<?php echo esc_url( wp_nonce_url(
                                    admin_url( 'admin.php?page=wp-secure-blocks&tab=ips&wps_action=unblock&block_id=' . $block['id'] ),
                                    'wps_unblock_' . $block['id']
                                ) ); ?>" class="button button-small" data-wps-confirm="<?php esc_attr_e( '¿Desbloquear esta IP?', 'wp-secure' ); ?>">
                                    <?php esc_html_e( 'Desbloquear', 'wp-secure' ); ?>
                                </a>
                                <?php if ( $block['expires_at'] ) : ?>
                                    <button type="button" class="button button-small wps-ajax-action" data-action="wps_make_permanent" data-id="<?php echo esc_attr( $block['id'] ); ?>" title="<?php esc_attr_e( 'Convertir a bloqueo permanente', 'wp-secure' ); ?>">
                                        <?php esc_html_e( 'Permanente', 'wp-secure' ); ?>
                                    </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>

            <?php $this->render_pagination( $result, 'ips' ); ?>
        </div>
        <?php
    }

    /*──────────────────────────────────────────────
     * Tab: Países Bloqueados
     *──────────────────────────────────────────────*/

    private function render_countries_tab(): void {
        $blocker           = WPS_Blocker::get_instance();
        $blocked_countries = $blocker->get_blocked_countries();
        $all_countries     = WPS_Geo::get_countries_list();
        ?>

        <!-- Formulario para bloquear país -->
        <div class="wps-section" style="margin-top: 15px;">
            <h2><?php esc_html_e( 'Bloquear País', 'wp-secure' ); ?></h2>
            <form method="post">
                <?php wp_nonce_field( 'wps_block_country', 'wps_block_country_nonce' ); ?>
                <input type="hidden" name="wps_action" value="block_country" />
                <p>
                    <select name="wps_country_code" id="wps-country-select" class="wps-country-select" required>
                        <option value=""><?php esc_html_e( '— Seleccionar país —', 'wp-secure' ); ?></option>
                        <?php
                        $blocked_codes = array_column( $blocked_countries, 'country_code' );
                        foreach ( $all_countries as $code => $name ) :
                            if ( in_array( $code, $blocked_codes, true ) ) {
                                continue;
                            }
                            ?>
                            <option value="<?php echo esc_attr( $code ); ?>"><?php echo esc_html( $name . ' (' . $code . ')' ); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <?php submit_button( __( 'Bloquear País', 'wp-secure' ), 'primary', 'submit', false ); ?>
                </p>
            </form>
        </div>

        <!-- Lista de países bloqueados -->
        <div class="wps-section">
            <h2><?php esc_html_e( 'Países Bloqueados', 'wp-secure' ); ?>
                <span class="wps-badge wps-badge-info"><?php echo count( $blocked_countries ); ?></span>
            </h2>

            <table class="wps-table widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'Código', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'País', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Bloqueado por', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if ( empty( $blocked_countries ) ) : ?>
                    <tr>
                        <td colspan="5" class="wps-no-data">
                            <?php esc_html_e( 'No hay países bloqueados.', 'wp-secure' ); ?>
                        </td>
                    </tr>
                <?php else : ?>
                    <?php foreach ( $blocked_countries as $country ) : ?>
                        <tr>
                            <td><code><?php echo esc_html( $country['country_code'] ); ?></code></td>
                            <td><?php echo esc_html( $country['country_name'] ); ?></td>
                            <td><?php echo esc_html( $country['blocked_by'] ); ?></td>
                            <td><?php echo esc_html( wp_date( 'Y-m-d H:i', strtotime( $country['blocked_at'] ) ) ); ?></td>
                            <td>
                                <a href="<?php echo esc_url( wp_nonce_url(
                                    admin_url( 'admin.php?page=wp-secure-blocks&tab=countries&wps_action=unblock_country&country_code=' . $country['country_code'] ),
                                    'wps_unblock_country_' . $country['country_code']
                                ) ); ?>" class="button button-small" data-wps-confirm="<?php
                                    echo esc_attr( sprintf(
                                        /* translators: %s: country name */
                                        __( '¿Desbloquear %s?', 'wp-secure' ),
                                        $country['country_name']
                                    ) );
                                ?>">
                                    <?php esc_html_e( 'Desbloquear', 'wp-secure' ); ?>
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    /*──────────────────────────────────────────────
     * Tab: ASNs Bloqueados
     *──────────────────────────────────────────────*/

    private function render_asns_tab(): void {
        $blocker      = WPS_Blocker::get_instance();
        $blocked_asns = $blocker->get_blocked_asns();

        $prefill_asn      = isset( $_GET['prefill_asn'] ) ? absint( $_GET['prefill_asn'] ) : 0;
        $prefill_asn_name = isset( $_GET['prefill_asn_name'] ) ? sanitize_text_field( wp_unslash( $_GET['prefill_asn_name'] ) ) : '';
        ?>

        <!-- Formulario para bloquear ASN -->
        <div class="wps-section" style="margin-top: 15px;">
            <h2><?php esc_html_e( 'Bloquear ASN', 'wp-secure' ); ?></h2>
            <form method="post">
                <?php wp_nonce_field( 'wps_block_asn', 'wps_block_asn_nonce' ); ?>
                <input type="hidden" name="wps_action" value="block_asn" />
                <table class="form-table">
                    <tr>
                        <th><label for="wps-asn-number"><?php esc_html_e( 'Número ASN', 'wp-secure' ); ?></label></th>
                        <td>
                            <input type="number" id="wps-asn-number" name="wps_asn" class="small-text"
                                   min="1" placeholder="15169" required value="<?php echo esc_attr( $prefill_asn ?: '' ); ?>" />
                            <p class="description"><?php esc_html_e( 'Número ASN sin prefijo "AS" (ejemplo: 15169 para Google).', 'wp-secure' ); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="wps-asn-name"><?php esc_html_e( 'Nombre / Proveedor', 'wp-secure' ); ?></label></th>
                        <td>
                            <input type="text" id="wps-asn-name" name="wps_asn_name" class="regular-text"
                                   placeholder="Google LLC" required value="<?php echo esc_attr( $prefill_asn_name ); ?>" />
                        </td>
                    </tr>
                </table>
                <?php submit_button( __( 'Bloquear ASN', 'wp-secure' ), 'primary', 'submit', true ); ?>
            </form>
        </div>

        <!-- Lista de ASNs bloqueados -->
        <div class="wps-section">
            <h2><?php esc_html_e( 'ASNs Bloqueados', 'wp-secure' ); ?>
                <span class="wps-badge wps-badge-info"><?php echo count( $blocked_asns ); ?></span>
            </h2>

            <table class="wps-table widefat striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e( 'ASN', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Nombre / Proveedor', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Bloqueado por', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Fecha', 'wp-secure' ); ?></th>
                        <th><?php esc_html_e( 'Acciones', 'wp-secure' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if ( empty( $blocked_asns ) ) : ?>
                    <tr>
                        <td colspan="5" class="wps-no-data">
                            <?php esc_html_e( 'No hay ASNs bloqueados.', 'wp-secure' ); ?>
                        </td>
                    </tr>
                <?php else : ?>
                    <?php foreach ( $blocked_asns as $asn ) : ?>
                        <tr>
                            <td><code>AS<?php echo esc_html( $asn['asn'] ); ?></code></td>
                            <td><?php echo esc_html( $asn['asn_name'] ); ?></td>
                            <td><?php echo esc_html( $asn['blocked_by'] ); ?></td>
                            <td><?php echo esc_html( wp_date( 'Y-m-d H:i', strtotime( $asn['blocked_at'] ) ) ); ?></td>
                            <td>
                                <a href="<?php echo esc_url( wp_nonce_url(
                                    admin_url( 'admin.php?page=wp-secure-blocks&tab=asns&wps_action=unblock_asn&asn=' . $asn['asn'] ),
                                    'wps_unblock_asn_' . $asn['asn']
                                ) ); ?>" class="button button-small" data-wps-confirm="<?php
                                    echo esc_attr( sprintf(
                                        /* translators: %s: ASN name */
                                        __( '¿Desbloquear AS%1$s (%2$s)?', 'wp-secure' ),
                                        $asn['asn'],
                                        $asn['asn_name']
                                    ) );
                                ?>">
                                    <?php esc_html_e( 'Desbloquear', 'wp-secure' ); ?>
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    /*──────────────────────────────────────────────
     * Acciones
     *──────────────────────────────────────────────*/

    /**
     * Procesar acciones (bloquear/desbloquear IPs, países, ASNs).
     */
    private function handle_actions(): ?array {
        $blocker = WPS_Blocker::get_instance();

        // ── Desbloquear IP (GET) ──
        if ( isset( $_GET['wps_action'] ) && 'unblock' === $_GET['wps_action'] ) {
            $block_id = absint( $_GET['block_id'] ?? 0 );
            if ( $block_id && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_unblock_' . $block_id ) ) {
                if ( $blocker->unblock( $block_id ) ) {
                    return array( 'type' => 'success', 'text' => __( 'IP desbloqueada correctamente.', 'wp-secure' ) );
                }
            }
            return array( 'type' => 'error', 'text' => __( 'Error al desbloquear.', 'wp-secure' ) );
        }

        // ── Desbloquear País (GET) ──
        if ( isset( $_GET['wps_action'] ) && 'unblock_country' === $_GET['wps_action'] ) {
            $code = sanitize_text_field( wp_unslash( $_GET['country_code'] ?? '' ) );
            if ( $code && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_unblock_country_' . $code ) ) {
                if ( $blocker->unblock_country( $code ) ) {
                    return array( 'type' => 'success', 'text' => sprintf( __( 'País %s desbloqueado.', 'wp-secure' ), $code ) );
                }
            }
            return array( 'type' => 'error', 'text' => __( 'Error al desbloquear país.', 'wp-secure' ) );
        }

        // ── Desbloquear ASN (GET) ──
        if ( isset( $_GET['wps_action'] ) && 'unblock_asn' === $_GET['wps_action'] ) {
            $asn = absint( $_GET['asn'] ?? 0 );
            if ( $asn && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_unblock_asn_' . $asn ) ) {
                if ( $blocker->unblock_asn( $asn ) ) {
                    return array( 'type' => 'success', 'text' => sprintf( __( 'ASN %d desbloqueado.', 'wp-secure' ), $asn ) );
                }
            }
            return array( 'type' => 'error', 'text' => __( 'Error al desbloquear ASN.', 'wp-secure' ) );
        }

        // ── Bloquear IP (POST) ──
        if ( isset( $_POST['wps_action'] ) && 'block_ip' === $_POST['wps_action'] ) {
            if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_block_nonce'] ?? '' ) ), 'wps_block_ip' ) ) {
                return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
            }

            $ip       = sanitize_text_field( wp_unslash( $_POST['wps_ip'] ?? '' ) );
            $reason   = sanitize_text_field( wp_unslash( $_POST['wps_reason'] ?? '' ) );
            $duration = absint( $_POST['wps_duration'] ?? 0 );
            $minutes  = $duration > 0 ? $duration : null;

            if ( false !== strpos( $ip, '/' ) ) {
                $result = $blocker->block_cidr( $ip, 'manual', $reason, $minutes );
            } else {
                $result = $blocker->block_ip( $ip, 'manual', $reason, $minutes );
            }

            if ( $result ) {
                $logger = WPS_Logger::get_instance();
                $logger->event_immediate( WPS_Event_Types::MANUAL_BLOCK, array(
                    'ip_address' => $ip,
                    'wp_user_id' => get_current_user_id(),
                    'details'    => array( 'reason' => $reason, 'duration' => $minutes ? $minutes . ' min' : 'permanent' ),
                ) );
                return array( 'type' => 'success', 'text' => sprintf( __( 'IP %s bloqueada correctamente.', 'wp-secure' ), $ip ) );
            }

            return array( 'type' => 'error', 'text' => __( 'No se pudo bloquear la IP. Verifique que sea válida y que no esté en la whitelist.', 'wp-secure' ) );
        }

        // ── Bloquear País (POST) ──
        if ( isset( $_POST['wps_action'] ) && 'block_country' === $_POST['wps_action'] ) {
            if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_block_country_nonce'] ?? '' ) ), 'wps_block_country' ) ) {
                return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
            }

            $code         = sanitize_text_field( wp_unslash( $_POST['wps_country_code'] ?? '' ) );
            $all_countries = WPS_Geo::get_countries_list();
            $country_name  = $all_countries[ strtoupper( $code ) ] ?? $code;

            if ( $blocker->block_country( $code, $country_name ) ) {
                return array( 'type' => 'success', 'text' => sprintf( __( 'País %s bloqueado correctamente.', 'wp-secure' ), $country_name ) );
            }

            return array( 'type' => 'error', 'text' => __( 'No se pudo bloquear el país.', 'wp-secure' ) );
        }

        // ── Bloquear ASN (POST) ──
        if ( isset( $_POST['wps_action'] ) && 'block_asn' === $_POST['wps_action'] ) {
            if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_block_asn_nonce'] ?? '' ) ), 'wps_block_asn' ) ) {
                return array( 'type' => 'error', 'text' => __( 'Nonce inválido.', 'wp-secure' ) );
            }

            $asn      = absint( $_POST['wps_asn'] ?? 0 );
            $asn_name = sanitize_text_field( wp_unslash( $_POST['wps_asn_name'] ?? '' ) );

            if ( $asn > 0 && $blocker->block_asn( $asn, $asn_name ) ) {
                return array( 'type' => 'success', 'text' => sprintf( __( 'ASN %d (%s) bloqueado correctamente.', 'wp-secure' ), $asn, $asn_name ) );
            }

            return array( 'type' => 'error', 'text' => __( 'No se pudo bloquear el ASN. Verifique que el número sea válido.', 'wp-secure' ) );
        }

        return null;
    }

    /**
     * Etiqueta legible del tipo de bloqueo.
     */
    private function type_label( string $type ): string {
        $labels = array(
            'manual'       => __( 'Manual', 'wp-secure' ),
            'auto_login'   => __( 'Login', 'wp-secure' ),
            'auto_xmlrpc'  => __( 'XML-RPC', 'wp-secure' ),
            'auto_sqli'    => __( 'SQLi', 'wp-secure' ),
            'auto_xss'     => __( 'XSS', 'wp-secure' ),
            'auto_rate'    => __( 'Rate Limit', 'wp-secure' ),
            'auto_scanner' => __( 'Scanner', 'wp-secure' ),
            'auto_traversal' => __( 'Traversal', 'wp-secure' ),
        );
        return $labels[ $type ] ?? $type;
    }

    /**
     * Clase de badge según tipo.
     */
    private function type_badge( string $type ): string {
        if ( 'manual' === $type ) {
            return 'info';
        }
        return 'warning';
    }

    /**
     * Paginación.
     */
    private function render_pagination( array $result, string $tab = 'ips' ): void {
        if ( $result['pages'] <= 1 ) {
            return;
        }

        $base_url = admin_url( 'admin.php?page=wp-secure-blocks&tab=' . $tab );
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
