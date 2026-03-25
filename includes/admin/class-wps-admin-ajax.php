<?php
defined( 'ABSPATH' ) || exit;

/**
 * Endpoints AJAX para el panel de administración.
 */
class WPS_Admin_Ajax {

    /** @var WPS_Loader */
    private $loader;

    public function __construct( WPS_Loader $loader ) {
        $this->loader = $loader;
    }

    /**
     * Registrar endpoints AJAX.
     */
    public function init(): void {
        add_action( 'wp_ajax_wps_block_ip', array( $this, 'ajax_block_ip' ) );
        add_action( 'wp_ajax_wps_unblock_ip', array( $this, 'ajax_unblock_ip' ) );
        add_action( 'wp_ajax_wps_make_permanent', array( $this, 'ajax_make_permanent' ) );
        add_action( 'wp_ajax_wps_whitelist_add', array( $this, 'ajax_whitelist_add' ) );
        add_action( 'wp_ajax_wps_whitelist_remove', array( $this, 'ajax_whitelist_remove' ) );
        add_action( 'wp_ajax_wps_get_dashboard_stats', array( $this, 'ajax_dashboard_stats' ) );
        add_action( 'wp_ajax_wps_block_country', array( $this, 'ajax_block_country' ) );
        add_action( 'wp_ajax_wps_unblock_country', array( $this, 'ajax_unblock_country' ) );
        add_action( 'wp_ajax_wps_block_asn', array( $this, 'ajax_block_asn' ) );
        add_action( 'wp_ajax_wps_unblock_asn', array( $this, 'ajax_unblock_asn' ) );
        add_action( 'wp_ajax_wps_geo_lookup', array( $this, 'ajax_geo_lookup' ) );
        add_action( 'wp_ajax_wps_ipdb_download', array( $this, 'ajax_ipdb_download' ) );
        add_action( 'wp_ajax_wps_get_live_traffic', array( $this, 'ajax_get_live_traffic' ) );
        add_action( 'wp_ajax_wps_export_events', array( $this, 'ajax_export_events' ) );
        add_action( 'wp_ajax_wps_export_traffic', array( $this, 'ajax_export_traffic' ) );
        add_action( 'wp_ajax_wps_export_config', array( $this, 'ajax_export_config' ) );
        add_action( 'wp_ajax_wps_import_config', array( $this, 'ajax_import_config' ) );
        add_action( 'wp_ajax_wps_clean_expired_blocks', array( $this, 'ajax_clean_expired_blocks' ) );
    }

    /**
     * Bloquear IP via AJAX.
     */
    public function ajax_block_ip(): void {
        $this->verify_ajax();

        $ip       = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
        $reason   = sanitize_text_field( wp_unslash( $_POST['reason'] ?? __( 'Bloqueo manual', 'wp-secure' ) ) );
        $duration = absint( $_POST['duration'] ?? 0 );
        $minutes  = $duration > 0 ? $duration : null;
        $blocker  = WPS_Blocker::get_instance();

        if ( false !== strpos( $ip, '/' ) ) {
            $result = $blocker->block_cidr( $ip, 'manual', $reason, $minutes );
        } else {
            $result = $blocker->block_ip( $ip, 'manual', $reason, $minutes );
        }

        if ( $result ) {
            wp_send_json_success( array( 'id' => $result, 'message' => __( 'IP bloqueada.', 'wp-secure' ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo bloquear la IP.', 'wp-secure' ) ) );
    }

    /**
     * Desbloquear IP via AJAX.
     */
    public function ajax_unblock_ip(): void {
        $this->verify_ajax();

        $block_id = absint( $_POST['id'] ?? 0 );
        if ( ! $block_id ) {
            wp_send_json_error( array( 'message' => __( 'ID inválido.', 'wp-secure' ) ) );
        }

        $blocker = WPS_Blocker::get_instance();
        if ( $blocker->unblock( $block_id ) ) {
            wp_send_json_success( array( 'message' => __( 'IP desbloqueada.', 'wp-secure' ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo desbloquear.', 'wp-secure' ) ) );
    }

    /**
     * Convertir bloqueo temporal en permanente via AJAX.
     */
    public function ajax_make_permanent(): void {
        $this->verify_ajax();

        $block_id = absint( $_POST['id'] ?? 0 );
        if ( ! $block_id ) {
            wp_send_json_error( array( 'message' => __( 'ID inválido.', 'wp-secure' ) ) );
        }

        $blocker = WPS_Blocker::get_instance();
        if ( $blocker->make_permanent( $block_id ) ) {
            wp_send_json_success( array( 'message' => __( 'Bloqueo convertido a permanente.', 'wp-secure' ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo convertir el bloqueo.', 'wp-secure' ) ) );
    }

    /**
     * Agregar IP a whitelist via AJAX.
     */
    public function ajax_whitelist_add(): void {
        $this->verify_ajax();

        $ip    = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
        $label = sanitize_text_field( wp_unslash( $_POST['label'] ?? '' ) );
        $type  = sanitize_text_field( wp_unslash( $_POST['type'] ?? 'global' ) );

        if ( ! in_array( $type, array( 'global', 'login' ), true ) ) {
            $type = 'global';
        }

        $whitelist = WPS_Whitelist::get_instance();

        if ( false !== strpos( $ip, '/' ) ) {
            $result = $whitelist->add_cidr( $ip, $label, $type );
        } else {
            $result = $whitelist->add_ip( $ip, $label, $type );
        }

        if ( $result ) {
            wp_send_json_success( array( 'id' => $result, 'message' => __( 'IP agregada a whitelist.', 'wp-secure' ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo agregar. Verifique que la IP sea válida.', 'wp-secure' ) ) );
    }

    /**
     * Eliminar entrada de whitelist via AJAX.
     */
    public function ajax_whitelist_remove(): void {
        $this->verify_ajax();

        $entry_id = absint( $_POST['id'] ?? 0 );
        if ( ! $entry_id ) {
            wp_send_json_error( array( 'message' => __( 'ID inválido.', 'wp-secure' ) ) );
        }

        $whitelist = WPS_Whitelist::get_instance();
        if ( $whitelist->remove( $entry_id ) ) {
            wp_send_json_success( array( 'message' => __( 'Entrada eliminada.', 'wp-secure' ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo eliminar.', 'wp-secure' ) ) );
    }

    /**
     * Estadísticas del dashboard via AJAX (para refresco sin recarga).
     */
    public function ajax_dashboard_stats(): void {
        $this->verify_ajax();

        $db             = WPS_Db::get_instance();
        $traffic_table  = WPS_Db_Schema::table( 'traffic_log' );
        $events_table   = WPS_Db_Schema::table( 'security_events' );
        $blocked_table  = WPS_Db_Schema::table( 'blocked_ips' );

        wp_send_json_success( array(
            'total_requests'   => (int) $db->get_var( "SELECT COUNT(*) FROM {$traffic_table} WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)" ),
            'unique_ips'       => (int) $db->get_var( "SELECT COUNT(DISTINCT ip_address) FROM {$traffic_table} WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)" ),
            'blocked_requests' => (int) $db->get_var( "SELECT COUNT(*) FROM {$events_table} WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND severity IN ('warning','critical')" ),
            'active_blocks'    => (int) $db->get_var( "SELECT COUNT(*) FROM {$blocked_table} WHERE is_active = 1" ),
        ) );
    }

    /*──────────────────────────────────────────────
     * Bloqueo por País
     *──────────────────────────────────────────────*/

    /**
     * Bloquear país via AJAX.
     */
    public function ajax_block_country(): void {
        $this->verify_ajax();

        $country_code = sanitize_text_field( wp_unslash( $_POST['country_code'] ?? '' ) );
        $country_name = sanitize_text_field( wp_unslash( $_POST['country_name'] ?? '' ) );

        if ( empty( $country_code ) || strlen( $country_code ) !== 2 ) {
            wp_send_json_error( array( 'message' => __( 'Código de país inválido.', 'wp-secure' ) ) );
        }

        if ( empty( $country_name ) ) {
            $country_name = WPS_Geo::country_name( $country_code );
        }

        $blocker = WPS_Blocker::get_instance();
        if ( $blocker->block_country( $country_code, $country_name ) ) {
            wp_send_json_success( array( 'message' => sprintf( __( 'País %s bloqueado.', 'wp-secure' ), $country_name ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo bloquear el país.', 'wp-secure' ) ) );
    }

    /**
     * Desbloquear país via AJAX.
     */
    public function ajax_unblock_country(): void {
        $this->verify_ajax();

        $country_code = sanitize_text_field( wp_unslash( $_POST['country_code'] ?? '' ) );
        if ( empty( $country_code ) ) {
            wp_send_json_error( array( 'message' => __( 'Código de país inválido.', 'wp-secure' ) ) );
        }

        $blocker = WPS_Blocker::get_instance();
        if ( $blocker->unblock_country( $country_code ) ) {
            wp_send_json_success( array( 'message' => __( 'País desbloqueado.', 'wp-secure' ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo desbloquear el país.', 'wp-secure' ) ) );
    }

    /*──────────────────────────────────────────────
     * Bloqueo por ASN
     *──────────────────────────────────────────────*/

    /**
     * Bloquear ASN via AJAX.
     */
    public function ajax_block_asn(): void {
        $this->verify_ajax();

        $asn      = absint( $_POST['asn'] ?? 0 );
        $asn_name = sanitize_text_field( wp_unslash( $_POST['asn_name'] ?? '' ) );

        if ( $asn <= 0 ) {
            wp_send_json_error( array( 'message' => __( 'Número ASN inválido.', 'wp-secure' ) ) );
        }

        if ( empty( $asn_name ) ) {
            $asn_name = 'AS' . $asn;
        }

        $blocker = WPS_Blocker::get_instance();
        if ( $blocker->block_asn( $asn, $asn_name ) ) {
            wp_send_json_success( array( 'message' => sprintf( __( 'ASN %d bloqueado.', 'wp-secure' ), $asn ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo bloquear el ASN.', 'wp-secure' ) ) );
    }

    /**
     * Desbloquear ASN via AJAX.
     */
    public function ajax_unblock_asn(): void {
        $this->verify_ajax();

        $asn = absint( $_POST['asn'] ?? 0 );
        if ( $asn <= 0 ) {
            wp_send_json_error( array( 'message' => __( 'Número ASN inválido.', 'wp-secure' ) ) );
        }

        $blocker = WPS_Blocker::get_instance();
        if ( $blocker->unblock_asn( $asn ) ) {
            wp_send_json_success( array( 'message' => __( 'ASN desbloqueado.', 'wp-secure' ) ) );
        }

        wp_send_json_error( array( 'message' => __( 'No se pudo desbloquear el ASN.', 'wp-secure' ) ) );
    }

    /*──────────────────────────────────────────────
     * Geo Lookup y IPDB
     *──────────────────────────────────────────────*/

    /**
     * Lookup de geolocalización via AJAX.
     */
    public function ajax_geo_lookup(): void {
        $this->verify_ajax();

        $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
        if ( empty( $ip ) || ! WPS_Ip_Utils::is_valid_ip( $ip ) ) {
            wp_send_json_error( array( 'message' => __( 'IP no válida.', 'wp-secure' ) ) );
        }

        $geo  = WPS_Geo::get_instance();
        $data = $geo->lookup( $ip );

        wp_send_json_success( array(
            'ip'           => $ip,
            'country'      => $data['country'],
            'country_name' => $data['country'] ? WPS_Geo::country_name( $data['country'] ) : null,
            'asn'          => $data['asn'],
            'asn_name'     => $data['asn_name'],
            'source'       => $data['source'],
        ) );
    }

    /**
     * Descargar/actualizar la base de datos MMDB via AJAX.
     */
    public function ajax_ipdb_download(): void {
        $this->verify_ajax();

        $updater = WPS_Ipdb_Updater::get_instance();
        $result  = $updater->download();

        if ( $result['success'] ) {
            wp_send_json_success( array( 'message' => $result['message'] ) );
        }

        wp_send_json_error( array( 'message' => $result['message'] ) );
    }

    /*──────────────────────────────────────────────
     * Tráfico en Vivo
     *──────────────────────────────────────────────*/

    /**
     * Obtener tráfico en vivo via AJAX (polling cada 5s).
     */
    public function ajax_get_live_traffic(): void {
        $this->verify_ajax();

        $db    = WPS_Db::get_instance();
        $table = WPS_Db_Schema::table( 'traffic_log' );

        $where  = array( '1=1' );
        $params = array();

        // Filtro por tipo de visitante.
        $visitor_type = sanitize_text_field( wp_unslash( $_POST['visitor_type'] ?? '' ) );
        if ( $visitor_type ) {
            $where[]  = 'visitor_type = %s';
            $params[] = $visitor_type;
        }

        // Filtro por método HTTP.
        $method = sanitize_text_field( wp_unslash( $_POST['method'] ?? '' ) );
        if ( $method ) {
            $where[]  = 'request_method = %s';
            $params[] = $method;
        }

        // Filtro por IP.
        $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
        if ( $ip ) {
            $where[]  = 'ip_address LIKE %s';
            $params[] = '%' . $db->esc_like( $ip ) . '%';
        }

        // Solo registros del último minuto (polling → recientes).
        $since = sanitize_text_field( wp_unslash( $_POST['since'] ?? '' ) );
        if ( $since ) {
            $where[]  = 'id > %d';
            $params[] = absint( $since );
        }

        $where_sql = implode( ' AND ', $where );
        $query     = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY created_at DESC LIMIT 50";

        if ( ! empty( $params ) ) {
            $query = $db->prepare( $query, ...$params );
        }

        $results = $db->get_results( $query );

        $rows = array();
        foreach ( $results as $row ) {
            $rows[] = array(
                'id'             => (int) $row['id'],
                'created_at'     => wp_date( 'H:i:s', strtotime( $row['created_at'] ) ),
                'ip_address'     => $row['ip_address'],
                'country_code'   => $row['country_code'] ?? '',
                'visitor_type'   => $row['visitor_type'],
                'request_method' => $row['request_method'],
                'request_uri'    => $row['request_uri'],
                'http_status'    => $row['http_status'] ?? '',
                'user_agent'     => $row['user_agent'] ?? '',
            );
        }

        wp_send_json_success( array( 'rows' => $rows ) );
    }

    /*──────────────────────────────────────────────
     * Exportación CSV
     *──────────────────────────────────────────────*/

    /**
     * Exportar eventos de seguridad a CSV.
     */
    public function ajax_export_events(): void {
        $this->verify_ajax();

        $date_from  = sanitize_text_field( wp_unslash( $_POST['date_from'] ?? '' ) );
        $date_to    = sanitize_text_field( wp_unslash( $_POST['date_to'] ?? '' ) );
        $severity   = sanitize_text_field( wp_unslash( $_POST['severity'] ?? '' ) );
        $event_type = sanitize_text_field( wp_unslash( $_POST['event_type'] ?? '' ) );

        WPS_Admin_Export::export_events( $date_from, $date_to, $severity, $event_type );
    }

    /**
     * Exportar tráfico a CSV.
     */
    public function ajax_export_traffic(): void {
        $this->verify_ajax();

        $date_from    = sanitize_text_field( wp_unslash( $_POST['date_from'] ?? '' ) );
        $date_to      = sanitize_text_field( wp_unslash( $_POST['date_to'] ?? '' ) );
        $visitor_type = sanitize_text_field( wp_unslash( $_POST['visitor_type'] ?? '' ) );

        WPS_Admin_Export::export_traffic( $date_from, $date_to, $visitor_type );
    }

    /**
     * Exportar configuración como JSON.
     */
    public function ajax_export_config(): void {
        // Verificar nonce desde GET (descarga directa).
        if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['nonce'] ?? $_POST['nonce'] ?? '' ) ), 'wps_admin_nonce' ) ) {
            wp_send_json_error( array( 'message' => __( 'Nonce inválido.', 'wp-secure' ) ), 403 );
        }
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Sin permisos.', 'wp-secure' ) ), 403 );
        }

        WPS_Admin_Export::export_config();
    }

    /**
     * Importar configuración desde JSON.
     */
    public function ajax_import_config(): void {
        $this->verify_ajax();

        if ( empty( $_FILES['config_file'] ) ) {
            wp_send_json_error( array( 'message' => __( 'No se recibió ningún archivo.', 'wp-secure' ) ) );
        }

        $file = $_FILES['config_file'];

        if ( $file['error'] !== UPLOAD_ERR_OK ) {
            wp_send_json_error( array( 'message' => __( 'Error al subir el archivo.', 'wp-secure' ) ) );
        }

        // Validar tipo y tamaño (max 1MB).
        if ( $file['size'] > 1048576 ) {
            wp_send_json_error( array( 'message' => __( 'El archivo es demasiado grande. Máximo 1 MB.', 'wp-secure' ) ) );
        }

        $content = file_get_contents( $file['tmp_name'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        $data    = json_decode( $content, true );

        if ( ! is_array( $data ) ) {
            wp_send_json_error( array( 'message' => __( 'El archivo no contiene JSON válido.', 'wp-secure' ) ) );
        }

        $result = WPS_Admin_Export::import_config( $data );

        if ( $result['success'] ) {
            wp_send_json_success( array( 'message' => $result['message'] ) );
        }

        wp_send_json_error( array( 'message' => $result['message'] ) );
    }

    /**
     * Limpiar bloqueos expirados via AJAX.
     */
    public function ajax_clean_expired_blocks(): void {
        $this->verify_ajax();

        $blocker = WPS_Blocker::get_instance();
        $cleaned = $blocker->clean_expired_blocks();

        wp_send_json_success( array(
            'message' => sprintf(
                /* translators: %d: number of cleaned blocks */
                __( 'Se limpiaron %d bloqueos expirados.', 'wp-secure' ),
                $cleaned
            ),
            'cleaned' => $cleaned,
        ) );
    }

    /**
     * Verificar nonce y permisos para AJAX.
     */
    private function verify_ajax(): void {
        if ( ! check_ajax_referer( 'wps_admin_nonce', 'nonce', false ) ) {
            wp_send_json_error( array( 'message' => __( 'Nonce inválido.', 'wp-secure' ) ), 403 );
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => __( 'Sin permisos.', 'wp-secure' ) ), 403 );
        }
    }
}
