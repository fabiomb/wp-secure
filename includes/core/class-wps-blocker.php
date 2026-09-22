<?php
defined( 'ABSPATH' ) || exit;

/**
 * Ejecuta bloqueos: verifica si una IP está bloqueada y emite respuesta 403.
 */
class WPS_Blocker {

    /** @var WPS_Blocker|null */
    private static $instance = null;

    /** @var WPS_Db */
    private $db;

    /** @var WPS_Loader */
    private $loader;

    /** @var bool Si ya se programó regenerar el archivo de la Capa 0. */
    private static $layer0_sync_scheduled = false;

    /** Opción con los bloqueos automáticos pendientes de notificar. */
    const DIGEST_OPTION = 'wps_block_digest';

    /** Bloqueos detallados por resumen; el resto sólo se cuenta. */
    const DIGEST_MAX_ITEMS = 100;

    private function __construct() {
        $this->db     = WPS_Db::get_instance();
        $this->loader = WPS_Loader::get_instance();
    }

    public static function get_instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Verificar si una IP está actualmente bloqueada.
     *
     * @return array|null Datos del bloqueo si está bloqueada, null si no.
     */
    public function is_blocked( string $ip ): ?array {
        $table = WPS_Db_Schema::table( 'blocked_ips' );

        // 1. Buscar por IP exacta.
        $row = $this->db->get_row(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT * FROM {$table}
             WHERE ip_address = %s
             AND is_active = 1
             AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())
             LIMIT 1",
            $ip
        );

        if ( $row ) {
            return $row;
        }

        // 2. Buscar por rango binario.
        $ip_bin = WPS_Ip_Utils::ip_to_binary( $ip );
        if ( $ip_bin ) {
            $row = $this->db->get_row(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "SELECT * FROM {$table}
                 WHERE ip_range_start IS NOT NULL
                 AND ip_range_end IS NOT NULL
                 AND ip_range_start <= %s
                 AND ip_range_end >= %s
                 AND is_active = 1
                 AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())
                 LIMIT 1",
                $ip_bin,
                $ip_bin
            );

            if ( $row ) {
                return $row;
            }
        }

        return null;
    }

    /**
     * Bloquear una IP individual.
     *
     * @param string      $ip         Dirección IP.
     * @param string      $block_type Tipo de bloqueo (manual, auto_login, etc.).
     * @param string      $reason     Razón del bloqueo.
     * @param int|null    $minutes    Minutos de bloqueo temporal. Null = permanente.
     * @return int|false  ID del bloqueo o false en error.
     */
    public function block_ip( string $ip, string $block_type, string $reason, ?int $minutes = null ) {
        if ( ! WPS_Ip_Utils::is_valid_ip( $ip ) ) {
            return false;
        }

        // Un detector nunca bloquea al propio servidor: de ahí salen wp-cron,
        // los loopbacks y los precargadores de caché. Sólo un bloqueo manual,
        // explícito, puede alcanzarlo.
        if ( 'manual' !== $block_type && WPS_Ip_Utils::is_server_ip( $ip ) ) {
            return false;
        }

        // Verificar que no esté en whitelist.
        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return false;
        }

        // Verificar si ya está bloqueada (activa).
        $existing = $this->is_blocked( $ip );
        if ( $existing ) {
            // Incrementar hit_count.
            $this->increment_hits( (int) $existing['id'] );
            return (int) $existing['id'];
        }

        $data = array(
            'ip_address' => $ip,
            'block_type' => $block_type,
            'reason'     => substr( $reason, 0, 500 ),
            'blocked_at' => current_time( 'mysql', true ),
            'is_active'  => 1,
        );

        if ( $minutes ) {
            $data['expires_at'] = gmdate( 'Y-m-d H:i:s', time() + ( $minutes * 60 ) );
        }

        $id = $this->db->insert( 'blocked_ips', $data );

        if ( $id ) {
            self::schedule_layer0_sync();
            $this->queue_block_notice( $ip, $block_type, $reason, $minutes );

            $logger = WPS_Logger::get_instance();
            $logger->event( WPS_Event_Types::IP_BLOCKED, array(
                'ip_address' => $ip,
                'details'    => array(
                    'block_type' => $block_type,
                    'reason'     => $reason,
                    'duration'   => $minutes ? $minutes . ' min' : 'permanent',
                ),
            ) );
        }

        return $id;
    }

    /**
     * Clave de cliente de una IP según el prefijo IPv6 configurado.
     *
     * @see WPS_Ip_Utils::client_key()
     */
    public function client_key( string $ip ): string {
        // IPv4 no depende del ajuste: no leerlo evita una consulta por
        // petición en instalaciones donde todavía no está guardado.
        if ( ! WPS_Ip_Utils::is_ipv6( $ip ) ) {
            return $ip;
        }

        return WPS_Ip_Utils::client_key( $ip, $this->ipv6_prefix() );
    }

    /**
     * Prefijo IPv6 configurado (`ipv6_block_prefix`), acotado a /48–/128.
     */
    public function ipv6_prefix(): int {
        return WPS_Ip_Utils::clamp_ipv6_prefix(
            (int) $this->loader->get_setting( 'ipv6_block_prefix', WPS_Ip_Utils::DEFAULT_IPV6_PREFIX )
        );
    }

    /**
     * Bloquear automáticamente al cliente que originó una petición.
     *
     * En IPv4 bloquea la IP. En IPv6 bloquea la red del prefijo configurado
     * (por defecto /64): bloquear la dirección exacta no sirve, porque el
     * cliente puede usar otra de su /64 en la petición siguiente.
     *
     * Las mismas salvaguardas que block_ip(): nunca el propio servidor ni una
     * IP de la whitelist. Si la red incluye la IP del servidor, se bloquea
     * sólo la dirección exacta, porque la Capa 0 no exime al servidor y le
     * cortaría wp-cron y los loopbacks.
     *
     * @param string   $ip         IP del visitante.
     * @param string   $block_type Tipo de bloqueo automático (auto_rate, auto_sqli, …).
     * @param string   $reason     Razón del bloqueo.
     * @param int|null $minutes    Minutos de bloqueo temporal. Null = permanente.
     * @return int|false ID del bloqueo o false si no se bloqueó.
     */
    public function block_offender( string $ip, string $block_type, string $reason, ?int $minutes = null ) {
        if ( ! WPS_Ip_Utils::is_valid_ip( $ip ) ) {
            return false;
        }

        $key = $this->client_key( $ip );
        if ( $key === $ip || $this->network_contains_server( $key ) ) {
            return $this->block_ip( $ip, $block_type, $reason, $minutes );
        }

        if ( WPS_Ip_Utils::is_server_ip( $ip ) || WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return false;
        }

        $existing = $this->is_blocked( $ip );
        if ( $existing ) {
            $this->increment_hits( (int) $existing['id'] );
            return (int) $existing['id'];
        }

        $id = $this->block_cidr( $key, $block_type, $reason, $minutes );

        if ( $id ) {
            WPS_Logger::get_instance()->event( WPS_Event_Types::IP_BLOCKED, array(
                'ip_address' => $ip,
                'details'    => array(
                    'block_type' => $block_type,
                    'reason'     => $reason,
                    'network'    => $key,
                    'duration'   => $minutes ? $minutes . ' min' : 'permanent',
                ),
            ) );
        }

        return $id;
    }

    /**
     * ¿La red incluye alguna de las IPs del propio servidor?
     */
    private function network_contains_server( string $cidr ): bool {
        foreach ( array( 'SERVER_ADDR', 'LOCAL_ADDR' ) as $key ) {
            $server_ip = WPS_Ip_Utils::strip_port( (string) ( $_SERVER[ $key ] ?? '' ) );
            if ( WPS_Ip_Utils::is_valid_ip( $server_ip ) && WPS_Ip_Utils::ip_in_cidr( $server_ip, $cidr ) ) {
                return true;
            }
        }

        return WPS_Ip_Utils::ip_in_cidr( '::1', $cidr );
    }

    /**
     * Bloquear un rango CIDR.
     */
    public function block_cidr( string $cidr, string $block_type, string $reason, ?int $minutes = null ) {
        if ( ! WPS_Ip_Utils::is_valid_cidr( $cidr ) ) {
            return false;
        }

        $range = WPS_Ip_Utils::cidr_to_range( $cidr );
        if ( ! $range ) {
            return false;
        }

        $data = array(
            'cidr'           => $cidr,
            'ip_range_start' => $range['start'],
            'ip_range_end'   => $range['end'],
            'block_type'     => $block_type,
            'reason'         => substr( $reason, 0, 500 ),
            'blocked_at'     => current_time( 'mysql', true ),
            'is_active'      => 1,
        );

        if ( $minutes ) {
            $data['expires_at'] = gmdate( 'Y-m-d H:i:s', time() + ( $minutes * 60 ) );
        }

        $id = $this->db->insert( 'blocked_ips', $data );

        if ( $id ) {
            self::schedule_layer0_sync();
            $this->queue_block_notice( $cidr, $block_type, $reason, $minutes );
        }

        return $id;
    }

    /**
     * Encolar un bloqueo automático para el resumen por mail.
     *
     * Un mail por bloqueo inundaría el correo durante un ataque, así que los
     * bloqueos se acumulan y WPS_Admin_Notifier::send_block_digest() envía un
     * único resumen por hora. Vive acá y no en el notificador porque la Capa 1
     * bloquea antes de que el autoloader del plugin esté registrado.
     *
     * @param string   $target     IP o red bloqueada.
     * @param string   $block_type Tipo de bloqueo.
     * @param string   $reason     Razón.
     * @param int|null $minutes    Duración; null o 0 = permanente.
     */
    private function queue_block_notice( string $target, string $block_type, string $reason, ?int $minutes ): void {
        if ( 'manual' === $block_type || ! function_exists( 'get_option' ) ) {
            return;
        }

        if ( ! $this->loader->get_setting( 'notify_auto_blocks', false ) ) {
            return;
        }

        $digest = get_option( self::DIGEST_OPTION, array() );
        if ( ! is_array( $digest ) ) {
            $digest = array();
        }

        $digest['count'] = (int) ( $digest['count'] ?? 0 ) + 1;
        $digest['items'] = (array) ( $digest['items'] ?? array() );

        if ( count( $digest['items'] ) < self::DIGEST_MAX_ITEMS ) {
            $digest['items'][] = array(
                'target'  => $target,
                'type'    => $block_type,
                'reason'  => substr( $reason, 0, 200 ),
                'minutes' => $minutes ? (int) $minutes : 0,
                'time'    => time(),
            );
        }

        update_option( self::DIGEST_OPTION, $digest, false );
    }

    /**
     * Desbloquear por ID.
     */
    public function unblock( int $id ): bool {
        $result = $this->db->update(
            'blocked_ips',
            array( 'is_active' => 0 ),
            array( 'id' => $id )
        );

        if ( $result ) {
            self::schedule_layer0_sync();

            $logger = WPS_Logger::get_instance();
            $logger->event( WPS_Event_Types::MANUAL_UNBLOCK, array(
                'details'    => array( 'block_id' => $id ),
                'wp_user_id' => get_current_user_id(),
            ) );
        }

        return $result > 0;
    }

    /**
     * Desbloquear una IP específica (todos los bloqueos activos).
     */
    public function unblock_ip( string $ip ): int {
        $table    = WPS_Db_Schema::table( 'blocked_ips' );
        $affected = $this->db->query(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "UPDATE {$table} SET is_active = 0 WHERE ip_address = %s AND is_active = 1",
            $ip
        );

        if ( $affected ) {
            self::schedule_layer0_sync();
        }

        return $affected;
    }

    /**
     * Incrementar el contador de hits de un bloqueo activo.
     */
    public function increment_hits( int $id ): void {
        $table = WPS_Db_Schema::table( 'blocked_ips' );
        $this->db->query(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "UPDATE {$table} SET hit_count = hit_count + 1 WHERE id = %d",
            $id
        );
    }

    /**
     * Convertir un bloqueo temporal en permanente.
     */
    public function make_permanent( int $id ): bool {
        $result = $this->db->update(
            'blocked_ips',
            array( 'expires_at' => null ),
            array( 'id' => $id, 'is_active' => 1 )
        );

        if ( $result ) {
            self::schedule_layer0_sync();
        }

        return $result > 0;
    }

    /**
     * Programar la regeneración del archivo de la Capa 0 al final de la petición.
     *
     * La Capa 0 no consulta la base de datos: sin esto, un desbloqueo desde el
     * panel no tenía efecto ahí hasta la siguiente pasada del cron horario.
     * Se difiere a `shutdown` para regenerar una sola vez aunque la petición
     * haga varios cambios, y porque también corre tras un `exit` de bloqueo.
     */
    public static function schedule_layer0_sync(): void {
        if ( self::$layer0_sync_scheduled || ! function_exists( 'add_action' ) ) {
            return;
        }

        self::$layer0_sync_scheduled = true;
        add_action( 'shutdown', array( __CLASS__, 'run_layer0_sync' ), 20 );
    }

    /**
     * Regenerar el archivo de la Capa 0 (callback de `shutdown`).
     */
    public static function run_layer0_sync(): void {
        // En la Capa 1 el autoloader del plugin puede no estar registrado.
        if ( ! class_exists( 'WPS_Activator' ) && defined( 'WPS_INCLUDES_DIR' )
            && is_file( WPS_INCLUDES_DIR . 'class-wps-activator.php' ) ) {
            require_once WPS_INCLUDES_DIR . 'class-wps-activator.php';
        }

        if ( class_exists( 'WPS_Activator' ) ) {
            WPS_Activator::sync_blocked_ips_file();
        }
    }

    /**
     * Obtener bloqueos activos paginados.
     */
    public function get_active_blocks( int $page = 1, int $per_page = 20 ): array {
        $table  = WPS_Db_Schema::table( 'blocked_ips' );
        $offset = ( $page - 1 ) * $per_page;

        $total = (int) $this->db->get_var(
            "SELECT COUNT(*) FROM {$table} WHERE is_active = 1"
        );

        $items = $this->db->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT * FROM {$table}
             WHERE is_active = 1
             ORDER BY blocked_at DESC
             LIMIT %d OFFSET %d",
            $per_page,
            $offset
        );

        return array(
            'items'    => $items,
            'total'    => $total,
            'pages'    => ceil( $total / $per_page ),
            'page'     => $page,
            'per_page' => $per_page,
        );
    }

    /**
     * Contar el total de bloqueos registrados (histórico completo).
     */
    public function count_total_blocks(): int {
        $table = WPS_Db_Schema::table( 'blocked_ips' );
        return (int) $this->db->get_var(
            "SELECT COUNT(*) FROM {$table}"
        );
    }

    /**
     * Limpiar bloqueos expirados (is_active=1 con expires_at en el pasado).
     *
     * @return int Cantidad de bloqueos desactivados.
     */
    public function clean_expired_blocks(): int {
        $table = WPS_Db_Schema::table( 'blocked_ips' );
        return (int) $this->db->query(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "UPDATE {$table} SET is_active = 0 WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()"
        );
    }

    /**
     * Emitir respuesta de bloqueo y detener ejecución.
     *
     * En Modo Inseguro la función retorna sin bloquear, permitiendo que
     * la detección y el log continúen funcionando normalmente.
     */
    public function send_block_response( string $reason = '' ): void {
        // Modo inseguro o kill switch: detectar y registrar, pero no bloquear.
        if ( self::blocking_disabled() ) {
            return;
        }

        $code         = (int) $this->loader->get_setting( 'block_response_code', 403 );
        $redirect_url = $this->loader->get_setting( 'block_redirect_url', '' );

        // Si hay una URL de redirección configurada, redirigir allí.
        if ( ! empty( $redirect_url ) ) {
            $safe_url = esc_url( $redirect_url );
            if ( $safe_url ) {
                header( 'X-WPS-Blocked: 1' );
                header( 'Location: ' . $safe_url, true, 302 );
                exit;
            }
        }

        $message = $this->loader->get_setting( 'block_custom_message', '' );

        if ( empty( $message ) ) {
            $message = __( 'Acceso denegado. Tu dirección IP ha sido bloqueada por motivos de seguridad.', 'wp-secure' );
        }

        http_response_code( $code );
        header( 'Content-Type: text/html; charset=utf-8' );
        header( 'X-WPS-Blocked: 1' );

        echo '<!DOCTYPE html><html><head><title>' . $code . '</title></head><body>';
        echo '<h1>' . esc_html( $code ) . ' — ' . esc_html( $code === 503 ? 'Service Unavailable' : 'Forbidden' ) . '</h1>';
        echo '<p>' . esc_html( $message ) . '</p>';
        echo '</body></html>';
        exit;
    }

    /**
     * ¿Está suspendido el bloqueo?
     *
     * Dos vías: el Modo Inseguro (opción del panel) y la constante
     * `WPS_DISABLE_BLOCKING`, que se define en wp-config.php para recuperar el
     * acceso cuando uno mismo quedó bloqueado y no puede entrar al panel.
     */
    public static function blocking_disabled(): bool {
        if ( defined( 'WPS_DISABLE_BLOCKING' ) && WPS_DISABLE_BLOCKING ) {
            return true;
        }

        return function_exists( 'get_option' ) && (bool) get_option( 'wps_unsafe_mode', false );
    }

    /**
     * Contar bloqueos temporales previos para una IP (para escalation).
     */
    public function count_previous_blocks( string $ip, string $block_type, int $hours = 24 ): int {
        $table = WPS_Db_Schema::table( 'blocked_ips' );

        // En IPv6 los bloqueos automáticos son de red: se cuentan los de la
        // IP exacta y los de su red, para que la escalada funcione igual.
        return (int) $this->db->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT COUNT(*) FROM {$table}
             WHERE ( ip_address = %s OR cidr = %s )
             AND block_type = %s
             AND blocked_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)",
            $ip,
            $this->client_key( $ip ),
            $block_type,
            $hours
        );
    }

    /*──────────────────────────────────────────────
     * Bloqueo por País
     *──────────────────────────────────────────────*/

    /**
     * Verificar si un país está bloqueado.
     */
    public function is_country_blocked( string $country_code ): bool {
        if ( empty( $country_code ) || strlen( $country_code ) !== 2 ) {
            return false;
        }

        $table = WPS_Db_Schema::table( 'blocked_countries' );
        $row   = $this->db->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT country_code FROM {$table} WHERE country_code = %s",
            strtoupper( $country_code )
        );

        return null !== $row;
    }

    /**
     * Bloquear un país.
     */
    public function block_country( string $country_code, string $country_name ): bool {
        $country_code = strtoupper( $country_code );
        if ( strlen( $country_code ) !== 2 ) {
            return false;
        }

        // Verificar si ya está bloqueado.
        if ( $this->is_country_blocked( $country_code ) ) {
            return true;
        }

        $result = $this->db->insert( 'blocked_countries', array(
            'country_code' => $country_code,
            'country_name' => substr( $country_name, 0, 100 ),
            'blocked_at'   => current_time( 'mysql', true ),
            'blocked_by'   => wp_get_current_user()->user_login ?: 'system',
        ) );

        if ( $result ) {
            $logger = WPS_Logger::get_instance();
            $logger->event_immediate( WPS_Event_Types::COUNTRY_BLOCKED, array(
                'details'    => array(
                    'country_code' => $country_code,
                    'country_name' => $country_name,
                    'action'       => 'blocked',
                ),
                'wp_user_id' => get_current_user_id(),
            ), WPS_Event_Types::SEVERITY_INFO );
        }

        return (bool) $result;
    }

    /**
     * Desbloquear un país.
     */
    public function unblock_country( string $country_code ): bool {
        $country_code = strtoupper( $country_code );
        $result       = $this->db->delete( 'blocked_countries', array( 'country_code' => $country_code ) );

        if ( $result ) {
            $logger = WPS_Logger::get_instance();
            $logger->event_immediate( WPS_Event_Types::MANUAL_UNBLOCK, array(
                'details'    => array(
                    'type'         => 'country',
                    'country_code' => $country_code,
                ),
                'wp_user_id' => get_current_user_id(),
            ), WPS_Event_Types::SEVERITY_INFO );
        }

        return $result > 0;
    }

    /**
     * Obtener todos los países bloqueados.
     */
    public function get_blocked_countries(): array {
        $table = WPS_Db_Schema::table( 'blocked_countries' );
        return $this->db->get_results(
            "SELECT * FROM {$table} ORDER BY country_name ASC"
        );
    }

    /*──────────────────────────────────────────────
     * Bloqueo por ASN
     *──────────────────────────────────────────────*/

    /**
     * Verificar si un ASN está bloqueado.
     */
    public function is_asn_blocked( int $asn ): bool {
        if ( $asn <= 0 ) {
            return false;
        }

        $table = WPS_Db_Schema::table( 'blocked_asns' );
        $row   = $this->db->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT asn FROM {$table} WHERE asn = %d",
            $asn
        );

        return null !== $row;
    }

    /**
     * Bloquear un ASN.
     */
    public function block_asn( int $asn, string $asn_name ): bool {
        if ( $asn <= 0 ) {
            return false;
        }

        if ( $this->is_asn_blocked( $asn ) ) {
            return true;
        }

        $result = $this->db->insert( 'blocked_asns', array(
            'asn'        => $asn,
            'asn_name'   => substr( $asn_name, 0, 255 ),
            'blocked_at' => current_time( 'mysql', true ),
            'blocked_by' => wp_get_current_user()->user_login ?: 'system',
        ) );

        if ( $result ) {
            $logger = WPS_Logger::get_instance();
            $logger->event_immediate( WPS_Event_Types::ASN_BLOCKED, array(
                'details'    => array(
                    'asn'      => $asn,
                    'asn_name' => $asn_name,
                    'action'   => 'blocked',
                ),
                'wp_user_id' => get_current_user_id(),
            ), WPS_Event_Types::SEVERITY_INFO );
        }

        return (bool) $result;
    }

    /**
     * Desbloquear un ASN.
     */
    public function unblock_asn( int $asn ): bool {
        $result = $this->db->delete( 'blocked_asns', array( 'asn' => $asn ) );

        if ( $result ) {
            $logger = WPS_Logger::get_instance();
            $logger->event_immediate( WPS_Event_Types::MANUAL_UNBLOCK, array(
                'details'    => array(
                    'type' => 'asn',
                    'asn'  => $asn,
                ),
                'wp_user_id' => get_current_user_id(),
            ), WPS_Event_Types::SEVERITY_INFO );
        }

        return $result > 0;
    }

    /**
     * Obtener todos los ASNs bloqueados.
     */
    public function get_blocked_asns(): array {
        $table = WPS_Db_Schema::table( 'blocked_asns' );
        return $this->db->get_results(
            "SELECT * FROM {$table} ORDER BY asn_name ASC"
        );
    }
}
