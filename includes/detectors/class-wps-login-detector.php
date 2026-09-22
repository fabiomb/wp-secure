<?php
defined( 'ABSPATH' ) || exit;

/**
 * Detector de intentos de login.
 *
 * Monitorea wp_login, wp_login_failed y bloquea por fuerza bruta.
 */
class WPS_Login_Detector {

    /** @var WPS_Loader */
    private $loader;

    /** @var WPS_Db */
    private $db;

    /** @var WPS_Logger */
    private $logger;

    /** @var WPS_Blocker */
    private $blocker;

    /**
     * Intento ya registrado en esta petición por check_before_auth().
     *
     * Con usuario inexistente el intento se graba antes de autenticar, para
     * poder contarlo y bloquear en el acto; después WordPress dispara
     * `wp_login_failed` por el mismo intento. Sin esta marca cada intento
     * sumaba dos filas: dos errores de tipeo bloqueaban la IP y el máximo de
     * intentos fallidos se alcanzaba con la mitad.
     *
     * @var bool
     */
    private $attempt_recorded = false;

    public function __construct( WPS_Loader $loader ) {
        $this->loader  = $loader;
        $this->db      = WPS_Db::get_instance();
        $this->logger  = WPS_Logger::get_instance();
        $this->blocker = WPS_Blocker::get_instance();
    }

    /**
     * Registrar hooks de WordPress para interceptar login.
     */
    public function init(): void {
        // Interceptar antes de que WordPress procese el login.
        add_action( 'wp_login', array( $this, 'on_login_success' ), 10, 2 );
        add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 10, 2 );
        add_filter( 'authenticate', array( $this, 'check_before_auth' ), 30, 3 );
    }

    /**
     * Mensaje único de rechazo de login.
     *
     * Todas las rutas de rechazo devuelven el mismo texto. Un mensaje
     * específico para "el usuario no existe" convierte al formulario de login
     * en un oráculo: permite enumerar cuentas válidas probando nombres y
     * mirando cuál responde distinto.
     */
    public static function denied_message(): string {
        return __( 'No se pudo completar el inicio de sesión. Verificá los datos o intentá más tarde.', 'wp-secure' );
    }

    /**
     * ¿Corresponde bloquear la IP por intentos con usuarios inexistentes?
     *
     * @param int $recent_attempts Intentos recientes con usuario inexistente desde esa IP.
     */
    public function should_block_unknown_user( int $recent_attempts ): bool {
        $threshold = (int) $this->loader->get_setting( 'login_unknown_user_threshold', 3 );

        // 0 deshabilita este bloqueo.
        if ( $threshold <= 0 ) {
            return false;
        }

        return $recent_attempts >= $threshold;
    }

    /**
     * Contar intentos recientes con usuario inexistente desde una IP.
     */
    private function count_recent_unknown_user_attempts( string $ip ): int {
        $table = WPS_Db_Schema::table( 'login_attempts' );

        return (int) $this->db->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT COUNT(*) FROM {$table}
             WHERE ip_address = %s
             AND user_exists = 0
             AND success = 0
             AND attempted_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)",
            $ip
        );
    }

    /**
     * Verificar antes de autenticar: bloquear IP si es necesario.
     *
     * @param WP_User|WP_Error|null $user
     * @param string                $username
     * @param string                $password
     * @return WP_User|WP_Error|null
     */
    public function check_before_auth( $user, string $username, string $password ) {
        if ( empty( $username ) ) {
            return $user;
        }

        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        // Si la IP está en whitelist de login, permitir.
        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip, 'login' ) ) {
            return $user;
        }

        // Eximido por regla personalizada.
        if ( WPS_Custom_Rules::is_exempt( 'login' ) ) {
            return $user;
        }

        // Si login solo whitelist está activo, bloquear IPs no listadas.
        if ( $this->loader->get_setting( 'login_whitelist_only', false ) ) {
            $this->logger->event_immediate( WPS_Event_Types::LOGIN_BLOCKED, array(
                'ip_address'  => $ip,
                'request_uri' => $request->uri(),
                'user_agent'  => $request->user_agent(),
                'details'     => array( 'reason' => 'login_whitelist_only', 'username' => $username ),
            ) );

            return new \WP_Error( 'wps_blocked', self::denied_message() );
        }

        // Verificar si la IP ya está bloqueada.
        $block = $this->blocker->is_blocked( $ip );
        if ( $block ) {
            $this->blocker->increment_hits( (int) $block['id'] );
            return new \WP_Error( 'wps_blocked', self::denied_message() );
        }

        // Evaluar reglas personalizadas con condición login_username.
        $login_context = array( 'login_username' => $username );
        $custom_rules  = WPS_Custom_Rules::get_instance();
        $matched_rule  = $custom_rules->evaluate( $request, $login_context );
        if ( $matched_rule ) {
            $custom_rules->apply_login_rule_action( $matched_rule, $ip, $request );
            if ( in_array( $matched_rule['action_type'], array( 'block_permanent', 'block_temporary' ), true ) ) {
                return new \WP_Error(
                    'wps_blocked',
                    __( 'Acceso bloqueado por una regla de seguridad personalizada.', 'wp-secure' )
                );
            }
        }

        // Bloquear la IP tras varios intentos con usuarios inexistentes.
        if ( $this->loader->get_setting( 'login_block_unknown_user', true ) ) {
            $user_exists = ( get_user_by( 'login', $username ) || get_user_by( 'email', $username ) );

            if ( ! $user_exists ) {
                $this->record_attempt( $ip, $username, false, false );
                $this->attempt_recorded = true;

                if ( $this->should_block_unknown_user( $this->count_recent_unknown_user_attempts( $ip ) ) ) {
                    $this->block_for_unknown_user( $ip, $username );

                    return new \WP_Error( 'wps_blocked', self::denied_message() );
                }

                // Por debajo del umbral se deja seguir el flujo normal de
                // WordPress, que responde igual que con una contraseña mala.
            }
        }

        return $user;
    }

    /**
     * Login exitoso.
     *
     * @param string  $username
     * @param WP_User $user
     */
    public function on_login_success( string $username, $user ): void {
        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        $this->record_attempt( $ip, $username, true, true );

        $this->logger->event( WPS_Event_Types::LOGIN_SUCCESS, array(
            'ip_address'  => $ip,
            'request_uri' => $request->uri(),
            'user_agent'  => $request->user_agent(),
            'wp_user_id'  => $user->ID,
            'details'     => array( 'username' => $username ),
        ), WPS_Event_Types::SEVERITY_INFO );
    }

    /**
     * Login fallido.
     *
     * @param string   $username
     * @param WP_Error $error
     */
    public function on_login_failed( string $username, $error = null ): void {
        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        // Verificar whitelist.
        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip, 'login' ) ) {
            return;
        }

        $user_exists = ( get_user_by( 'login', $username ) || get_user_by( 'email', $username ) );

        // Si check_before_auth() ya lo grabó, no contarlo dos veces.
        if ( $this->attempt_recorded ) {
            $this->attempt_recorded = false;
        } else {
            $this->record_attempt( $ip, $username, $user_exists, false );
        }

        $this->logger->event( WPS_Event_Types::LOGIN_FAILED, array(
            'ip_address'  => $ip,
            'request_uri' => $request->uri(),
            'user_agent'  => $request->user_agent(),
            'details'     => array(
                'username'    => $username,
                'user_exists' => $user_exists,
            ),
        ) );

        // Evaluar si se debe bloquear.
        $this->evaluate_block( $ip );
    }

    /**
     * Registrar un intento de login en la tabla de intentos.
     */
    private function record_attempt( string $ip, string $username, bool $user_exists, bool $success ): void {
        $this->db->insert( 'login_attempts', array(
            'ip_address'   => $ip,
            'username'     => substr( $username, 0, 255 ),
            'user_exists'  => $user_exists ? 1 : 0,
            'success'      => $success ? 1 : 0,
            'attempted_at' => current_time( 'mysql', true ),
        ) );
    }

    /**
     * Bloquear IP por intento con usuario inexistente.
     */
    private function block_for_unknown_user( string $ip, string $username ): void {
        $minutes = (int) $this->loader->get_setting( 'login_block_minutes', 15 );
        $minutes = $this->calculate_escalated_duration( $ip, 'auto_login', $minutes );

        $this->blocker->block_ip(
            $ip,
            'auto_login',
            sprintf( 'Login con usuario inexistente: %s', substr( $username, 0, 50 ) ),
            $minutes
        );

        $this->logger->event( WPS_Event_Types::LOGIN_BLOCKED, array(
            'ip_address' => $ip,
            'details'    => array(
                'reason'   => 'unknown_user',
                'username' => $username,
                'duration' => $minutes . ' min',
            ),
        ) );
    }

    /**
     * Evaluar si la IP debe ser bloqueada por exceder intentos fallidos.
     */
    private function evaluate_block( string $ip ): void {
        $max_attempts = (int) $this->loader->get_setting( 'login_max_attempts', 5 );
        $table        = WPS_Db_Schema::table( 'login_attempts' );

        // Contar intentos fallidos en la última hora.
        $failed_count = (int) $this->db->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT COUNT(*) FROM {$table}
             WHERE ip_address = %s
             AND success = 0
             AND attempted_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)",
            $ip
        );

        if ( $failed_count >= $max_attempts ) {
            $minutes = (int) $this->loader->get_setting( 'login_block_minutes', 15 );
            $minutes = $this->calculate_escalated_duration( $ip, 'auto_login', $minutes );

            $this->blocker->block_ip(
                $ip,
                'auto_login',
                sprintf( 'Excedió %d intentos de login fallidos en 1 hora', $max_attempts ),
                $minutes
            );

            $this->logger->event( WPS_Event_Types::LOGIN_BLOCKED, array(
                'ip_address' => $ip,
                'details'    => array(
                    'reason'         => 'max_attempts',
                    'failed_count'   => $failed_count,
                    'max_attempts'   => $max_attempts,
                    'duration'       => $minutes . ' min',
                ),
            ) );
        }
    }

    /**
     * Calcular duración escalada basada en bloqueos previos.
     */
    private function calculate_escalated_duration( string $ip, string $block_type, int $base_minutes ): int {
        $escalate_after = (int) $this->loader->get_setting( 'login_escalate_after', 3 );
        $escalate_hours = (int) $this->loader->get_setting( 'login_escalate_hours', 24 );
        $permanent_after = (int) $this->loader->get_setting( 'login_permanent_after', 3 );

        $previous = $this->blocker->count_previous_blocks( $ip, $block_type, 48 );

        // ¿Bloqueo permanente?
        $escalated_count = max( 0, $previous - $escalate_after );
        if ( $escalated_count >= $permanent_after ) {
            return 0; // 0 = permanente (block_ip con null minutes).
        }

        // ¿Escalar?
        if ( $previous >= $escalate_after ) {
            return $escalate_hours * 60;
        }

        return $base_minutes;
    }
}
