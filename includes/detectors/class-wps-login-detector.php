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

        // Application passwords (Basic auth en REST): sus fallos no pasan
        // por wp_login_failed.
        add_action( 'application_password_failed_authentication', array( $this, 'on_application_password_failed' ) );

        // Recuperación de contraseña y registro: límite por cliente.
        add_action( 'lostpassword_post', array( $this, 'on_lost_password' ), 10, 2 );
        add_action( 'after_password_reset', array( $this, 'on_password_reset' ) );
        add_filter( 'registration_errors', array( $this, 'limit_registration' ), 10, 3 );

        // Mensajes de WordPress que revelan si una cuenta existe.
        if ( $this->loader->get_setting( 'rest_block_user_enum', true ) ) {
            add_filter( 'wp_login_errors', array( $this, 'uniform_login_errors' ) );
        }
    }

    /**
     * Unificar los errores de login que revelan si la cuenta existe.
     *
     * WordPress responde «The username X is not registered on this site» o
     * «The password you entered for the username X is incorrect»: probando
     * nombres se sabe cuáles existen. Se reemplazan por un único mensaje.
     *
     * @param WP_Error $errors Errores del formulario de login.
     * @return WP_Error
     */
    public function uniform_login_errors( $errors ) {
        if ( ! is_wp_error( $errors ) ) {
            return $errors;
        }

        $revealing = array( 'invalid_username', 'invalid_email', 'incorrect_password' );
        if ( ! array_intersect( $revealing, $errors->get_error_codes() ) ) {
            return $errors;
        }

        $uniform = new \WP_Error();
        foreach ( $errors->get_error_codes() as $code ) {
            if ( ! in_array( $code, $revealing, true ) ) {
                foreach ( $errors->get_error_messages( $code ) as $message ) {
                    $uniform->add( $code, $message );
                }
            }
        }
        $uniform->add( 'wps_login_failed', self::denied_message() );

        return $uniform;
    }

    /**
     * Recuperación de contraseña: límite por cliente y respuesta uniforme.
     *
     * - Superado el límite (`rate_lostpassword_per_hour`) se rechaza el
     *   envío, sin bloquear la IP: frena el envío masivo de mails.
     * - Con «Bloquear enumeración de usuarios» activo, si la cuenta no existe
     *   se responde igual que si existiera (redirección a «revisá tu correo»),
     *   en lugar de «There is no account with that username or email».
     *
     * @param WP_Error      $errors    Errores acumulados.
     * @param WP_User|false $user_data Usuario encontrado, o false.
     */
    public function on_lost_password( $errors, $user_data = false ): void {
        if ( ! is_wp_error( $errors ) || WPS_Blocker::blocking_disabled() ) {
            return;
        }

        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return;
        }

        if ( WPS_Rate_Limiter::get_instance( $this->loader )->exceeds( $ip, 'lostpassword' ) ) {
            $this->logger->event( WPS_Event_Types::RATE_LIMITED, array(
                'ip_address'  => $ip,
                'request_uri' => $request->uri(),
                'user_agent'  => $request->user_agent(),
                'details'     => array( 'type' => 'lostpassword' ),
            ) );
            $errors->add( 'wps_rate_limited', __( 'Demasiadas solicitudes. Intentá de nuevo más tarde.', 'wp-secure' ) );
            return;
        }

        if ( ! $user_data && $this->should_hide_missing_account( $errors ) ) {
            $this->redirect_as_sent();
        }
    }

    /**
     * ¿Corresponde responder como si la cuenta existiera?
     *
     * Sólo si el ajuste está activo y el único problema es que la cuenta no
     * existe: un campo vacío se sigue informando.
     */
    public function should_hide_missing_account( $errors ): bool {
        if ( ! $this->loader->get_setting( 'rest_block_user_enum', true ) ) {
            return false;
        }

        $codes = is_wp_error( $errors ) ? $errors->get_error_codes() : array();

        return ! array_diff( $codes, array( 'invalid_email', 'invalidcombo' ) );
    }

    /**
     * Redirigir como lo hace WordPress tras enviar el mail de recuperación.
     */
    protected function redirect_as_sent(): void {
        $redirect_to = ! empty( $_REQUEST['redirect_to'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            ? wp_unslash( $_REQUEST['redirect_to'] ) // phpcs:ignore
            : 'wp-login.php?checkemail=confirm';

        wp_safe_redirect( $redirect_to );
        exit;
    }

    /**
     * Registro de usuarios: límite por cliente.
     *
     * @param WP_Error $errors               Errores del registro.
     * @param string   $sanitized_user_login Usuario.
     * @param string   $user_email           Email.
     * @return WP_Error
     */
    public function limit_registration( $errors, $sanitized_user_login = '', $user_email = '' ) {
        if ( ! is_wp_error( $errors ) || WPS_Blocker::blocking_disabled() ) {
            return $errors;
        }

        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return $errors;
        }

        if ( WPS_Rate_Limiter::get_instance( $this->loader )->exceeds( $ip, 'register' ) ) {
            $this->logger->event( WPS_Event_Types::RATE_LIMITED, array(
                'ip_address'  => $ip,
                'request_uri' => $request->uri(),
                'user_agent'  => $request->user_agent(),
                'details'     => array( 'type' => 'register' ),
            ) );
            $errors->add( 'wps_rate_limited', __( 'Demasiados registros desde tu conexión. Intentá de nuevo más tarde.', 'wp-secure' ) );
        }

        return $errors;
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
            $this->blocker->client_key( $ip )
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

        // Modo Inseguro o kill switch: el login no se rechaza. Sin esto, una
        // IP bloqueada no podía entrar al panel ni siquiera con el bloqueo
        // suspendido, que es justamente cuando se lo necesita.
        if ( WPS_Blocker::blocking_disabled() ) {
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

        // Cuenta bajo ataque: sólo entran sus redes conocidas.
        $target = get_user_by( 'login', $username ) ?: get_user_by( 'email', $username );
        if ( $target && $this->is_account_throttled( $target, $ip ) ) {
            $this->logger->event_immediate( WPS_Event_Types::LOGIN_BLOCKED, array(
                'ip_address'  => $ip,
                'request_uri' => $request->uri(),
                'user_agent'  => $request->user_agent(),
                'details'     => array( 'reason' => 'account_throttled', 'username' => $username ),
            ) );

            return new \WP_Error( 'wps_blocked', self::denied_message() );
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
     * ¿La cuenta está bajo ataque y el cliente no es uno de sus habituales?
     *
     * Los límites por IP no frenan a una botnet: miles de IPs prueban
     * contraseñas contra la misma cuenta sin que ninguna llegue a su límite.
     * Superados `login_user_max_attempts` fallos contra la cuenta en la
     * última hora (desde cualquier IP), se rechazan los logins de clientes
     * desconocidos sin comprobar la contraseña. El dueño sigue entrando desde
     * las redes donde ya inició sesión, y el bloqueo se levanta solo cuando
     * los fallos salen de la ventana de una hora.
     *
     * @param WP_User $user Cuenta objetivo.
     * @param string  $ip   IP del visitante.
     */
    public function is_account_throttled( $user, string $ip ): bool {
        $max = (int) $this->loader->get_setting( 'login_user_max_attempts', 10 );
        if ( $max <= 0 || empty( $user->ID ) ) {
            return false;
        }

        if ( $this->count_recent_account_failures( $user ) < $max ) {
            return false;
        }

        return ! WPS_Known_Clients::is_known( (int) $user->ID, $ip );
    }

    /**
     * Fallos contra una cuenta en la última hora, desde cualquier IP, por
     * nombre de usuario o por email.
     */
    private function count_recent_account_failures( $user ): int {
        $table = WPS_Db_Schema::table( 'login_attempts' );

        return (int) $this->db->get_var(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            "SELECT COUNT(*) FROM {$table}
             WHERE username IN (%s, %s)
             AND success = 0
             AND attempted_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)",
            (string) $user->user_login,
            (string) ( $user->user_email ?? '' )
        );
    }

    /**
     * Tras restablecer la contraseña, la red desde la que se hizo pasa a ser
     * conocida: el dueño que viaja puede volver a entrar aunque su cuenta
     * esté bajo ataque.
     *
     * @param WP_User $user Usuario.
     */
    public function on_password_reset( $user ): void {
        if ( ! empty( $user->ID ) ) {
            WPS_Known_Clients::record( (int) $user->ID, WPS_Request::get_instance()->ip() );
        }
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

        // Aviso de login de un administrador desde una red desconocida.
        WPS_Admin_Notifier::get_instance( $this->loader )->track_login( $user, $ip );
    }

    /**
     * Login fallido.
     *
     * @param string   $username
     * @param WP_Error $error
     */
    public function on_login_failed( string $username, $error = null ): void {
        $this->register_failure( $username, 'password' );
    }

    /**
     * Fallo de autenticación con application password.
     *
     * La autenticación Basic de la REST API con application passwords no
     * dispara `wp_login_failed`: sin esto, se podían probar contraseñas contra
     * `/wp-json/` sin límite. Se cuentan igual que un login fallido.
     *
     * Sólo cuentan los intentos reales (contraseña incorrecta, usuario o
     * email inexistente). Los errores por application passwords desactivadas
     * son de clientes mal configurados, no de un ataque.
     *
     * @param WP_Error $error Error de autenticación.
     */
    public function on_application_password_failed( $error ): void {
        if ( ! is_wp_error( $error ) ) {
            return;
        }

        if ( ! in_array( $error->get_error_code(), array( 'incorrect_password', 'invalid_username', 'invalid_email' ), true ) ) {
            return;
        }

        // WordPress no pasa el usuario al hook; lo toma de la cabecera Basic.
        $username = isset( $_SERVER['PHP_AUTH_USER'] ) ? (string) wp_unslash( $_SERVER['PHP_AUTH_USER'] ) : '';

        $this->register_failure( $username, 'application_password' );
    }

    /**
     * Registrar un intento fallido y evaluar si corresponde bloquear.
     *
     * @param string $username Usuario o email usado.
     * @param string $method   `password` o `application_password`.
     */
    private function register_failure( string $username, string $method ): void {
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
                'method'      => $method,
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
            'ip_address'   => $this->blocker->client_key( $ip ),
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

        $this->blocker->block_offender(
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
            $this->blocker->client_key( $ip )
        );

        if ( $failed_count >= $max_attempts ) {
            $minutes = (int) $this->loader->get_setting( 'login_block_minutes', 15 );
            $minutes = $this->calculate_escalated_duration( $ip, 'auto_login', $minutes );

            $this->blocker->block_offender(
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
