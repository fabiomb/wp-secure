<?php
defined( 'ABSPATH' ) || exit;

/**
 * Detector de uso de XML-RPC.
 *
 * Bloquea todo acceso a xmlrpc.php si la configuración lo indica.
 */
class WPS_Xmlrpc_Detector {

    /** @var WPS_Loader */
    private $loader;

    /** @var WPS_Logger */
    private $logger;

    /** @var WPS_Blocker */
    private $blocker;

    public function __construct( WPS_Loader $loader ) {
        $this->loader  = $loader;
        $this->logger  = WPS_Logger::get_instance();
        $this->blocker = WPS_Blocker::get_instance();
    }

    /**
     * Registrar hooks para interceptar XML-RPC.
     */
    public function init(): void {
        // Verificar lo más temprano posible.
        add_action( 'init', array( $this, 'check_xmlrpc' ), 1 );

        // Desactivar pingbacks si XML-RPC está bloqueado.
        if ( $this->loader->get_setting( 'xmlrpc_block_all', true ) ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
            add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
            add_filter( 'bloginfo_url', array( $this, 'remove_pingback_url' ), 10, 2 );
        }
    }

    /**
     * Verificar si la petición actual es a xmlrpc.php y bloquearla.
     */
    public function check_xmlrpc(): void {
        if ( ! $this->is_xmlrpc_request() ) {
            return;
        }

        if ( ! $this->loader->get_setting( 'xmlrpc_block_all', true ) ) {
            return;
        }

        $request = WPS_Request::get_instance();
        $ip      = $request->ip();

        // Permitir si está en whitelist.
        if ( WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
            return;
        }

        // Eximido por regla personalizada.
        if ( WPS_Custom_Rules::is_exempt( 'xmlrpc' ) ) {
            return;
        }

        // Registrar evento.
        $this->logger->event_immediate( WPS_Event_Types::XMLRPC_BLOCKED, array(
            'ip_address'  => $ip,
            'request_uri' => $request->uri(),
            'user_agent'  => $request->user_agent(),
            'details'     => array(
                'method'  => $request->method(),
            ),
        ) );

        // Bloquear la IP automáticamente.
        $this->blocker->block_ip(
            $ip,
            'auto_xmlrpc',
            'Intento de acceso a XML-RPC',
            (int) $this->loader->get_setting( 'login_block_minutes', 15 )
        );

        // Emitir respuesta.
        $this->blocker->send_block_response( 'XML-RPC bloqueado' );
    }

    /**
     * ¿Es una petición a xmlrpc.php?
     */
    private function is_xmlrpc_request(): bool {
        $script = $_SERVER['SCRIPT_FILENAME'] ?? '';
        if ( basename( $script ) === 'xmlrpc.php' ) {
            return true;
        }

        $uri = $_SERVER['REQUEST_URI'] ?? '';
        return false !== strpos( $uri, 'xmlrpc.php' );
    }

    /**
     * Remover header X-Pingback.
     */
    public function remove_pingback_header( array $headers ): array {
        unset( $headers['X-Pingback'] );
        return $headers;
    }

    /**
     * Remover URL de pingback.
     */
    public function remove_pingback_url( string $output, string $show ): string {
        if ( 'pingback_url' === $show ) {
            return '';
        }
        return $output;
    }
}
