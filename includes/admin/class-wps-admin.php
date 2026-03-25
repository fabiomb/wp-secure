<?php
defined( 'ABSPATH' ) || exit;

/**
 * Controlador principal del panel de administración.
 *
 * Registra menús, carga assets, delega a subpáginas.
 */
class WPS_Admin {

    /** @var WPS_Loader */
    private $loader;

    /** @var string Capability requerida para acceder al panel. */
    private $capability = 'manage_options';

    /** @var string Slug del menú principal. */
    private $menu_slug = 'wp-secure';

    /** @var string Hook suffix de la página actual (para cargar assets). */
    private $hook_suffix = '';

    /** @var array Hook suffixes de todas las páginas del plugin. */
    private $page_hooks = array();

    public function __construct( WPS_Loader $loader ) {
        $this->loader = $loader;
    }

    /**
     * Inicializar hooks de admin.
     */
    public function init(): void {
        add_action( 'admin_menu', array( $this, 'register_menu' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
        add_action( 'admin_init', array( $this, 'handle_settings_save' ) );
        add_action( 'admin_init', array( $this, 'handle_export' ) );

        // Widget en el dashboard de WordPress.
        add_action( 'wp_dashboard_setup', array( $this, 'register_dashboard_widget' ) );

        // Redirigir al wizard o dashboard después de activar.
        add_action( 'admin_init', array( $this, 'maybe_redirect_after_activation' ) );
    }

    /**
     * Registrar widget en el dashboard de WordPress.
     */
    public function register_dashboard_widget(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        wp_add_dashboard_widget(
            'wps_dashboard_widget',
            __( 'WP Seguro — Resumen de Seguridad', 'wp-secure' ),
            array( $this, 'render_dashboard_widget' )
        );
    }

    /**
     * Renderizar el widget del dashboard de WordPress.
     */
    public function render_dashboard_widget(): void {
        $dashboard = new WPS_Admin_Dashboard( $this->loader );
        $dashboard->render_widget();
    }

    /**
     * Registrar menú y submenús.
     */
    public function register_menu(): void {
        // Menú principal.
        $this->page_hooks[] = add_menu_page(
            __( 'WP Seguro', 'wp-secure' ),
            __( 'WP Seguro', 'wp-secure' ),
            $this->capability,
            $this->menu_slug,
            array( $this, 'render_dashboard' ),
            'dashicons-shield-alt',
            65
        );

        // Dashboard.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Dashboard', 'wp-secure' ),
            __( 'Dashboard', 'wp-secure' ),
            $this->capability,
            $this->menu_slug,
            array( $this, 'render_dashboard' )
        );

        // Tráfico en Vivo.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Tráfico en Vivo', 'wp-secure' ),
            __( 'Tráfico en Vivo', 'wp-secure' ),
            $this->capability,
            $this->menu_slug . '-traffic',
            array( $this, 'render_traffic' )
        );

        // Bloqueos.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Bloqueos', 'wp-secure' ),
            __( 'Bloqueos', 'wp-secure' ),
            $this->capability,
            $this->menu_slug . '-blocks',
            array( $this, 'render_blocks' )
        );

        // Whitelist.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Whitelist', 'wp-secure' ),
            __( 'Whitelist', 'wp-secure' ),
            $this->capability,
            $this->menu_slug . '-whitelist',
            array( $this, 'render_whitelist' )
        );

        // Eventos.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Eventos', 'wp-secure' ),
            __( 'Eventos', 'wp-secure' ),
            $this->capability,
            $this->menu_slug . '-events',
            array( $this, 'render_events' )
        );

        // Base de Datos IP.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Base de Datos IP', 'wp-secure' ),
            __( 'Base de Datos IP', 'wp-secure' ),
            $this->capability,
            $this->menu_slug . '-ipdb',
            array( $this, 'render_ipdb' )
        );

        // Configuración.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Configuración', 'wp-secure' ),
            __( 'Configuración', 'wp-secure' ),
            $this->capability,
            $this->menu_slug . '-settings',
            array( $this, 'render_settings' )
        );

        // Reglas Personalizadas.
        $this->page_hooks[] = add_submenu_page(
            $this->menu_slug,
            __( 'Reglas', 'wp-secure' ),
            __( 'Reglas', 'wp-secure' ),
            $this->capability,
            $this->menu_slug . '-rules',
            array( $this, 'render_rules' )
        );

        // Wizard (oculto del menú, solo accesible por URL).
        $this->page_hooks[] = add_submenu_page(
            null,
            __( 'Asistente de Configuración', 'wp-secure' ),
            '',
            $this->capability,
            $this->menu_slug . '-wizard',
            array( $this, 'render_wizard' )
        );
    }

    /**
     * Cargar assets CSS/JS solo en páginas del plugin.
     */
    public function enqueue_assets( string $hook_suffix ): void {

        // Cargar assets en el dashboard principal de WordPress para el widget.
        if ( 'index.php' === $hook_suffix && current_user_can( $this->capability ) ) {
            wp_enqueue_style(
                'wps-admin',
                WPS_PLUGIN_URL . 'assets/css/wps-admin.css',
                array(),
                WPS_VERSION
            );

            wp_enqueue_script(
                'chartjs',
                'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js',
                array(),
                '4.4.0',
                true
            );

            wp_enqueue_script(
                'wps-admin',
                WPS_PLUGIN_URL . 'assets/js/wps-admin.js',
                array( 'jquery', 'chartjs' ),
                WPS_VERSION,
                true
            );

            wp_localize_script( 'wps-admin', 'wpsAdmin', array(
                'ajaxUrl' => admin_url( 'admin-ajax.php' ),
                'nonce'   => wp_create_nonce( 'wps_admin_nonce' ),
                'page'    => 'index.php',
                'strings' => array(),
            ) );

            return;
        }

        if ( ! $this->is_plugin_page( $hook_suffix ) ) {
            return;
        }

        wp_enqueue_style(
            'wps-admin',
            WPS_PLUGIN_URL . 'assets/css/wps-admin.css',
            array(),
            WPS_VERSION
        );

        wp_enqueue_script(
            'wps-admin',
            WPS_PLUGIN_URL . 'assets/js/wps-admin.js',
            array( 'jquery' ),
            WPS_VERSION,
            true
        );

        wp_localize_script( 'wps-admin', 'wpsAdmin', array(
            'ajaxUrl' => admin_url( 'admin-ajax.php' ),
            'nonce'   => wp_create_nonce( 'wps_admin_nonce' ),
            'page'    => isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '',
            'strings' => array(
                'confirm_action' => __( '¿Estás seguro?', 'wp-secure' ),
                'saving'         => __( 'Guardando...', 'wp-secure' ),
                'saved'          => __( 'Guardado', 'wp-secure' ),
                'error'          => __( 'Error al guardar', 'wp-secure' ),
                'loading'        => __( 'Cargando...', 'wp-secure' ),
                'paused'         => __( 'Pausado', 'wp-secure' ),
                'live'           => __( 'En vivo', 'wp-secure' ),
                'block_ok'       => __( 'IP bloqueada.', 'wp-secure' ),
                'unblock_ok'     => __( 'IP desbloqueada.', 'wp-secure' ),
                'whitelist_ok'   => __( 'IP agregada a whitelist.', 'wp-secure' ),
                'confirm_import' => __( '¿Importar esta configuración? Los ajustes actuales serán reemplazados.', 'wp-secure' ),
            ),
        ) );

        // Chart.js solo en dashboard.
        $current_page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
        if ( 'wp-secure' === $current_page ) {
            wp_enqueue_script(
                'chartjs',
                'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js',
                array(),
                '4.4.0',
                true
            );
        }
    }

    /**
     * Verificar si el hook corresponde a una página del plugin.
     */
    private function is_plugin_page( string $hook_suffix ): bool {
        return in_array( $hook_suffix, $this->page_hooks, true )
            || ( isset( $_GET['page'] ) && 0 === strpos( sanitize_text_field( wp_unslash( $_GET['page'] ) ), 'wp-secure' ) );
    }

    /**
     * Redirigir al wizard/dashboard después de activación.
     */
    public function maybe_redirect_after_activation(): void {
        if ( get_option( 'wps_activated' ) && current_user_can( $this->capability ) ) {
            delete_option( 'wps_activated' );
            if ( ! isset( $_GET['activate-multi'] ) ) {
                $wizard_done = $this->loader->get_setting( 'wizard_completed', false );
                $target = $wizard_done
                    ? admin_url( 'admin.php?page=' . $this->menu_slug )
                    : admin_url( 'admin.php?page=' . $this->menu_slug . '-wizard' );
                wp_safe_redirect( $target );
                exit;
            }
        }
    }

    /**
     * Procesar guardado de configuración.
     */
    public function handle_settings_save(): void {
        if ( ! isset( $_POST['wps_settings_nonce'] ) ) {
            return;
        }

        if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_settings_nonce'] ) ), 'wps_save_settings' ) ) {
            wp_die( esc_html__( 'Nonce de seguridad inválido.', 'wp-secure' ) );
        }

        if ( ! current_user_can( $this->capability ) ) {
            wp_die( esc_html__( 'No tienes permisos para realizar esta acción.', 'wp-secure' ) );
        }

        $settings_page = new WPS_Admin_Settings( $this->loader );
        $settings_page->save();

        // Log del cambio.
        $logger = WPS_Logger::get_instance();
        $logger->event_immediate( WPS_Event_Types::SETTINGS_CHANGED, array(
            'wp_user_id' => get_current_user_id(),
            'details'    => array( 'action' => 'settings_updated' ),
        ), WPS_Event_Types::SEVERITY_INFO );

        wp_safe_redirect( admin_url( 'admin.php?page=wp-secure-settings&saved=1' ) );
        exit;
    }

    /**
     * Procesar exportación CSV.
     */
    public function handle_export(): void {
        if ( ! isset( $_GET['wps_export'] ) ) {
            return;
        }

        if ( ! current_user_can( $this->capability ) ) {
            return;
        }

        if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wps_export' ) ) {
            wp_die( esc_html__( 'Nonce de seguridad inválido.', 'wp-secure' ) );
        }

        $export_type  = sanitize_text_field( wp_unslash( $_GET['wps_export'] ) );
        $date_from    = sanitize_text_field( wp_unslash( $_GET['date_from'] ?? '' ) );
        $date_to      = sanitize_text_field( wp_unslash( $_GET['date_to'] ?? '' ) );
        $severity     = sanitize_text_field( wp_unslash( $_GET['severity'] ?? '' ) );
        $event_type   = sanitize_text_field( wp_unslash( $_GET['event_type'] ?? '' ) );
        $visitor_type = sanitize_text_field( wp_unslash( $_GET['visitor_type'] ?? '' ) );

        if ( 'events' === $export_type ) {
            WPS_Admin_Export::export_events( $date_from, $date_to, $severity, $event_type );
        } elseif ( 'traffic' === $export_type ) {
            WPS_Admin_Export::export_traffic( $date_from, $date_to, $visitor_type );
        }
    }

    /*──────────────────────────────────────────────
     * Render de páginas
     *──────────────────────────────────────────────*/

    /**
     * Dashboard principal.
     */
    public function render_dashboard(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $dashboard = new WPS_Admin_Dashboard( $this->loader );
        $dashboard->render();
    }

    /**
     * Configuración.
     */
    public function render_settings(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $settings = new WPS_Admin_Settings( $this->loader );
        $settings->render();
    }

    /**
     * Bloqueos.
     */
    public function render_blocks(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $blocks = new WPS_Admin_Blocks( $this->loader );
        $blocks->render();
    }

    /**
     * Whitelist.
     */
    public function render_whitelist(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $whitelist = new WPS_Admin_Whitelist( $this->loader );
        $whitelist->render();
    }

    /**
     * Eventos.
     */
    public function render_events(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $events = new WPS_Admin_Events( $this->loader );
        $events->render();
    }

    /**
     * Tráfico en Vivo.
     */
    public function render_traffic(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $traffic = new WPS_Admin_Live_Traffic( $this->loader );
        $traffic->render();
    }

    /**
     * Asistente de configuración.
     */
    public function render_wizard(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $wizard = new WPS_Admin_Wizard( $this->loader );
        $wizard->render();
    }

    /**
     * Base de Datos IP.
     */
    public function render_ipdb(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $ipdb = new WPS_Admin_Ipdb( $this->loader );
        $ipdb->render();
    }

    /**
     * Reglas Personalizadas.
     */
    public function render_rules(): void {
        if ( ! current_user_can( $this->capability ) ) {
            return;
        }
        $rules = new WPS_Admin_Custom_Rules( $this->loader );
        $rules->render();
    }

}
