<?php
defined( 'ABSPATH' ) || exit;

/**
 * Página de configuración del plugin.
 */
class WPS_Admin_Settings {

    /** @var WPS_Loader */
    private $loader;

    /**
     * Definición de campos de configuración.
     * Cada sección agrupa campos relacionados.
     */
    private $sections;

    public function __construct( WPS_Loader $loader ) {
        $this->loader   = $loader;
        $this->sections = $this->define_sections();
    }

    /**
     * Renderizar la página de configuración.
     */
    public function render(): void {
        $saved = isset( $_GET['saved'] ) && '1' === $_GET['saved'];
        ?>
        <div class="wrap wps-wrap">
            <h1><?php esc_html_e( 'WP Seguro — Configuración', 'wp-secure' ); ?></h1>

            <?php if ( $saved ) : ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php esc_html_e( 'Configuración guardada correctamente.', 'wp-secure' ); ?></p>
                </div>
            <?php endif; ?>

            <form method="post" action="<?php echo esc_url( admin_url( 'admin.php?page=wp-secure-settings' ) ); ?>">
                <?php wp_nonce_field( 'wps_save_settings', 'wps_settings_nonce' ); ?>

                <div class="wps-settings-container">
                    <!-- Navegación de secciones -->
                    <nav class="wps-settings-nav">
                        <ul>
                            <?php foreach ( $this->sections as $id => $section ) : ?>
                                <li>
                                    <a href="#wps-section-<?php echo esc_attr( $id ); ?>" class="wps-settings-nav-item" data-section="<?php echo esc_attr( $id ); ?>">
                                        <span class="dashicons <?php echo esc_attr( $section['icon'] ); ?>"></span>
                                        <?php echo esc_html( $section['title'] ); ?>
                                    </a>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </nav>

                    <!-- Contenido de secciones -->
                    <div class="wps-settings-content">
                        <?php foreach ( $this->sections as $id => $section ) : ?>
                            <div id="wps-section-<?php echo esc_attr( $id ); ?>" class="wps-settings-section">
                                <h2><?php echo esc_html( $section['title'] ); ?></h2>
                                <?php if ( ! empty( $section['description'] ) ) : ?>
                                    <p class="description"><?php echo esc_html( $section['description'] ); ?></p>
                                <?php endif; ?>
                                <table class="form-table">
                                    <tbody>
                                        <?php
                                        foreach ( $section['fields'] as $field ) {
                                            $this->render_field( $field );
                                        }
                                        ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endforeach; ?>

                        <?php submit_button( __( 'Guardar Configuración', 'wp-secure' ) ); ?>
                    </div>
                </div>
            </form>
        </div>
        <?php
    }

    /**
     * Guardar configuración desde POST.
     */
    public function save(): void {
        foreach ( $this->sections as $section ) {
            foreach ( $section['fields'] as $field ) {
                $key = $field['key'];

                switch ( $field['type'] ) {
                    case 'checkbox':
                        $value = isset( $_POST[ 'wps_' . $key ] ) ? true : false;
                        break;

                    case 'number':
                        $value = isset( $_POST[ 'wps_' . $key ] )
                            ? absint( $_POST[ 'wps_' . $key ] )
                            : $field['default'];
                        break;

                    case 'text':
                    case 'password':
                        $value = isset( $_POST[ 'wps_' . $key ] )
                            ? sanitize_text_field( wp_unslash( $_POST[ 'wps_' . $key ] ) )
                            : $field['default'];
                        break;

                    case 'textarea':
                        $value = isset( $_POST[ 'wps_' . $key ] )
                            ? sanitize_textarea_field( wp_unslash( $_POST[ 'wps_' . $key ] ) )
                            : $field['default'];
                        break;

                    case 'select':
                        $value = isset( $_POST[ 'wps_' . $key ] )
                            ? sanitize_text_field( wp_unslash( $_POST[ 'wps_' . $key ] ) )
                            : $field['default'];
                        // Validar que el valor esté entre las opciones permitidas.
                        if ( ! array_key_exists( $value, $field['options'] ) ) {
                            $value = $field['default'];
                        }
                        break;

                    case 'email':
                        $value = isset( $_POST[ 'wps_' . $key ] )
                            ? sanitize_email( wp_unslash( $_POST[ 'wps_' . $key ] ) )
                            : $field['default'];
                        break;

                    default:
                        continue 2;
                }

                $this->loader->set_setting( $key, $value );
            }
        }
    }

    /**
     * Renderizar un campo individual.
     */
    private function render_field( array $field ): void {
        $key     = $field['key'];
        $name    = 'wps_' . $key;
        $value   = $this->loader->get_setting( $key, $field['default'] );
        $id      = 'wps-field-' . str_replace( '_', '-', $key );
        ?>
        <tr>
            <th scope="row">
                <label for="<?php echo esc_attr( $id ); ?>"><?php echo esc_html( $field['label'] ); ?></label>
            </th>
            <td>
                <?php
                switch ( $field['type'] ) {
                    case 'text':
                    case 'password':
                    case 'email':
                        ?>
                        <input type="<?php echo esc_attr( $field['type'] ); ?>"
                               id="<?php echo esc_attr( $id ); ?>"
                               name="<?php echo esc_attr( $name ); ?>"
                               value="<?php echo esc_attr( $value ); ?>"
                               class="regular-text" />
                        <?php
                        break;

                    case 'number':
                        $min = $field['min'] ?? 0;
                        $max = $field['max'] ?? 9999;
                        ?>
                        <input type="number"
                               id="<?php echo esc_attr( $id ); ?>"
                               name="<?php echo esc_attr( $name ); ?>"
                               value="<?php echo esc_attr( $value ); ?>"
                               min="<?php echo esc_attr( $min ); ?>"
                               max="<?php echo esc_attr( $max ); ?>"
                               class="small-text" />
                        <?php
                        break;

                    case 'checkbox':
                        ?>
                        <label>
                            <input type="checkbox"
                                   id="<?php echo esc_attr( $id ); ?>"
                                   name="<?php echo esc_attr( $name ); ?>"
                                   value="1"
                                   <?php checked( $value, true ); ?> />
                            <?php echo esc_html( $field['checkbox_label'] ?? '' ); ?>
                        </label>
                        <?php
                        break;

                    case 'select':
                        ?>
                        <select id="<?php echo esc_attr( $id ); ?>" name="<?php echo esc_attr( $name ); ?>">
                            <?php foreach ( $field['options'] as $opt_value => $opt_label ) : ?>
                                <option value="<?php echo esc_attr( $opt_value ); ?>" <?php selected( $value, $opt_value ); ?>>
                                    <?php echo esc_html( $opt_label ); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                        <?php
                        break;

                    case 'textarea':
                        $textarea_value = is_array( $value ) ? implode( "\n", $value ) : (string) $value;
                        ?>
                        <textarea id="<?php echo esc_attr( $id ); ?>"
                                  name="<?php echo esc_attr( $name ); ?>"
                                  rows="4"
                                  class="large-text"><?php echo esc_textarea( $textarea_value ); ?></textarea>
                        <?php
                        break;
                }

                if ( ! empty( $field['description'] ) ) {
                    echo '<p class="description">' . esc_html( $field['description'] ) . '</p>';
                }
                ?>
            </td>
        </tr>
        <?php
    }

    /**
     * Definir las secciones y campos de configuración.
     */
    private function define_sections(): array {
        return array(
            'api' => array(
                'title'       => __( 'API y Datos', 'wp-secure' ),
                'icon'        => 'dashicons-cloud',
                'description' => __( 'Configuración de la API de ipinfo.io para geolocalización de IPs.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'         => 'ipinfo_api_key',
                        'label'       => __( 'API Key ipinfo.io', 'wp-secure' ),
                        'type'        => 'password',
                        'default'     => '',
                        'description' => __( 'Obtén tu API key gratuita en ipinfo.io/signup', 'wp-secure' ),
                    ),
                    array(
                        'key'     => 'ipinfo_mode',
                        'label'   => __( 'Modo de datos', 'wp-secure' ),
                        'type'    => 'select',
                        'default' => 'api',
                        'options' => array(
                            'api'   => __( 'API en línea', 'wp-secure' ),
                            'local' => __( 'Base de datos local (MMDB)', 'wp-secure' ),
                        ),
                        'description' => __( 'El modo local es más rápido pero requiere descargar la base de datos.', 'wp-secure' ),
                    ),
                ),
            ),

            'login' => array(
                'title'       => __( 'Protección de Login', 'wp-secure' ),
                'icon'        => 'dashicons-lock',
                'description' => __( 'Configuración de protección contra ataques de fuerza bruta al login.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'         => 'login_max_attempts',
                        'label'       => __( 'Intentos máximos antes de bloqueo', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 5,
                        'min'         => 1,
                        'max'         => 20,
                        'description' => __( 'Cantidad de intentos fallidos permitidos antes del bloqueo temporal.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'login_block_minutes',
                        'label'       => __( 'Duración del bloqueo temporal (minutos)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 15,
                        'min'         => 1,
                        'max'         => 1440,
                    ),
                    array(
                        'key'         => 'login_escalate_after',
                        'label'       => __( 'Escalar bloqueo tras N bloqueos temporales', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 3,
                        'min'         => 1,
                        'max'         => 10,
                    ),
                    array(
                        'key'         => 'login_escalate_hours',
                        'label'       => __( 'Duración del bloqueo escalado (horas)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 24,
                        'min'         => 1,
                        'max'         => 720,
                    ),
                    array(
                        'key'            => 'login_block_unknown_user',
                        'label'          => __( 'Bloquear usuario inexistente', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Bloquear IP inmediatamente si el usuario no existe', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'login_whitelist_only',
                        'label'          => __( 'Login solo desde whitelist', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Permitir login solo desde IPs en la whitelist de login', 'wp-secure' ),
                        'description'    => __( 'Cuidado: asegúrate de tener tu IP en la whitelist antes de activar.', 'wp-secure' ),
                    ),
                ),
            ),

            'xmlrpc' => array(
                'title'       => __( 'XML-RPC', 'wp-secure' ),
                'icon'        => 'dashicons-admin-tools',
                'description' => __( 'XML-RPC es un vector de ataque común. Se recomienda bloquearlo si no lo necesitas.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'            => 'xmlrpc_block_all',
                        'label'          => __( 'Bloquear XML-RPC', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Bloquear completamente el acceso a xmlrpc.php', 'wp-secure' ),
                    ),
                ),
            ),

            'restapi' => array(
                'title'       => __( 'REST API', 'wp-secure' ),
                'icon'        => 'dashicons-rest-api',
                'description' => '',
                'fields'      => array(
                    array(
                        'key'            => 'rest_block_user_enum',
                        'label'          => __( 'Bloquear enumeración de usuarios', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Bloquear el endpoint /wp-json/wp/v2/users para no autenticados', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'rest_disable_public',
                        'label'          => __( 'Desactivar REST API pública', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Solo permitir REST API a usuarios autenticados', 'wp-secure' ),
                        'description'    => __( 'Puede romper formularios de contacto y otras integraciones.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'rest_allowed_namespaces',
                        'label'       => __( 'Namespaces REST permitidos', 'wp-secure' ),
                        'type'        => 'textarea',
                        'default'     => "contact-form-7\nwoocommerce",
                        'description' => __( 'Namespaces que pueden ser accedidos sin autenticación (uno por línea). Aplica solo si la REST API pública está desactivada. oembed siempre está permitido.', 'wp-secure' ),
                    ),
                ),
            ),

            'rate' => array(
                'title'       => __( 'Rate Limiting', 'wp-secure' ),
                'icon'        => 'dashicons-performance',
                'description' => __( 'Limitar la cantidad de peticiones por IP para prevenir abuso.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'         => 'rate_pages_per_min',
                        'label'       => __( 'Peticiones/minuto (páginas)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 60,
                        'min'         => 10,
                        'max'         => 500,
                    ),
                    array(
                        'key'         => 'rate_total_per_min',
                        'label'       => __( 'Peticiones/minuto (total)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 240,
                        'min'         => 30,
                        'max'         => 2000,
                    ),
                    array(
                        'key'         => 'rate_404_per_min',
                        'label'       => __( 'Errores 404/minuto', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 10,
                        'min'         => 3,
                        'max'         => 100,
                    ),
                    array(
                        'key'         => 'rate_login_per_hour',
                        'label'       => __( 'Intentos de login/hora', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 5,
                        'min'         => 1,
                        'max'         => 50,
                        'description' => __( 'Máximo de intentos de login por IP por hora.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'rate_xmlrpc_per_hour',
                        'label'       => __( 'Peticiones XML-RPC/hora', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 0,
                        'min'         => 0,
                        'max'         => 100,
                        'description' => __( '0 = deshabilitado. Si XML-RPC está bloqueado globalmente, este límite no aplica.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'rate_block_minutes',
                        'label'       => __( 'Duración del bloqueo (minutos)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 15,
                        'min'         => 1,
                        'max'         => 1440,
                    ),
                ),
            ),

            'firewall' => array(
                'title'       => __( 'Firewall Avanzado', 'wp-secure' ),
                'icon'        => 'dashicons-shield',
                'description' => __( 'Configuración de las capas de firewall y detección de amenazas.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'            => 'firewall_layer0_enabled',
                        'label'          => __( 'Capa 0: auto_prepend_file', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Habilitar firewall PHP pre-WordPress (requiere configuración manual de .htaccess o .user.ini)', 'wp-secure' ),
                        'description'    => __( 'Bloquea IPs antes de que PHP cargue WordPress. Máximo rendimiento.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'firewall_layer1_enabled',
                        'label'          => __( 'Capa 1: MU-Plugin', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Instalar MU-Plugin de firewall', 'wp-secure' ),
                        'description'    => __( 'Intercepta peticiones antes de plugins y temas con acceso a la BD.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'risky_countries',
                        'label'       => __( 'Países de alto riesgo', 'wp-secure' ),
                        'type'        => 'text',
                        'default'     => '',
                        'description' => __( 'Códigos de país separados por coma (ej: CN,RU,KP). Aumenta la puntuación de riesgo para IPs de estos países.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'crawler_rdns_enabled',
                        'label'          => __( 'Verificar crawlers por rDNS', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Verificar identidad de crawlers conocidos (Googlebot, Bingbot, etc.) mediante reverse DNS', 'wp-secure' ),
                        'description'    => __( 'Los crawlers que se hacen pasar por bots legítimos serán bloqueados.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'security_headers_enabled',
                        'label'          => __( 'Security Headers', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Enviar headers de seguridad (X-Frame-Options, X-Content-Type-Options, etc.)', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'hide_wp_version',
                        'label'          => __( 'Ocultar versión WP', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Ocultar la versión de WordPress del código fuente', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'block_bad_methods',
                        'label'          => __( 'Bloquear métodos HTTP peligrosos', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Bloquear TRACE, TRACK, DEBUG y restringir DELETE/PUT/PATCH fuera de REST API', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'block_empty_ua',
                        'label'          => __( 'Bloquear User-Agent vacío', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Bloquear peticiones sin header User-Agent', 'wp-secure' ),
                        'description'    => __( 'Puede bloquear scripts legítimos. Activar con precaución.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'block_no_host',
                        'label'          => __( 'Bloquear sin Host header', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Bloquear peticiones HTTP sin header Host', 'wp-secure' ),
                    ),
                    array(
                        'key'     => 'critical_block_mode',
                        'label'   => __( 'Bloqueo de eventos críticos', 'wp-secure' ),
                        'type'    => 'select',
                        'default' => 'temporary',
                        'options' => array(
                            'temporary' => __( 'Bloqueo temporal', 'wp-secure' ),
                            'permanent' => __( 'Bloqueo permanente', 'wp-secure' ),
                        ),
                        'description' => __( 'Determina si las detecciones de ataques críticos (SQLi, XSS, Path Traversal, Scanner) generan un bloqueo temporal o permanente.', 'wp-secure' ),
                    ),
                ),
            ),

            'response' => array(
                'title'       => __( 'Respuesta de Bloqueo', 'wp-secure' ),
                'icon'        => 'dashicons-dismiss',
                'description' => '',
                'fields'      => array(
                    array(
                        'key'     => 'block_response_code',
                        'label'   => __( 'Código HTTP de respuesta', 'wp-secure' ),
                        'type'    => 'select',
                        'default' => '403',
                        'options' => array(
                            '403' => '403 Forbidden',
                            '503' => '503 Service Unavailable',
                        ),
                    ),
                    array(
                        'key'         => 'block_custom_message',
                        'label'       => __( 'Mensaje personalizado', 'wp-secure' ),
                        'type'        => 'textarea',
                        'default'     => '',
                        'description' => __( 'Mensaje mostrado a IPs bloqueadas. Dejar vacío para usar el predeterminado.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'block_redirect_url',
                        'label'       => __( 'URL de página de bloqueo', 'wp-secure' ),
                        'type'        => 'text',
                        'default'     => '',
                        'description' => __( 'URL de una página HTML personalizada a la que se redirigirá a los bloqueados. Dejar vacío para mostrar el mensaje de texto por defecto. Debe ser una URL externa al sitio protegido.', 'wp-secure' ),
                    ),
                ),
            ),

            'proxy' => array(
                'title'       => __( 'CDN / Proxy', 'wp-secure' ),
                'icon'        => 'dashicons-cloud-saved',
                'description' => __( 'Si tu sitio está detrás de Cloudflare, Sucuri u otro proxy/CDN, configura la detección de IP real aquí.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'     => 'proxy_mode',
                        'label'   => __( 'Modo de proxy', 'wp-secure' ),
                        'type'    => 'select',
                        'default' => 'auto',
                        'options' => array(
                            'auto'       => __( 'Auto-detectar', 'wp-secure' ),
                            'cloudflare' => __( 'Cloudflare', 'wp-secure' ),
                            'sucuri'     => __( 'Sucuri', 'wp-secure' ),
                            'custom'     => __( 'Personalizado', 'wp-secure' ),
                            'none'       => __( 'Sin proxy (usar REMOTE_ADDR)', 'wp-secure' ),
                        ),
                        'description' => __( 'Auto-detectar funciona para Cloudflare y Sucuri. Usa "Personalizado" para otros proxies/load balancers.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'proxy_trusted_ips',
                        'label'       => __( 'IPs de proxy confiables', 'wp-secure' ),
                        'type'        => 'textarea',
                        'default'     => '',
                        'description' => __( 'Una IP o CIDR por línea. Solo aplica en modo "Personalizado".', 'wp-secure' ),
                    ),
                    array(
                        'key'     => 'proxy_header',
                        'label'   => __( 'Header de IP real', 'wp-secure' ),
                        'type'    => 'select',
                        'default' => 'X-Forwarded-For',
                        'options' => array(
                            'X-Forwarded-For'   => 'X-Forwarded-For',
                            'X-Real-IP'         => 'X-Real-IP',
                            'CF-Connecting-IP'  => 'CF-Connecting-IP',
                            'X-Sucuri-ClientIP' => 'X-Sucuri-ClientIP',
                        ),
                        'description' => __( 'Header que contiene la IP real. Solo aplica en modo "Personalizado".', 'wp-secure' ),
                    ),
                ),
            ),

            'retention' => array(
                'title'       => __( 'Retención de Datos', 'wp-secure' ),
                'icon'        => 'dashicons-calendar-alt',
                'description' => __( 'Controla cuánto tiempo se conservan los registros.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'         => 'retention_traffic_days',
                        'label'       => __( 'Logs de tráfico (días)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 30,
                        'min'         => 1,
                        'max'         => 365,
                    ),
                    array(
                        'key'         => 'retention_events_days',
                        'label'       => __( 'Eventos de seguridad (días)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 90,
                        'min'         => 7,
                        'max'         => 365,
                    ),
                    array(
                        'key'         => 'retention_login_days',
                        'label'       => __( 'Intentos de login (días)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 7,
                        'min'         => 1,
                        'max'         => 90,
                    ),
                    array(
                        'key'         => 'retention_blocks_days',
                        'label'       => __( 'Bloqueos expirados (días)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 30,
                        'min'         => 1,
                        'max'         => 365,
                        'description' => __( 'Días que se conservan los registros de bloqueos temporales ya cumplidos antes de eliminarlos.', 'wp-secure' ),
                    ),
                ),
            ),

            'performance' => array(
                'title'       => __( 'Rendimiento', 'wp-secure' ),
                'icon'        => 'dashicons-dashboard',
                'description' => '',
                'fields'      => array(
                    array(
                        'key'            => 'exclude_static_from_log',
                        'label'          => __( 'Excluir estáticos del log', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'No registrar peticiones a archivos estáticos (CSS, JS, imágenes)', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'performance_debug',
                        'label'          => __( 'Modo debug de rendimiento', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Mostrar métricas de rendimiento del plugin en el admin bar', 'wp-secure' ),
                        'description'    => __( 'Solo visible para administradores. También escribe tiempos en el error_log.', 'wp-secure' ),
                    ),
                ),
            ),

            'notifications' => array(
                'title'       => __( 'Notificaciones', 'wp-secure' ),
                'icon'        => 'dashicons-email-alt',
                'description' => '',
                'fields'      => array(
                    array(
                        'key'     => 'notify_email',
                        'label'   => __( 'Email de notificación', 'wp-secure' ),
                        'type'    => 'email',
                        'default' => '',
                    ),
                    array(
                        'key'            => 'notify_auto_blocks',
                        'label'          => __( 'Notificar bloqueos automáticos', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Enviar email por cada bloqueo automático (puede generar mucho correo)', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'notify_new_login_ip',
                        'label'          => __( 'Notificar login desde IP nueva', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Enviar email cuando un administrador inicia sesión desde una IP no registrada', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'notify_settings_change',
                        'label'          => __( 'Notificar cambios de configuración', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Enviar email cuando se modifica la configuración del plugin', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'notify_daily_summary',
                        'label'          => __( 'Resumen diario', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Enviar resumen diario de seguridad por email', 'wp-secure' ),
                    ),
                ),
            ),
        );
    }
}
