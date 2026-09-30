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
     * Campos de configuración indexados por clave.
     *
     * @return array<string, array>
     */
    public function fields(): array {
        $fields = array();
        foreach ( $this->sections as $section ) {
            foreach ( $section['fields'] as $field ) {
                $fields[ $field['key'] ] = $field;
            }
        }
        return $fields;
    }

    /**
     * Validar un valor que no viene del formulario (p. ej. importado).
     *
     * Aplica las mismas reglas que el formulario, pero en lugar de caer al
     * valor por defecto rechaza lo que no cumple: un archivo importado no
     * puede dejar un ajuste fuera de rango ni con una opción inexistente.
     *
     * @param array $field Definición del campo.
     * @param mixed $value Valor a validar.
     * @return array{0: bool, 1: mixed} [es válido, valor saneado].
     */
    public static function validate_value( array $field, $value ): array {
        switch ( $field['type'] ) {
            case 'checkbox':
                if ( is_bool( $value ) || in_array( $value, array( 0, 1, '0', '1' ), true ) ) {
                    return array( true, (bool) $value );
                }
                return array( false, null );

            case 'number':
                if ( ! is_int( $value ) && ! ( is_string( $value ) && ctype_digit( $value ) ) ) {
                    return array( false, null );
                }
                $value = (int) $value;
                if ( ( isset( $field['min'] ) && $value < $field['min'] ) || ( isset( $field['max'] ) && $value > $field['max'] ) ) {
                    return array( false, null );
                }
                return array( true, $value );

            case 'select':
                $value = is_scalar( $value ) ? (string) $value : '';
                return array_key_exists( $value, $field['options'] ) ? array( true, $value ) : array( false, null );

            case 'email':
                $value = is_string( $value ) ? sanitize_email( $value ) : '';
                return '' !== $value ? array( true, $value ) : array( false, null );

            case 'text':
            case 'password':
                return is_scalar( $value ) ? array( true, sanitize_text_field( (string) $value ) ) : array( false, null );

            case 'textarea':
                return is_scalar( $value ) ? array( true, sanitize_textarea_field( (string) $value ) ) : array( false, null );
        }

        return array( false, null );
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

            <!-- Importar / Exportar Configuración -->
            <div class="wps-section" style="margin-top:20px;">
                <h2><span class="dashicons dashicons-download" style="vertical-align:text-bottom;"></span> <?php esc_html_e( 'Exportar / Importar Configuración', 'wp-secure' ); ?></h2>
                <p class="description"><?php esc_html_e( 'Exporta la configuración completa del plugin (ajustes y reglas personalizadas) como archivo JSON, o importa una configuración previamente exportada.', 'wp-secure' ); ?></p>

                <div style="display:flex;gap:20px;flex-wrap:wrap;margin-top:12px;">
                    <!-- Exportar -->
                    <div style="flex:1;min-width:280px;">
                        <h3><?php esc_html_e( 'Exportar', 'wp-secure' ); ?></h3>
                        <p><?php esc_html_e( 'Descarga un archivo JSON con toda la configuración actual.', 'wp-secure' ); ?></p>
                        <button type="button" class="button button-primary" id="wps-export-config">
                            <span class="dashicons dashicons-download" style="vertical-align:text-top;"></span>
                            <?php esc_html_e( 'Exportar Configuración', 'wp-secure' ); ?>
                        </button>
                    </div>

                    <!-- Importar -->
                    <div style="flex:1;min-width:280px;">
                        <h3><?php esc_html_e( 'Importar', 'wp-secure' ); ?></h3>
                        <p><?php esc_html_e( 'Sube un archivo JSON exportado previamente para restaurar la configuración.', 'wp-secure' ); ?></p>
                        <form id="wps-import-config-form" enctype="multipart/form-data">
                            <input type="file" name="config_file" id="wps-import-config-file" accept=".json" required />
                            <button type="submit" class="button" id="wps-import-config-btn">
                                <span class="dashicons dashicons-upload" style="vertical-align:text-top;"></span>
                                <?php esc_html_e( 'Importar Configuración', 'wp-secure' ); ?>
                            </button>
                        </form>
                    </div>
                </div>
            </div>
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
                        'key'         => 'login_user_max_attempts',
                        'label'       => __( 'Intentos fallidos por cuenta/hora', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 10,
                        'min'         => 0,
                        'max'         => 1000,
                        'description' => __( 'Contra una misma cuenta, desde cualquier IP. Al superarlo, la cuenta sólo acepta logins desde redes donde su dueño ya inició sesión, hasta que los fallos salgan de la ventana de una hora. Frena ataques distribuidos. 0 lo desactiva.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'admin_max_sessions',
                        'label'       => __( 'Sesiones simultáneas por administrador', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 0,
                        'min'         => 0,
                        'max'         => 20,
                        'description' => __( 'Al iniciar una sesión nueva se cierran las más viejas que excedan el límite. Limita el daño de una cookie de sesión robada. 0 = sin límite.', 'wp-secure' ),
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
                        'checkbox_label' => __( 'Bloquear IP tras varios intentos con usuarios que no existen', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'login_unknown_user_threshold',
                        'label'       => __( 'Intentos con usuario inexistente', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 3,
                        'min'         => 0,
                        'max'         => 50,
                        'description' => __( 'Intentos con usuarios inexistentes, en una hora, antes de bloquear la IP. 0 desactiva este bloqueo. Un umbral de 1 bloquea a quien simplemente se equivoca de usuario.', 'wp-secure' ),
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
                        'key'         => 'rate_search_per_min',
                        'label'       => __( 'Búsquedas/minuto', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 20,
                        'min'         => 0,
                        'max'         => 500,
                        'description' => __( 'Por cliente, en el buscador del sitio y en la REST API. Al superarlo se responde 429, sin bloquear la IP. 0 desactiva el límite.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'rate_lostpassword_per_hour',
                        'label'       => __( 'Recuperaciones de contraseña/hora', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 5,
                        'min'         => 0,
                        'max'         => 100,
                        'description' => __( 'Por cliente. Al superarlo se rechaza el pedido, sin bloquear la IP. 0 desactiva el límite.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'rate_register_per_hour',
                        'label'       => __( 'Registros de usuario/hora', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 3,
                        'min'         => 0,
                        'max'         => 100,
                        'description' => __( 'Por cliente, en el registro de WordPress. Al superarlo se rechaza el registro, sin bloquear la IP. 0 desactiva el límite.', 'wp-secure' ),
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
                        'description'    => sprintf(
                            /* translators: %s: ruta absoluta del cargador de la Capa 0. */
                            __( 'Bloquea IPs antes de que PHP cargue WordPress. Máximo rendimiento. La directiva auto_prepend_file debe apuntar a: %s', 'wp-secure' ),
                            WPS_Activator::prepend_loader_path()
                        ),
                    ),
                    array(
                        'key'            => 'integrity_enabled',
                        'label'          => __( 'Monitor de integridad', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Vigilar los archivos de código del núcleo, plugins y temas', 'wp-secure' ),
                        'description'    => __( 'Una vez por día se comparan contra la referencia tomada. Las actualizaciones toman una referencia nueva automáticamente. Los cambios se revisan en WP Seguro → Integridad. También busca archivos PHP en la carpeta de subidas.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'uploads_block_php',
                        'label'          => __( 'PHP en uploads', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Impedir la ejecución de archivos PHP en la carpeta de subidas', 'wp-secure' ),
                        'description'    => __( 'Escribe reglas en uploads/.htaccess (Apache y LiteSpeed) y, con la Capa 0 activa, también lo aplica ahí (nginx). Un webshell subido por un formulario o un plugin vulnerable deja de poder ejecutarse.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'activity_log_enabled',
                        'label'          => __( 'Registro de actividad', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Registrar las acciones de quienes editan el sitio (usuarios, contenido, plugins, temas y ajustes)', 'wp-secure' ),
                        'description'    => __( 'Se consulta en WP Seguro → Actividad. Sólo se registran usuarios que pueden editar contenido y WP-CLI.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'honeypot_enabled',
                        'label'          => __( 'Rutas trampa', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Bloquear de inmediato a quien pida una ruta trampa', 'wp-secure' ),
                        'description'    => __( 'Rutas que ningún visitante legítimo pide pero todo scanner prueba (/.env, copias de wp-config, /.git/). Los administradores logueados y la whitelist no se bloquean.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'honeypot_paths',
                        'label'       => __( 'Rutas trampa', 'wp-secure' ),
                        'type'        => 'textarea',
                        'default'     => WPS_Honeypot::DEFAULT_PATHS,
                        'description' => __( 'Una por línea. Se compara el final de la ruta, sin distinguir mayúsculas. Un * al final abarca todo lo que haya debajo (p. ej. /.git/*).', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'honeypot_block_minutes',
                        'label'       => __( 'Duración del bloqueo por ruta trampa (minutos)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => WPS_Honeypot::DEFAULT_BLOCK_MINUTES,
                        'min'         => 1,
                        'max'         => 43200,
                    ),
                    array(
                        'key'            => 'form_guard_enabled',
                        'label'          => __( 'Protección de formularios', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Campo trampa y tiempo mínimo en login y comentarios', 'wp-secure' ),
                        'description'    => __( 'Frena bots sin captcha. Un comentario enviado sin los campos del plugin (por ejemplo, desde una página cacheada antes de activar la función) va a la cola de spam en lugar de rechazarse.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'form_guard_comment_min_seconds',
                        'label'       => __( 'Tiempo mínimo para comentar (segundos)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 3,
                        'min'         => 0,
                        'max'         => 60,
                        'description' => __( 'Un comentario enviado antes de este tiempo desde que se cargó la página se rechaza. 0 desactiva el control.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'form_guard_login_min_seconds',
                        'label'       => __( 'Tiempo mínimo para iniciar sesión (segundos)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 0,
                        'min'         => 0,
                        'max'         => 30,
                        'description' => __( 'Desactivado por defecto: los gestores de contraseñas con envío automático completan el login en menos de un segundo. El campo trampa sigue activo.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'ipv6_block_prefix',
                        'label'       => __( 'Prefijo IPv6 por cliente', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 64,
                        'min'         => 48,
                        'max'         => 128,
                        'description' => __( 'En IPv6 cada cliente recibe normalmente un /64 completo y puede cambiar de dirección en cada petición. El rate limiting, el conteo de intentos de login y los bloqueos automáticos se aplican a toda la red de este prefijo. 128 = dirección exacta. Los bloqueos manuales y la whitelist siempre usan la dirección exacta.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'range_escalation_enabled',
                        'label'          => __( 'Escalada a rango', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Bloquear el /24 (IPv4) o /48 (IPv6) cuando varias de sus IPs reciben bloqueos automáticos en poco tiempo', 'wp-secure' ),
                        'description'    => __( 'Frena a quien rota de IP dentro de un rango de hosting. Nunca se bloquea un rango que contenga al servidor, una entrada de la whitelist o una red desde la que algún usuario inició sesión.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'range_escalation_threshold',
                        'label'       => __( 'Clientes bloqueados para escalar', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 3,
                        'min'         => 2,
                        'max'         => 50,
                        'description' => __( 'IPs distintas del mismo rango (en IPv6, redes del prefijo por cliente) con bloqueo automático dentro de la ventana.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'range_escalation_window',
                        'label'       => __( 'Ventana de la escalada (minutos)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 60,
                        'min'         => 5,
                        'max'         => 1440,
                    ),
                    array(
                        'key'         => 'range_escalation_minutes',
                        'label'       => __( 'Duración del bloqueo de rango (minutos)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 1440,
                        'min'         => 15,
                        'max'         => 43200,
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
                        'key'         => 'risk_engine_mode',
                        'label'       => __( 'Motor de puntuación de riesgo', 'wp-secure' ),
                        'type'        => 'select',
                        'default'     => 'off',
                        'options'     => array(
                            'off'     => __( 'Desactivado', 'wp-secure' ),
                            'shadow'  => __( 'Modo sombra (mide y registra, no bloquea)', 'wp-secure' ),
                            'enforce' => __( 'Activo (bloquea según el puntaje)', 'wp-secure' ),
                        ),
                        'description' => __( 'Puntúa cada petición combinando varios factores (User-Agent, ruta, tasa de peticiones, país, detecciones). Activá primero el modo sombra: durante unos días WP Seguro → Motor de riesgo muestra a quién habría bloqueado, con qué factores y qué umbral conviene, sin que se bloquee a nadie. Cuando los números tengan sentido para tu sitio, pasalo a Activo.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'risk_block_threshold',
                        'label'       => __( 'Umbral de bloqueo por riesgo', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 81,
                        'min'         => 51,
                        'max'         => 500,
                        'description' => __( 'Puntaje desde el que el motor bloquea temporalmente. El reporte del modo sombra sugiere un valor para tu tráfico.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'risk_hard_block_threshold',
                        'label'       => __( 'Umbral de bloqueo permanente', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 101,
                        'min'         => 0,
                        'max'         => 1000,
                        'description' => __( 'Puntaje desde el que el bloqueo es permanente. 0 = nunca permanente (sólo temporal).', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'risky_countries',
                        'label'       => __( 'Países de alto riesgo', 'wp-secure' ),
                        'type'        => 'text',
                        'default'     => '',
                        'description' => __( 'Códigos de país separados por coma (ej: CN,RU,KP). Aumenta la puntuación de riesgo para IPs de estos países. Requiere el motor de riesgo encendido.', 'wp-secure' ),
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
                        'key'         => 'hsts_max_age',
                        'label'       => __( 'HSTS', 'wp-secure' ),
                        'type'        => 'select',
                        'default'     => '0',
                        'options'     => array(
                            '0'        => __( 'Desactivado', 'wp-secure' ),
                            '300'      => __( '5 minutos (para probar)', 'wp-secure' ),
                            '86400'    => __( '1 día', 'wp-secure' ),
                            '2592000'  => __( '30 días', 'wp-secure' ),
                            '31536000' => __( '1 año (recomendado una vez probado)', 'wp-secure' ),
                        ),
                        'description' => __( 'Obliga a los navegadores a usar siempre HTTPS durante ese tiempo. Sólo se envía por HTTPS. Mientras dure, el sitio no se puede volver a servir por HTTP: empezá con 5 minutos y subilo cuando confirmes que todo funciona.', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'hsts_include_subdomains',
                        'label'          => __( 'HSTS en subdominios', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => false,
                        'checkbox_label' => __( 'Incluir los subdominios (includeSubDomains)', 'wp-secure' ),
                        'description'    => __( 'Activalo sólo si todos los subdominios tienen HTTPS.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'csp_mode',
                        'label'       => __( 'Content-Security-Policy', 'wp-secure' ),
                        'type'        => 'select',
                        'default'     => 'off',
                        'options'     => array(
                            'off'     => __( 'Desactivada', 'wp-secure' ),
                            'report'  => __( 'Sólo reportar (no bloquea nada)', 'wp-secure' ),
                            'enforce' => __( 'Aplicar', 'wp-secure' ),
                        ),
                        'description' => __( 'Empezá en «Sólo reportar»: los navegadores informan lo que la política habría bloqueado y WP Seguro → Endurecimiento arma una política sugerida con esos orígenes. Aplicala recién cuando no aparezcan reportes nuevos.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'csp_policy',
                        'label'       => __( 'Política CSP', 'wp-secure' ),
                        'type'        => 'textarea',
                        'default'     => '',
                        'description' => __( 'Una directiva por línea o separadas por «;». Vacío usa la política base para WordPress. El destino de los reportes se agrega solo.', 'wp-secure' ),
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
                    array(
                        'key'         => 'retention_activity_days',
                        'label'       => __( 'Registro de actividad (días)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 180,
                        'min'         => 7,
                        'max'         => 730,
                    ),
                ),
            ),

            'performance' => array(
                'title'       => __( 'Rendimiento', 'wp-secure' ),
                'icon'        => 'dashicons-dashboard',
                'description' => '',
                'fields'      => array(
                    array(
                        'key'         => 'traffic_log_mode',
                        'label'       => __( 'Registro de tráfico', 'wp-secure' ),
                        'type'        => 'select',
                        'default'     => 'full',
                        'options'     => array(
                            'full'     => __( 'Todas las peticiones', 'wp-secure' ),
                            'sampled'  => __( 'Muestreo (para sitios con mucho tráfico)', 'wp-secure' ),
                            'relevant' => __( 'Sólo errores y peticiones que no son GET', 'wp-secure' ),
                            'off'      => __( 'Desactivado', 'wp-secure' ),
                        ),
                        'description' => __( 'Cada petición registrada es una escritura en la base de datos. Con muestreo se guarda una de cada N con su peso, así los totales del dashboard siguen siendo estimaciones correctas; los errores (4xx, 5xx) y las peticiones POST se guardan siempre. No afecta la detección ni los bloqueos.', 'wp-secure' ),
                    ),
                    array(
                        'key'         => 'traffic_sample_rate',
                        'label'       => __( 'Tasa de muestreo (1 de cada N)', 'wp-secure' ),
                        'type'        => 'number',
                        'default'     => 10,
                        'min'         => 2,
                        'max'         => 1000,
                    ),
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

            'detectors' => array(
                'title'       => __( 'Detectores', 'wp-secure' ),
                'icon'        => 'dashicons-visibility',
                'description' => __( 'Activa o desactiva los detectores de amenazas individualmente. Desactivar un detector evita que analice las peticiones entrantes. Útil para evitar falsos positivos o limitar el alcance del firewall.', 'wp-secure' ),
                'fields'      => array(
                    array(
                        'key'            => 'detector_login_enabled',
                        'label'          => __( 'Login (Fuerza Bruta)', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Detectar ataques de fuerza bruta al login de WordPress', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'detector_xmlrpc_enabled',
                        'label'          => __( 'XML-RPC', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Detectar y bloquear accesos a xmlrpc.php', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'detector_sqli_enabled',
                        'label'          => __( 'SQL Injection', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Detectar intentos de inyección SQL en parámetros y URIs', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'detector_xss_enabled',
                        'label'          => __( 'XSS (Cross-Site Scripting)', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Detectar intentos de inyección de scripts maliciosos', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'detector_path_traversal_enabled',
                        'label'          => __( 'Path Traversal', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Detectar intentos de recorrido de directorios y acceso a archivos sensibles', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'detector_scanner_enabled',
                        'label'          => __( 'Scanner', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Detectar herramientas de escaneo de vulnerabilidades y enumeración', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'detector_restapi_enabled',
                        'label'          => __( 'REST API', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Detectar abuso de la REST API de WordPress', 'wp-secure' ),
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
                        'checkbox_label' => __( 'Enviar un resumen por hora de los bloqueos automáticos (sólo si hubo alguno)', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'notify_new_login_ip',
                        'label'          => __( 'Notificar login desde IP nueva', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Enviar email cuando un administrador inicia sesión desde una IP no registrada', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'notify_file_changes',
                        'label'          => __( 'Notificar archivos modificados', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Enviar email cuando el monitor de integridad encuentre archivos de código modificados, nuevos o eliminados', 'wp-secure' ),
                    ),
                    array(
                        'key'            => 'notify_privilege_changes',
                        'label'          => __( 'Notificar cambios de privilegios', 'wp-secure' ),
                        'type'           => 'checkbox',
                        'default'        => true,
                        'checkbox_label' => __( 'Enviar email al crear un administrador, ascender un rol, instalar o activar un plugin o tema, desactivar un plugin o editar un archivo desde el panel', 'wp-secure' ),
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
