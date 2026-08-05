<?php
defined( 'ABSPATH' ) || exit;

/**
 * Migraciones de esquema de base de datos.
 *
 * Permite actualizar el esquema entre versiones del plugin.
 */
class WPS_Db_Migrations {

    /**
     * Ejecutar migraciones pendientes.
     */
    public static function run(): void {
        $db              = WPS_Db::get_instance();
        $current_version = $db->get_setting( 'db_version', '0.0.0' );

        // Si no hay versión previa o es igual a la actual, re-ejecutar dbDelta por seguridad.
        if ( version_compare( $current_version, WPS_VERSION, '<' ) ) {
            WPS_Db_Schema::create_tables();

            self::adopt_existing_layer0( $db, $current_version );

            $db->set_setting( 'db_version', WPS_VERSION );
        }
    }

    /**
     * Reconocer instalaciones que ya tenían la Capa 0 en funcionamiento.
     *
     * Hasta la 0.2.11 el ajuste `firewall_layer0_enabled` no controlaba nada:
     * el archivo de bloqueos se escribía siempre, quedara el checkbox marcado o
     * no. Ahora sí lo controla, así que un sitio con la Capa 0 realmente
     * configurada en .htaccess perdería protección al actualizar. Si el archivo
     * de datos ya existe, se da el ajuste por activado.
     */
    private static function adopt_existing_layer0( WPS_Db $db, string $from_version ): void {
        if ( version_compare( $from_version, '0.2.11', '>=' ) ) {
            return;
        }

        if ( ! is_file( WPS_DATA_DIR . 'wps-blocked-ips.php' ) ) {
            return;
        }

        $db->set_setting( 'firewall_layer0_enabled', true );
    }
}
