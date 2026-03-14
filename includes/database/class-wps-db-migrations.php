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
            $db->set_setting( 'db_version', WPS_VERSION );
        }
    }
}
