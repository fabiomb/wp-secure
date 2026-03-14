<?php
defined( 'ABSPATH' ) || exit;

/**
 * Lógica de desactivación del plugin.
 *
 * No elimina datos para permitir reactivación.
 */
class WPS_Deactivator {

    /**
     * Hook de desactivación.
     */
    public static function deactivate(): void {
        // Remover tareas de cron.
        WPS_Db_Maintenance::unschedule();

        // Remover MU-Plugin (Capa 1).
        WPS_Activator::remove_muplugin();

        // Marcar como desactivado.
        update_option( 'wps_activated', false );
    }
}
