<?php
defined( 'ABSPATH' ) || exit;

/**
 * Acceso a base de datos propia del plugin.
 *
 * Wrapper sobre $wpdb para las tablas wps_*.
 */
class WPS_Db {

    /** @var WPS_Db|null */
    private static $instance = null;

    /** @var wpdb */
    private $wpdb;

    private function __construct() {
        global $wpdb;
        $this->wpdb = $wpdb;
    }

    public static function get_instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Nombre completo de una tabla.
     */
    public function table( string $name ): string {
        return WPS_Db_Schema::table( $name );
    }

    /*──────────────────────────────────────────────
     * Settings
     *──────────────────────────────────────────────*/

    /**
     * Obtener un setting.
     *
     * @param string $key     Clave del setting.
     * @param mixed  $default Valor por defecto.
     * @return mixed
     */
    public function get_setting( string $key, $default = null ) {
        $table = $this->table( 'settings' );
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $value = $this->wpdb->get_var(
            $this->wpdb->prepare(
                "SELECT setting_value FROM {$table} WHERE setting_key = %s",
                $key
            )
        );

        if ( null === $value ) {
            return $default;
        }

        $decoded = json_decode( $value, true );
        return ( json_last_error() === JSON_ERROR_NONE ) ? $decoded : $value;
    }

    /**
     * Guardar un setting.
     */
    public function set_setting( string $key, $value, bool $autoload = true ): bool {
        $table    = $this->table( 'settings' );
        $encoded  = is_string( $value ) ? $value : wp_json_encode( $value );

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $result = $this->wpdb->query(
            $this->wpdb->prepare(
                "INSERT INTO {$table} (setting_key, setting_value, autoload)
                 VALUES (%s, %s, %d)
                 ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), autoload = VALUES(autoload)",
                $key,
                $encoded,
                $autoload ? 1 : 0
            )
        );

        return false !== $result;
    }

    /**
     * Eliminar un setting.
     */
    public function delete_setting( string $key ): bool {
        $table = $this->table( 'settings' );
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $result = $this->wpdb->delete( $table, array( 'setting_key' => $key ), array( '%s' ) );
        return false !== $result;
    }

    /**
     * Obtener todos los settings con autoload.
     */
    public function get_autoload_settings(): array {
        $table = $this->table( 'settings' );
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $rows = $this->wpdb->get_results(
            "SELECT setting_key, setting_value FROM {$table} WHERE autoload = 1",
            ARRAY_A
        );

        $settings = array();
        if ( $rows ) {
            foreach ( $rows as $row ) {
                $decoded = json_decode( $row['setting_value'], true );
                $settings[ $row['setting_key'] ] = ( json_last_error() === JSON_ERROR_NONE ) ? $decoded : $row['setting_value'];
            }
        }
        return $settings;
    }

    /*──────────────────────────────────────────────
     * Generic helpers
     *──────────────────────────────────────────────*/

    /**
     * Insertar una fila en una tabla del plugin.
     *
     * @return int|false  El ID insertado (o 1 si no hay auto-increment) o false en error.
     */
    public function insert( string $table_name, array $data, array $format = array() ) {
        $table  = $this->table( $table_name );
        $result = $this->wpdb->insert( $table, $data, $format ?: null );
        if ( ! $result ) {
            return false;
        }
        return $this->wpdb->insert_id ?: 1;
    }

    /**
     * Actualizar filas.
     */
    public function update( string $table_name, array $data, array $where, array $format = array(), array $where_format = array() ): int {
        $table  = $this->table( $table_name );
        $result = $this->wpdb->update( $table, $data, $where, $format ?: null, $where_format ?: null );
        return $result !== false ? $result : 0;
    }

    /**
     * Eliminar filas.
     */
    public function delete( string $table_name, array $where, array $where_format = array() ): int {
        $table  = $this->table( $table_name );
        $result = $this->wpdb->delete( $table, $where, $where_format ?: null );
        return $result !== false ? $result : 0;
    }

    /**
     * Ejecutar una query preparada y devolver resultados.
     */
    public function get_results( string $query, ...$args ): array {
        if ( $args ) {
            $query = $this->wpdb->prepare( $query, ...$args );
        }
        $results = $this->wpdb->get_results( $query, ARRAY_A );
        return $results ?: array();
    }

    /**
     * Devolver un valor escalar.
     */
    public function get_var( string $query, ...$args ) {
        if ( $args ) {
            $query = $this->wpdb->prepare( $query, ...$args );
        }
        return $this->wpdb->get_var( $query );
    }

    /**
     * Devolver una fila.
     */
    public function get_row( string $query, ...$args ): ?array {
        if ( $args ) {
            $query = $this->wpdb->prepare( $query, ...$args );
        }
        $row = $this->wpdb->get_row( $query, ARRAY_A );
        return $row ?: null;
    }

    /**
     * Query directa (para INSERT ON DUPLICATE u operaciones complejas).
     */
    public function query( string $query, ...$args ): int {
        if ( $args ) {
            $query = $this->wpdb->prepare( $query, ...$args );
        }
        $result = $this->wpdb->query( $query );
        return $result !== false ? (int) $result : 0;
    }

    /**
     * Preparar una query con placeholders.
     */
    public function prepare( string $query, ...$args ): string {
        return $this->wpdb->prepare( $query, ...$args );
    }

    /**
     * Escapar un valor para uso con LIKE.
     */
    public function esc_like( string $text ): string {
        return $this->wpdb->esc_like( $text );
    }

    /**
     * Último error de la BD.
     */
    public function last_error(): string {
        return $this->wpdb->last_error;
    }
}
