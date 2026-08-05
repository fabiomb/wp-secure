<?php
defined( 'ABSPATH' ) || exit;

/**
 * Gestión de la whitelist de IPs.
 */
class WPS_Whitelist {

    /** @var WPS_Whitelist|null */
    private static $instance = null;

    /** @var WPS_Db */
    private $db;

    /** @var array|null Cache de IPs en whitelist global. */
    private $cache = null;

    private function __construct() {
        $this->db = WPS_Db::get_instance();
    }

    public static function get_instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Verificar si una IP está en la whitelist (global o tipo específico).
     *
     * Cada petición consulta esto una decena de veces (loader, detectores,
     * hardener, rate limiter). La tabla es chica y estable, así que se carga
     * entera una sola vez y las coincidencias se resuelven en memoria.
     */
    public function is_whitelisted( string $ip, string $type = 'global' ): bool {
        return self::matches_entries( $ip, $type, $this->get_entries() );
    }

    /**
     * Resolver una coincidencia contra un conjunto de entradas ya cargadas.
     *
     * @param string $ip      IP del visitante.
     * @param string $type    Tipo consultado (global, login, …).
     * @param array  $entries Filas con ip_address, cidr y whitelist_type.
     */
    public static function matches_entries( string $ip, string $type, array $entries ): bool {
        foreach ( $entries as $entry ) {
            $entry_type = $entry['whitelist_type'] ?? 'global';

            // Las entradas globales aplican a todo; las tipadas sólo a su tipo.
            if ( 'global' !== $entry_type && $type !== $entry_type ) {
                continue;
            }

            if ( ! empty( $entry['ip_address'] ) && $entry['ip_address'] === $ip ) {
                return true;
            }

            if ( ! empty( $entry['cidr'] ) && WPS_Ip_Utils::ip_in_cidr( $ip, $entry['cidr'] ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Cargar la whitelist completa, una sola vez por petición.
     */
    private function get_entries(): array {
        if ( null !== $this->cache ) {
            return $this->cache;
        }

        $table = WPS_Db_Schema::table( 'whitelist' );

        $this->cache = $this->db->get_results(
            "SELECT ip_address, cidr, whitelist_type FROM {$table}"
        );

        return $this->cache;
    }

    /**
     * Agregar una IP a la whitelist.
     *
     * @return int|false ID de la entrada o false en error.
     */
    public function add_ip( string $ip, string $label, string $type = 'global' ) {
        if ( ! WPS_Ip_Utils::is_valid_ip( $ip ) ) {
            return false;
        }

        // Verificar duplicados.
        if ( $this->is_whitelisted( $ip, $type ) ) {
            return false;
        }

        $this->cache = null; // Invalidar cache.

        return $this->db->insert( 'whitelist', array(
            'ip_address'     => $ip,
            'label'          => substr( $label, 0, 255 ),
            'whitelist_type' => $type,
            'created_at'     => current_time( 'mysql', true ),
        ) );
    }

    /**
     * Agregar un rango CIDR a la whitelist.
     */
    public function add_cidr( string $cidr, string $label, string $type = 'global' ) {
        if ( ! WPS_Ip_Utils::is_valid_cidr( $cidr ) ) {
            return false;
        }

        $this->cache = null;

        return $this->db->insert( 'whitelist', array(
            'cidr'           => $cidr,
            'label'          => substr( $label, 0, 255 ),
            'whitelist_type' => $type,
            'created_at'     => current_time( 'mysql', true ),
        ) );
    }

    /**
     * Eliminar una entrada de la whitelist por ID.
     */
    public function remove( int $id ): bool {
        $this->cache = null;
        return $this->db->delete( 'whitelist', array( 'id' => $id ) ) > 0;
    }

    /**
     * Obtener todas las entradas de la whitelist, opcionalmente filtradas por tipo.
     */
    public function get_all( string $type = '' ): array {
        $table = WPS_Db_Schema::table( 'whitelist' );

        if ( $type ) {
            return $this->db->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "SELECT * FROM {$table} WHERE whitelist_type = %s ORDER BY created_at DESC",
                $type
            );
        }

        return $this->db->get_results(
            "SELECT * FROM {$table} ORDER BY whitelist_type ASC, created_at DESC"
        );
    }

    /**
     * Obtener entradas paginadas.
     */
    public function get_paginated( int $page = 1, int $per_page = 20, string $type = '' ): array {
        $table  = WPS_Db_Schema::table( 'whitelist' );
        $offset = ( $page - 1 ) * $per_page;

        if ( $type ) {
            $total = (int) $this->db->get_var(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "SELECT COUNT(*) FROM {$table} WHERE whitelist_type = %s",
                $type
            );
            $items = $this->db->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "SELECT * FROM {$table} WHERE whitelist_type = %s ORDER BY created_at DESC LIMIT %d OFFSET %d",
                $type,
                $per_page,
                $offset
            );
        } else {
            $total = (int) $this->db->get_var(
                "SELECT COUNT(*) FROM {$table}"
            );
            $items = $this->db->get_results(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                "SELECT * FROM {$table} ORDER BY whitelist_type ASC, created_at DESC LIMIT %d OFFSET %d",
                $per_page,
                $offset
            );
        }

        return array(
            'items'    => $items,
            'total'    => $total,
            'pages'    => ceil( $total / $per_page ),
            'page'     => $page,
            'per_page' => $per_page,
        );
    }
}
