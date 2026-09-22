<?php
defined( 'ABSPATH' ) || exit;

/**
 * Utilidades de IP: validación, CIDR, rangos, IPv4/IPv6.
 */
class WPS_Ip_Utils {

    /**
     * Validar que un string sea una IP válida (v4 o v6).
     */
    public static function is_valid_ip( string $ip ): bool {
        return false !== filter_var( $ip, FILTER_VALIDATE_IP );
    }

    /**
     * Validar IPv4.
     */
    public static function is_ipv4( string $ip ): bool {
        return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
    }

    /**
     * Validar IPv6.
     */
    public static function is_ipv6( string $ip ): bool {
        return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
    }

    /**
     * ¿Es una IP privada/reservada? (RFC 1918, loopback, etc.)
     */
    public static function is_private_ip( string $ip ): bool {
        return ! filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * ¿La IP es el propio servidor?
     *
     * Cubre loopback (127.0.0.0/8, ::1) y la dirección con la que el servidor
     * atiende la petición (SERVER_ADDR, o LOCAL_ADDR en IIS). Son el origen de
     * wp-cron, los loopbacks de Site Health y los precargadores de caché;
     * bloquearlas o limitarlas deja al sitio sin tareas programadas.
     */
    public static function is_server_ip( string $ip ): bool {
        if ( ! self::is_valid_ip( $ip ) ) {
            return false;
        }

        if ( '::1' === $ip || self::ip_in_cidr( $ip, '127.0.0.0/8' ) ) {
            return true;
        }

        foreach ( array( 'SERVER_ADDR', 'LOCAL_ADDR' ) as $key ) {
            $server_ip = self::strip_port( (string) ( $_SERVER[ $key ] ?? '' ) );
            if ( '' !== $server_ip && self::is_valid_ip( $server_ip )
                && inet_pton( $server_ip ) === inet_pton( $ip ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Convertir IP a representación binaria (16 bytes para v4 y v6).
     *
     * IPv4 se mapea a IPv6 (::ffff:x.x.x.x) para comparación uniforme.
     */
    public static function ip_to_binary( string $ip ): ?string {
        $packed = inet_pton( $ip );
        if ( false === $packed ) {
            return null;
        }
        // IPv4: 4 bytes → mapear a 16 bytes.
        if ( 4 === strlen( $packed ) ) {
            $packed = str_repeat( "\x00", 10 ) . "\xff\xff" . $packed;
        }
        return $packed;
    }

    /**
     * Convertir binario (16 bytes) de vuelta a string IP legible.
     */
    public static function binary_to_ip( string $binary ): ?string {
        if ( 16 !== strlen( $binary ) ) {
            return null;
        }
        // Detectar IPv4-mapped (::ffff:x.x.x.x).
        $prefix = substr( $binary, 0, 12 );
        if ( $prefix === str_repeat( "\x00", 10 ) . "\xff\xff" ) {
            return inet_ntop( substr( $binary, 12, 4 ) );
        }
        return inet_ntop( $binary );
    }

    /**
     * Verificar si una IP está dentro de un rango CIDR.
     *
     * Soporta IPv4 (1.2.3.0/24) e IPv6 (2001:db8::/32).
     */
    public static function ip_in_cidr( string $ip, string $cidr ): bool {
        $parts = explode( '/', $cidr, 2 );
        if ( count( $parts ) !== 2 ) {
            return $ip === $cidr;
        }

        list( $subnet, $mask_bits ) = $parts;
        $mask_bits = (int) $mask_bits;

        $ip_bin     = self::ip_to_binary( $ip );
        $subnet_bin = self::ip_to_binary( $subnet );

        if ( null === $ip_bin || null === $subnet_bin ) {
            return false;
        }

        // Familias distintas nunca coinciden. Sin esto, una IPv6 contra un
        // CIDR IPv4 se comparaba con la máscara sin el prefijo de 96 bits y
        // podía coincidir por los ceros iniciales (p. ej. ::1 con 127.0.0.0/8).
        if ( self::is_ipv4( $ip ) !== self::is_ipv4( $subnet ) ) {
            return false;
        }

        // Ajustar bits de máscara para IPv4-mapped (añadir 96 bits del prefijo).
        if ( self::is_ipv4( $ip ) ) {
            $mask_bits += 96;
        }

        // Comparar bit a bit.
        $full_bytes = (int) floor( $mask_bits / 8 );
        $remaining  = $mask_bits % 8;

        // Comparar bytes completos.
        if ( substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
            return false;
        }

        // Comparar bits restantes del siguiente byte.
        if ( $remaining > 0 && $full_bytes < 16 ) {
            $mask_byte  = 0xFF << ( 8 - $remaining ) & 0xFF;
            $ip_byte    = ord( $ip_bin[ $full_bytes ] );
            $subnet_byte = ord( $subnet_bin[ $full_bytes ] );
            if ( ( $ip_byte & $mask_byte ) !== ( $subnet_byte & $mask_byte ) ) {
                return false;
            }
        }

        return true;
    }

    /**
     * Verificar si una IP está dentro de un rango (start-end) en formato binario.
     */
    public static function ip_in_range( string $ip, string $range_start_bin, string $range_end_bin ): bool {
        $ip_bin = self::ip_to_binary( $ip );
        if ( null === $ip_bin ) {
            return false;
        }
        return $ip_bin >= $range_start_bin && $ip_bin <= $range_end_bin;
    }

    /**
     * Expandir notación CIDR a rango binario (start, end) de 16 bytes.
     *
     * @return array{start: string, end: string}|null
     */
    public static function cidr_to_range( string $cidr ): ?array {
        $parts = explode( '/', $cidr, 2 );
        if ( count( $parts ) !== 2 ) {
            return null;
        }

        list( $subnet, $mask_bits ) = $parts;
        $mask_bits = (int) $mask_bits;

        $subnet_bin = self::ip_to_binary( $subnet );
        if ( null === $subnet_bin ) {
            return null;
        }

        if ( self::is_ipv4( $subnet ) ) {
            $mask_bits += 96;
        }

        // Construir máscara.
        $mask = str_repeat( "\xff", 16 );
        for ( $i = $mask_bits; $i < 128; $i++ ) {
            $byte_index = (int) floor( $i / 8 );
            $bit_offset = $i % 8;
            $mask[ $byte_index ] = chr( ord( $mask[ $byte_index ] ) & ~( 1 << ( 7 - $bit_offset ) ) );
        }

        // Start = subnet AND mask.
        $start = '';
        for ( $i = 0; $i < 16; $i++ ) {
            $start .= chr( ord( $subnet_bin[ $i ] ) & ord( $mask[ $i ] ) );
        }

        // End = start OR (NOT mask).
        $end = '';
        for ( $i = 0; $i < 16; $i++ ) {
            $end .= chr( ord( $start[ $i ] ) | ( ~ord( $mask[ $i ] ) & 0xFF ) );
        }

        return array(
            'start' => $start,
            'end'   => $end,
        );
    }

    /**
     * Validar notación CIDR.
     */
    public static function is_valid_cidr( string $cidr ): bool {
        $parts = explode( '/', $cidr, 2 );
        if ( count( $parts ) !== 2 ) {
            return false;
        }

        list( $subnet, $mask ) = $parts;
        if ( ! self::is_valid_ip( $subnet ) ) {
            return false;
        }

        $mask = (int) $mask;
        $max  = self::is_ipv4( $subnet ) ? 32 : 128;

        return $mask >= 0 && $mask <= $max;
    }

    /**
     * Obtener la subred /24 (IPv4) o /48 (IPv6) de una IP.
     */
    public static function get_network( string $ip, int $prefix = 0 ): ?string {
        if ( 0 === $prefix ) {
            $prefix = self::is_ipv4( $ip ) ? 24 : 48;
        }

        $range = self::cidr_to_range( $ip . '/' . $prefix );
        if ( null === $range ) {
            return null;
        }

        $network_ip = self::binary_to_ip( $range['start'] );
        if ( null === $network_ip ) {
            return null;
        }

        return $network_ip . '/' . $prefix;
    }

    /**
     * Eliminar el número de puerto de una cadena IP si viene en formato ip:puerto.
     *
     * Soporta IPv4 con puerto (1.2.3.4:5678) e IPv6 en notación de corchetes ([::1]:80).
     * Las IPs IPv6 puras (múltiples colons sin corchetes) no se modifican.
     *
     * @param string $value Valor que puede contener IP:puerto.
     * @return string IP sin puerto.
     */
    public static function strip_port( string $value ): string {
        $value = trim( $value );

        // IPv6 con puerto en notación de corchetes: [2001:db8::1]:80
        if ( 0 === strpos( $value, '[' ) ) {
            $bracket_end = strpos( $value, ']' );
            if ( false !== $bracket_end ) {
                return substr( $value, 1, $bracket_end - 1 );
            }
        }

        // IPv4 con puerto: exactamente un colon → separar y descartar puerto.
        if ( 1 === substr_count( $value, ':' ) ) {
            return (string) strstr( $value, ':', true );
        }

        return $value;
    }

    /**
     * Sanitizar un string que puede contener IP:puerto.
     *
     * Elimina puerto si está presente, luego valida.
     * Devuelve la IP limpia o null si no es válida.
     */
    public static function sanitize_ip( string $value ): ?string {
        $ip = self::strip_port( $value );
        if ( self::is_valid_ip( $ip ) ) {
            return $ip;
        }
        return null;
    }

    /**
     * Anonimizar una IP (para mostrar parcialmente).
     * 1.2.3.4 → 1.2.3.***
     */
    public static function anonymize( string $ip ): string {
        if ( self::is_ipv4( $ip ) ) {
            $parts    = explode( '.', $ip );
            $parts[3] = '***';
            return implode( '.', $parts );
        }

        // IPv6: ocultar los últimos 4 grupos.
        $expanded = inet_ntop( inet_pton( $ip ) );
        if ( false === $expanded ) {
            return $ip;
        }
        $parts = explode( ':', $expanded );
        $count = count( $parts );
        for ( $i = max( 0, $count - 4 ); $i < $count; $i++ ) {
            $parts[ $i ] = '****';
        }
        return implode( ':', $parts );
    }
}
