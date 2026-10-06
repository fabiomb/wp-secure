<?php
defined( 'ABSPATH' ) || exit;

/**
 * Extracción mínima de un archivo de un .tar.gz.
 *
 * MaxMind entrega sus bases como `GeoLite2-Country_AAAAMMDD/GeoLite2-Country.mmdb`
 * dentro de un .tar.gz. PharData no siempre está disponible (extensión phar
 * deshabilitada en muchos hostings), así que se lee el formato ustar a mano
 * con zlib: sólo se busca el primer archivo regular con la extensión pedida
 * y se copia su contenido al destino. Nunca se usa el nombre del miembro
 * para escribir en disco.
 */
class WPS_Tar_Reader {

	/** Tamaño de bloque del formato tar. */
	const BLOCK = 512;

	/**
	 * Extraer el primer archivo regular cuyo nombre termine en `$suffix`.
	 *
	 * @param string $archive   Ruta del .tar.gz.
	 * @param string $dest      Ruta donde escribir el contenido.
	 * @param string $suffix    Extensión buscada (p. ej. '.mmdb').
	 * @param int    $max_bytes Tamaño máximo aceptado del miembro.
	 * @throws \RuntimeException Si el archivo no se puede leer, no contiene el
	 *                           miembro o el miembro no es aceptable.
	 */
	public static function extract( string $archive, string $dest, string $suffix, int $max_bytes ): void {
		if ( ! function_exists( 'gzopen' ) ) {
			throw new \RuntimeException( 'zlib no está disponible.' );
		}

		$gz = @gzopen( $archive, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $gz ) {
			throw new \RuntimeException( 'No se pudo abrir el archivo comprimido.' );
		}

		try {
			self::extract_from( $gz, $dest, $suffix, $max_bytes );
		} finally {
			gzclose( $gz );
		}
	}

	/**
	 * @param resource $gz
	 */
	private static function extract_from( $gz, string $dest, string $suffix, int $max_bytes ): void {
		$long_name = null;

		while ( true ) {
			$header = self::read_exact( $gz, self::BLOCK );
			if ( null === $header || '' === trim( $header, "\0" ) ) {
				// Fin del archivo (o bloque de ceros final).
				break;
			}

			if ( 'ustar' !== substr( $header, 257, 5 ) ) {
				throw new \RuntimeException( 'El archivo no tiene formato tar.' );
			}

			$size = self::parse_octal( substr( $header, 124, 12 ) );
			if ( $size < 0 ) {
				throw new \RuntimeException( 'Cabecera tar inválida.' );
			}

			$type   = $header[156];
			$name   = rtrim( substr( $header, 0, 100 ), "\0" );
			$prefix = rtrim( substr( $header, 345, 155 ), "\0" );
			if ( '' !== $prefix ) {
				$name = $prefix . '/' . $name;
			}
			if ( null !== $long_name ) {
				$name      = $long_name;
				$long_name = null;
			}

			// Nombre largo de GNU tar: el contenido es el nombre del miembro siguiente.
			if ( 'L' === $type ) {
				if ( $size > 4096 ) {
					throw new \RuntimeException( 'Cabecera tar inválida.' );
				}
				$data      = self::read_exact( $gz, self::padded( $size ) );
				$long_name = rtrim( (string) substr( (string) $data, 0, $size ), "\0" );
				continue;
			}

			$is_regular = ( '0' === $type || "\0" === $type );
			if ( ! $is_regular || substr( strtolower( $name ), -strlen( $suffix ) ) !== $suffix ) {
				self::skip( $gz, self::padded( $size ) );
				continue;
			}

			if ( ! self::is_safe_name( $name ) ) {
				throw new \RuntimeException( 'El archivo contiene una ruta no permitida.' );
			}

			if ( $size > $max_bytes ) {
				throw new \RuntimeException( 'El archivo contenido supera el tamaño máximo permitido.' );
			}

			self::copy_to( $gz, $dest, $size );
			return;
		}

		throw new \RuntimeException( 'El archivo comprimido no contiene una base de datos.' );
	}

	/**
	 * Nombre relativo, sin componentes `..` ni rutas absolutas.
	 */
	private static function is_safe_name( string $name ): bool {
		$name = str_replace( '\\', '/', $name );
		if ( '' === $name || '/' === $name[0] || preg_match( '/^[a-zA-Z]:/', $name ) ) {
			return false;
		}
		return ! in_array( '..', explode( '/', $name ), true );
	}

	/**
	 * Copiar `$size` bytes del archivo comprimido al destino.
	 *
	 * @param resource $gz
	 */
	private static function copy_to( $gz, string $dest, int $size ): void {
		$out = @fopen( $dest, 'wb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
		if ( false === $out ) {
			throw new \RuntimeException( 'No se pudo escribir el archivo temporal.' );
		}

		$remaining = $size;
		while ( $remaining > 0 ) {
			$chunk = gzread( $gz, min( 1048576, $remaining ) );
			if ( false === $chunk || '' === $chunk ) {
				fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				throw new \RuntimeException( 'El archivo comprimido está truncado.' );
			}
			fwrite( $out, $chunk ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$remaining -= strlen( $chunk );
		}

		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/**
	 * @param resource $gz
	 */
	private static function skip( $gz, int $bytes ): void {
		while ( $bytes > 0 ) {
			$chunk = gzread( $gz, min( 1048576, $bytes ) );
			if ( false === $chunk || '' === $chunk ) {
				throw new \RuntimeException( 'El archivo comprimido está truncado.' );
			}
			$bytes -= strlen( $chunk );
		}
	}

	/**
	 * Leer exactamente `$bytes` bytes; null si el archivo terminó antes.
	 *
	 * @param resource $gz
	 */
	private static function read_exact( $gz, int $bytes ): ?string {
		$data = '';
		while ( strlen( $data ) < $bytes ) {
			$chunk = gzread( $gz, $bytes - strlen( $data ) );
			if ( false === $chunk || '' === $chunk ) {
				return '' === $data ? null : $data;
			}
			$data .= $chunk;
		}
		return $data;
	}

	/**
	 * Tamaño redondeado al bloque siguiente.
	 */
	private static function padded( int $size ): int {
		return (int) ( ceil( $size / self::BLOCK ) * self::BLOCK );
	}

	/**
	 * Número octal de una cabecera tar; -1 si no es válido.
	 */
	private static function parse_octal( string $field ): int {
		$field = trim( $field, "\0 " );
		if ( '' === $field ) {
			return 0;
		}
		if ( ! preg_match( '/^[0-7]+$/', $field ) ) {
			return -1;
		}
		return (int) octdec( $field );
	}
}
