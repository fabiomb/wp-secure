<?php
defined( 'ABSPATH' ) || exit;

/**
 * Lector puro PHP de archivos MMDB (MaxMind DB / ipinfo.io).
 *
 * Implementa la lectura del formato MaxMind DB v2 sin dependencias externas.
 * Compatible con bases de datos de ipinfo.io y MaxMind GeoLite2.
 *
 * @link https://maxmind.github.io/MaxMind-DB/
 */
class WPS_Mmdb_Reader {

	const METADATA_MARKER = "\xAB\xCD\xEFMaxMind.com";

	// Data types in the MMDB format.
	const TYPE_EXTENDED  = 0;
	const TYPE_POINTER   = 1;
	const TYPE_UTF8      = 2;
	const TYPE_DOUBLE    = 3;
	const TYPE_BYTES     = 4;
	const TYPE_UINT16    = 5;
	const TYPE_UINT32    = 6;
	const TYPE_MAP       = 7;
	const TYPE_INT32     = 8;
	const TYPE_UINT64    = 9;
	const TYPE_UINT128   = 10;
	const TYPE_ARRAY     = 11;
	const TYPE_CONTAINER = 12;
	const TYPE_END       = 13;
	const TYPE_BOOLEAN   = 14;
	const TYPE_FLOAT     = 15;

	/** @var string|null */
	private $file_path;

	/** @var resource|null */
	private $file_handle;

	/** @var string File content loaded in memory for fast reads. */
	private $file_content;

	/** @var int */
	private $file_size;

	/** @var array Metadata decoded from the MMDB file. */
	private $metadata;

	/** @var int Size of each record in bits. */
	private $record_size;

	/** @var int Number of nodes in the search tree. */
	private $node_count;

	/** @var int Size of each node in bytes. */
	private $node_byte_size;

	/** @var int Byte offset where the search tree ends and data begins. */
	private $search_tree_size;

	/** @var int Byte offset where the data section starts (after 16-byte separator). */
	private $data_start;

	/** @var int IP version (4 or 6). */
	private $ip_version;

	/**
	 * Open and parse an MMDB file.
	 *
	 * @param string $file_path Absolute path to the .mmdb file.
	 * @throws \RuntimeException If the file cannot be read or parsed.
	 */
	public function __construct( string $file_path ) {
		if ( ! is_file( $file_path ) || ! is_readable( $file_path ) ) {
			throw new \RuntimeException( "MMDB file not readable: {$file_path}" );
		}

		$this->file_path = $file_path;
		$this->file_size = filesize( $file_path );

		if ( $this->file_size < 100 ) {
			throw new \RuntimeException( 'MMDB file is too small to be valid.' );
		}

		// Load entire file into memory for fast reads (databases are typically 10-30MB).
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$this->file_content = file_get_contents( $file_path );
		if ( false === $this->file_content ) {
			throw new \RuntimeException( "Failed to read MMDB file: {$file_path}" );
		}

		$this->read_metadata();
	}

	/**
	 * Look up an IP address in the database.
	 *
	 * @param string $ip IPv4 or IPv6 address.
	 * @return array|null Record data or null if not found.
	 */
	public function lookup( string $ip ): ?array {
		$packed = @inet_pton( $ip );
		if ( false === $packed ) {
			return null;
		}

		// For IPv4-only databases, use the raw 4-byte address.
		// For IPv6 databases, map IPv4 to IPv6.
		if ( 4 === strlen( $packed ) && 6 === $this->ip_version ) {
			// IPv4-mapped IPv6: ::ffff:x.x.x.x
			$packed = str_repeat( "\x00", 12 ) . $packed;
		}

		$bit_count = strlen( $packed ) * 8;

		// Walk the binary search tree.
		$node = 0;
		for ( $i = 0; $i < $bit_count; $i++ ) {
			if ( $node >= $this->node_count ) {
				break;
			}

			$byte = ord( $packed[ (int) ( $i / 8 ) ] );
			$bit  = 1 & ( $byte >> ( 7 - ( $i % 8 ) ) );

			$node = $this->read_node( $node, $bit );
		}

		// node_count means "not found".
		if ( $node === $this->node_count ) {
			return null;
		}

		// node > node_count means it's a data pointer.
		if ( $node > $this->node_count ) {
			$data_offset = $node - $this->node_count - 16;
			$result      = $this->decode_data( $this->data_start + $data_offset );
			return is_array( $result[0] ) ? $result[0] : null;
		}

		return null;
	}

	/**
	 * Get metadata about the database.
	 *
	 * @return array
	 */
	public function get_metadata(): array {
		return $this->metadata;
	}

	/**
	 * Get the database type (e.g. "GeoLite2-Country", "ipinfo country_asn").
	 */
	public function get_type(): string {
		return $this->metadata['database_type'] ?? 'unknown';
	}

	/**
	 * Get build epoch timestamp.
	 */
	public function get_build_time(): int {
		return (int) ( $this->metadata['build_epoch'] ?? 0 );
	}

	/**
	 * Close and release resources.
	 */
	public function close(): void {
		$this->file_content = '';
	}

	/**
	 * Read and parse metadata from the end of the file.
	 */
	private function read_metadata(): void {
		$marker_pos = strrpos( $this->file_content, self::METADATA_MARKER );
		if ( false === $marker_pos ) {
			throw new \RuntimeException( 'MMDB metadata marker not found.' );
		}

		$meta_start = $marker_pos + strlen( self::METADATA_MARKER );
		$result     = $this->decode_data( $meta_start );
		$this->metadata = $result[0];

		if ( ! is_array( $this->metadata ) || ! isset( $this->metadata['record_size'] ) ) {
			throw new \RuntimeException( 'Invalid MMDB metadata.' );
		}

		$this->record_size      = (int) $this->metadata['record_size'];
		$this->node_count       = (int) $this->metadata['node_count'];
		$this->ip_version       = (int) $this->metadata['ip_version'];
		$this->node_byte_size   = (int) ( $this->record_size / 4 );
		$this->search_tree_size = $this->node_count * $this->node_byte_size;
		$this->data_start       = $this->search_tree_size + 16; // 16-byte data separator.
	}

	/**
	 * Read a node value from the binary search tree.
	 *
	 * @param int $node_number The node index.
	 * @param int $direction   0 for left, 1 for right.
	 * @return int The value of the record.
	 */
	private function read_node( int $node_number, int $direction ): int {
		$offset = $node_number * $this->node_byte_size;

		switch ( $this->record_size ) {
			case 24:
				if ( 0 === $direction ) {
					$bytes = substr( $this->file_content, $offset, 3 );
					return $this->bytes_to_int( $bytes );
				}
				$bytes = substr( $this->file_content, $offset + 3, 3 );
				return $this->bytes_to_int( $bytes );

			case 28:
				if ( 0 === $direction ) {
					$bytes  = substr( $this->file_content, $offset, 3 );
					$middle = ord( $this->file_content[ $offset + 3 ] );
					return ( ( $middle >> 4 ) << 24 ) | $this->bytes_to_int( $bytes );
				}
				$bytes  = substr( $this->file_content, $offset + 4, 3 );
				$middle = ord( $this->file_content[ $offset + 3 ] );
				return ( ( $middle & 0x0F ) << 24 ) | $this->bytes_to_int( $bytes );

			case 32:
				if ( 0 === $direction ) {
					$bytes = substr( $this->file_content, $offset, 4 );
					return $this->bytes_to_int( $bytes );
				}
				$bytes = substr( $this->file_content, $offset + 4, 4 );
				return $this->bytes_to_int( $bytes );

			default:
				throw new \RuntimeException( "Unsupported record size: {$this->record_size}" );
		}
	}

	/**
	 * Decode a data value at the given byte offset.
	 *
	 * @param int $offset Byte offset in the file.
	 * @return array [decoded_value, new_offset_after_value]
	 */
	private function decode_data( int $offset ): array {
		$ctrl_byte = ord( $this->file_content[ $offset ] );
		$type      = $ctrl_byte >> 5;
		$offset++;

		// Extended type.
		if ( 0 === $type ) {
			$type = ord( $this->file_content[ $offset ] ) + 7;
			$offset++;
		}

		// Pointer.
		if ( self::TYPE_POINTER === $type ) {
			return $this->decode_pointer( $ctrl_byte, $offset );
		}

		// Determine size of the data payload.
		$size = $ctrl_byte & 0x1F;
		if ( $size >= 29 ) {
			$bytes_to_read = $size - 28; // 1, 2, or 3 bytes.
			$size_bytes    = substr( $this->file_content, $offset, $bytes_to_read );
			$offset       += $bytes_to_read;
			$add_val       = $this->bytes_to_int( $size_bytes );

			switch ( $bytes_to_read ) {
				case 1:
					$size = 29 + $add_val;
					break;
				case 2:
					$size = 285 + $add_val;
					break;
				case 3:
					$size = 65821 + $add_val;
					break;
			}
		}

		return $this->decode_by_type( $type, $offset, $size );
	}

	/**
	 * Decode a value based on its type.
	 */
	private function decode_by_type( int $type, int $offset, int $size ): array {
		switch ( $type ) {
			case self::TYPE_MAP:
				return $this->decode_map( $offset, $size );

			case self::TYPE_ARRAY:
				return $this->decode_array( $offset, $size );

			case self::TYPE_UTF8:
				$value = substr( $this->file_content, $offset, $size );
				return array( $value, $offset + $size );

			case self::TYPE_BYTES:
				$value = substr( $this->file_content, $offset, $size );
				return array( $value, $offset + $size );

			case self::TYPE_DOUBLE:
				$bytes = substr( $this->file_content, $offset, 8 );
				$value = unpack( 'E', $bytes )[1]; // Big-endian double.
				return array( $value, $offset + 8 );

			case self::TYPE_FLOAT:
				$bytes = substr( $this->file_content, $offset, 4 );
				$value = unpack( 'G', $bytes )[1]; // Big-endian float.
				return array( $value, $offset + 4 );

			case self::TYPE_UINT16:
			case self::TYPE_UINT32:
			case self::TYPE_INT32:
				$bytes = substr( $this->file_content, $offset, $size );
				$value = 0 === $size ? 0 : $this->bytes_to_int( $bytes );
				if ( self::TYPE_INT32 === $type && $size > 0 ) {
					// Interpret as signed.
					if ( $value >= ( 1 << ( $size * 8 - 1 ) ) ) {
						$value -= ( 1 << ( $size * 8 ) );
					}
				}
				return array( $value, $offset + $size );

			case self::TYPE_UINT64:
			case self::TYPE_UINT128:
				// Return as string to avoid overflow.
				$bytes = substr( $this->file_content, $offset, $size );
				$value = 0 === $size ? '0' : $this->bytes_to_string_int( $bytes );
				return array( $value, $offset + $size );

			case self::TYPE_BOOLEAN:
				return array( 0 !== $size, $offset );

			case self::TYPE_END:
				return array( null, $offset );

			default:
				// Unknown/container type, skip.
				return array( null, $offset + $size );
		}
	}

	/**
	 * Decode a map (key-value pairs).
	 */
	private function decode_map( int $offset, int $size ): array {
		$map = array();
		for ( $i = 0; $i < $size; $i++ ) {
			list( $key, $offset )   = $this->decode_data( $offset );
			list( $value, $offset ) = $this->decode_data( $offset );
			$map[ $key ] = $value;
		}
		return array( $map, $offset );
	}

	/**
	 * Decode an array.
	 */
	private function decode_array( int $offset, int $size ): array {
		$arr = array();
		for ( $i = 0; $i < $size; $i++ ) {
			list( $value, $offset ) = $this->decode_data( $offset );
			$arr[] = $value;
		}
		return array( $arr, $offset );
	}

	/**
	 * Decode a pointer and resolve the referenced data.
	 */
	private function decode_pointer( int $ctrl_byte, int $offset ): array {
		$pointer_size = ( ( $ctrl_byte >> 3 ) & 0x03 );
		$base         = $ctrl_byte & 0x07;

		switch ( $pointer_size ) {
			case 0:
				$pointer_offset = ( $base << 8 ) | ord( $this->file_content[ $offset ] );
				$new_offset     = $offset + 1;
				break;
			case 1:
				$pointer_offset = ( $base << 16 )
					| ( ord( $this->file_content[ $offset ] ) << 8 )
					| ord( $this->file_content[ $offset + 1 ] );
				$pointer_offset += 2048;
				$new_offset      = $offset + 2;
				break;
			case 2:
				$pointer_offset = ( $base << 24 )
					| ( ord( $this->file_content[ $offset ] ) << 16 )
					| ( ord( $this->file_content[ $offset + 1 ] ) << 8 )
					| ord( $this->file_content[ $offset + 2 ] );
				$pointer_offset += 526336;
				$new_offset      = $offset + 3;
				break;
			case 3:
				$pointer_offset = $this->bytes_to_int( substr( $this->file_content, $offset, 4 ) );
				$new_offset     = $offset + 4;
				break;
			default:
				throw new \RuntimeException( 'Invalid pointer size.' );
		}

		// Resolve the pointer — read the data at the pointed-to location.
		$result = $this->decode_data( $this->data_start + $pointer_offset );

		// Return the decoded value but advance past the pointer bytes in the original stream.
		return array( $result[0], $new_offset );
	}

	/**
	 * Convert a big-endian byte string to integer.
	 */
	private function bytes_to_int( string $bytes ): int {
		$len = strlen( $bytes );
		$val = 0;
		for ( $i = 0; $i < $len; $i++ ) {
			$val = ( $val << 8 ) | ord( $bytes[ $i ] );
		}
		return $val;
	}

	/**
	 * Convert a big-endian byte string to a string representation of a large integer.
	 * Used for uint64 and uint128 to avoid PHP integer overflow.
	 */
	private function bytes_to_string_int( string $bytes ): string {
		$len = strlen( $bytes );
		// For values that fit in PHP int (8 bytes on 64-bit).
		if ( $len <= 8 && PHP_INT_SIZE >= 8 ) {
			return (string) $this->bytes_to_int( $bytes );
		}

		// Manual base-10 conversion for large integers.
		$result = '0';
		for ( $i = 0; $i < $len; $i++ ) {
			$result = bcadd( bcmul( $result, '256' ), (string) ord( $bytes[ $i ] ) );
		}
		return $result;
	}
}
