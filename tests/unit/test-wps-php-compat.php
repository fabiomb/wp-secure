<?php
/**
 * Compatibilidad con versiones nuevas de PHP.
 *
 * Desde PHP 8.4, un parámetro tipado con `= null` sin `?` («nullable
 * implícito») emite un Deprecated en cada carga de la clase. Con PHP 8.2
 * no se ve, así que se revisa el código fuente.
 */
class Test_WPS_Php_Compat extends \PHPUnit\Framework\TestCase {

	public function test_no_implicitly_nullable_parameters(): void {
		$root  = str_replace( '\\', '/', dirname( __DIR__, 2 ) );
		$files = array_merge(
			array( $root . '/wp-secure.php', $root . '/uninstall.php' ),
			$this->php_files( $root . '/includes' )
		);

		$type  = '(?:array|string|int|float|bool|callable|iterable|object|self|[A-Za-z_\\\\][A-Za-z0-9_\\\\]*)';
		$param = '/(\??)(' . $type . ')\s+&?\s*(?:\.\.\.)?\$\w+\s*=\s*null\b/i';
		$found = array();

		foreach ( $files as $file ) {
			$src = (string) file_get_contents( $file );

			preg_match_all( '/function\s*&?\s*\w*\s*\(/i', $src, $functions, PREG_OFFSET_CAPTURE );
			foreach ( $functions[0] as $function ) {
				$params = $this->parameter_list( $src, $function[1] + strlen( $function[0] ) );

				preg_match_all( $param, $params, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE );
				foreach ( $matches as $match ) {
					$union = '|' === substr( rtrim( substr( $params, 0, $match[0][1] ) ), -1 );
					if ( '?' !== $match[1][0] && ! $union && 'mixed' !== strtolower( $match[2][0] ) ) {
						$found[] = str_replace( $root . '/', '', $file ) . ': ' . $match[0][0];
					}
				}
			}
		}

		$this->assertSame( array(), $found, 'Usar ?Tipo $param = null (Deprecated en PHP 8.4).' );
	}

	private function parameter_list( string $src, int $start ): string {
		$depth = 1;
		$i     = $start;
		$len   = strlen( $src );

		while ( $i < $len && $depth > 0 ) {
			$depth += '(' === $src[ $i ] ? 1 : ( ')' === $src[ $i ] ? -1 : 0 );
			$i++;
		}

		return substr( $src, $start, $i - $start - 1 );
	}

	/**
	 * @return string[]
	 */
	private function php_files( string $dir ): array {
		$files = array();
		foreach ( new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ) ) as $file ) {
			if ( 'php' === $file->getExtension() ) {
				$files[] = str_replace( '\\', '/', $file->getPathname() );
			}
		}
		return $files;
	}
}
