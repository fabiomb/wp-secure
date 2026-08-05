<?php
/**
 * Tests unitarios para WPS_Event_Types.
 */
class Test_WPS_Event_Types extends \PHPUnit\Framework\TestCase {

	/**
	 * Constantes que son tipos de evento, excluyendo las de severidad.
	 *
	 * @return string[]
	 */
	private function event_type_constants(): array {
		$constants = ( new \ReflectionClass( 'WPS_Event_Types' ) )->getConstants();

		return array_values( array_filter(
			$constants,
			function ( $value, $name ) {
				return 0 !== strpos( $name, 'SEVERITY_' );
			},
			ARRAY_FILTER_USE_BOTH
		) );
	}

	public function test_all_returns_every_event_type(): void {
		$this->assertEqualsCanonicalizing(
			$this->event_type_constants(),
			WPS_Event_Types::all(),
			'Un tipo de evento fuera de all() no se puede filtrar en el visor.'
		);
	}

	public function test_all_excludes_severity_constants(): void {
		foreach ( array( 'info', 'warning', 'critical' ) as $severity ) {
			$this->assertNotContains( $severity, WPS_Event_Types::all() );
		}
	}

	public function test_every_event_type_has_a_readable_label(): void {
		foreach ( WPS_Event_Types::all() as $type ) {
			$this->assertNotEquals(
				$type,
				WPS_Event_Types::label( $type ),
				"El tipo '{$type}' no tiene etiqueta legible y se muestra crudo en la interfaz."
			);
		}
	}

	public function test_every_event_type_has_a_severity(): void {
		$valid = array(
			WPS_Event_Types::SEVERITY_INFO,
			WPS_Event_Types::SEVERITY_WARNING,
			WPS_Event_Types::SEVERITY_CRITICAL,
		);

		foreach ( WPS_Event_Types::all() as $type ) {
			$this->assertContains( WPS_Event_Types::default_severity( $type ), $valid );
		}
	}
}
