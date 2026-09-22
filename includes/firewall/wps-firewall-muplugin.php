<?php
/**
 * Plugin Name: WP Seguro — Firewall (Capa 1)
 * Description: MU-Plugin del firewall WP Seguro. Se ejecuta antes de plugins y temas.
 * Version: 0.4.1
 * Author: WP Seguro
 *
 * Este archivo se instala automáticamente en wp-content/mu-plugins/.
 * Se ejecuta después del core de WordPress pero ANTES de plugins y themes,
 * permitiendo interceptar peticiones tempranamente con acceso a la DB.
 *
 * Flujo:
 * 1. Verificar que el plugin principal existe y está activo.
 * 2. Cargar las clases mínimas necesarias (autoloader del plugin).
 * 3. Clasificar la petición.
 * 4. Evaluar rate limiting.
 * 5. Ejecutar detección de patrones de ataque.
 * 6. Evaluar puntuación de riesgo.
 *
 * @package WP_Secure
 */

// Evitar acceso directo.
if ( ! defined( 'ABSPATH' ) ) {
	return;
}

// Evitar doble carga.
if ( defined( 'WPS_MUPLUGIN_LOADED' ) ) {
	return;
}
define( 'WPS_MUPLUGIN_LOADED', true );

/**
 * Clase contenedora del MU-Plugin firewall.
 */
final class WPS_Firewall_MuPlugin {

	/**
	 * Ruta al directorio del plugin principal.
	 *
	 * @var string
	 */
	private static $plugin_dir = '';

	/**
	 * Ejecutar el firewall MU-Plugin.
	 */
	public static function run(): void {
		// Determinar ruta al plugin principal.
		self::$plugin_dir = WP_PLUGIN_DIR . '/wp-secure';

		// Verificar que el plugin principal existe.
		if ( ! is_dir( self::$plugin_dir ) ) {
			return;
		}

		// Verificar que el bootstrap existe.
		$bootstrap = self::$plugin_dir . '/wp-secure.php';
		if ( ! is_file( $bootstrap ) ) {
			return;
		}

		// Hookear en muplugins_loaded para ejecutar lo antes posible.
		add_action( 'muplugins_loaded', array( __CLASS__, 'firewall_check' ), 0 );
	}

	/**
	 * Ejecutar las comprobaciones del firewall.
	 * Se ejecuta en muplugins_loaded, antes de plugins y themes.
	 */
	public static function firewall_check(): void {
		// Cargar el autoloader del plugin si no está cargado.
		if ( ! class_exists( 'WPS_Request', false ) ) {
			self::load_dependencies();
		}

		// Verificar que las clases necesarias existen.
		if ( ! class_exists( 'WPS_Request', false ) || ! class_exists( 'WPS_Blocker', false ) ) {
			return;
		}

		if ( ! class_exists( 'WPS_Loader', false ) ) {
			return;
		}

		$loader = WPS_Loader::get_instance();

		// Respetar el interruptor de Capa 1 de la configuración.
		if ( ! $loader->is_layer_enabled( 1 ) ) {
			return;
		}

		// Conectar el loader a la config de proxy antes de construir la
		// petición: WPS_Request resuelve la IP en su constructor y sin esto
		// el ajuste `proxy_mode` del sitio no se aplicaría en esta capa.
		if ( class_exists( 'WPS_Proxy_Config', false ) ) {
			WPS_Proxy_Config::get_instance()->set_loader( $loader );
		}

		// Clases esenciales para la evaluación.
		$request = WPS_Request::get_instance();
		$ip      = $request->ip();

		// Nada que hacer sin IP válida.
		if ( empty( $ip ) ) {
			return;
		}

		// Whitelist bypass.
		if ( class_exists( 'WPS_Whitelist', false ) && WPS_Whitelist::get_instance()->is_whitelisted( $ip ) ) {
			return;
		}

		// El propio servidor (wp-cron, loopbacks) nunca se bloquea, aunque una
		// versión anterior lo haya dejado en la lista de bloqueos.
		if ( WPS_Ip_Utils::is_server_ip( $ip ) ) {
			return;
		}

		// Verificar si ya está bloqueada.
		$blocker = WPS_Blocker::get_instance();
		if ( $blocker->is_blocked( $ip ) ) {
			$blocker->send_block_response( 'IP bloqueada' );
			return;
		}

		// En muplugins_loaded la autenticación de WP aún no está disponible.
		// Se detecta sesión activa mediante la cookie de WordPress como proxy.
		$has_wp_session = false;
		foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
			if ( 0 === strpos( $cookie_name, 'wordpress_logged_in_' ) ) {
				$has_wp_session = true;
				break;
			}
		}

		// wp-cron no se limita: lo dispara el propio sitio, no un visitante.
		$doing_cron = defined( 'DOING_CRON' ) && DOING_CRON;

		// Rate limiting para la petición actual (si el rate limiter está cargado y no hay sesión activa).
		// El loader vuelve a registrar estos hits en `init`; WPS_Rate_Limiter
		// cuenta cada tipo una sola vez por petición.
		if ( ! $has_wp_session && ! $doing_cron && class_exists( 'WPS_Rate_Limiter', false ) ) {
			$rate_limiter = WPS_Rate_Limiter::get_instance( $loader );
			$visitor_type = $request->visitor_type();

			// Registrar hit de tipo 'total'.
			$rate_limiter->record_hit( $ip, 'total' );

			// Registrar hit de tipo 'pages' si genera carga WordPress.
			if ( ! in_array( $visitor_type, array( 'static' ), true ) ) {
				$rate_limiter->record_hit( $ip, 'pages' );
			}
		}
	}

	/**
	 * Cargar las dependencias mínimas del plugin principal.
	 */
	private static function load_dependencies(): void {
		$includes = self::$plugin_dir . '/includes';

		// Definir constantes del plugin si no están definidas.
		if ( ! defined( 'WPS_PLUGIN_DIR' ) ) {
			define( 'WPS_PLUGIN_DIR', self::$plugin_dir . '/' );
		}
		if ( ! defined( 'WPS_INCLUDES_DIR' ) ) {
			define( 'WPS_INCLUDES_DIR', $includes . '/' );
		}
		if ( ! defined( 'WPS_DATA_DIR' ) ) {
			define( 'WPS_DATA_DIR', dirname( self::$plugin_dir, 2 ) . '/wps-data/' );
		}
		if ( ! defined( 'WPS_VERSION' ) ) {
			define( 'WPS_VERSION', '0.4.1' );
		}

		// Cargar clases en el orden necesario (sin autoloader para minimizar carga).
		$classes = array(
			'database/class-wps-db-schema.php',
			'database/class-wps-db.php',
			'logging/class-wps-event-types.php',
			'logging/class-wps-logger.php',
			'core/class-wps-ip-utils.php',
			'class-wps-loader.php',
			// Debe cargarse antes que WPS_Request: la petición resuelve la IP
			// del visitante en su constructor y delega esa decisión acá.
			'core/class-wps-proxy-config.php',
			'core/class-wps-request.php',
			'core/class-wps-whitelist.php',
			'core/class-wps-blocker.php',
			'core/class-wps-rate-limiter.php',
		);

		foreach ( $classes as $class_file ) {
			$file = $includes . '/' . $class_file;
			if ( is_file( $file ) ) {
				require_once $file;
			}
		}
	}
}

// Ejecutar inmediatamente.
WPS_Firewall_MuPlugin::run();
