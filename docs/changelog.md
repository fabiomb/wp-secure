# Registro de Cambios

## [0.2.8] — 2026-05-05

### Corrección: Administradores logueados podían ser bloqueados por el firewall

Los detectores de inyección SQL, XSS, Path Traversal y Scanner excluían el análisis únicamente cuando el administrador estaba en el área `/wp-admin`, pero no cuando navegaba por el frontend. Esto provocaba que peticiones legítimas del admin (editores de bloques, previsualizaciones, REST API de WooCommerce, etc.) pudieran activar detecciones falsas y generar bloqueos temporales o permanentes.

- **`WPS_Sqli_Detector::check_request()`**, **`WPS_Xss_Detector::check_request()`**, **`WPS_Path_Traversal_Detector::check_request()`**, **`WPS_Scanner_Detector::check_request()`**: eliminada la condición `is_admin() &&` del guard inicial; ahora se omite el análisis para cualquier usuario con capacidad `manage_options`, independientemente de la página visitada.
- **`WPS_Loader::init_rate_limiting()`** (`init` hook): eliminada la condición `is_admin() &&` del guard; el rate limiting de páginas y total ya no contabiliza peticiones de administradores logueados en ninguna parte del sitio.
- **`WPS_Loader::init_rate_limiting()`** (`template_redirect` hook): añadido guard `current_user_can('manage_options')` para que los errores 404 que genere un administrador tampoco cuenten hacia el rate limit.
- **`WPS_Loader::check_custom_rules()`**: añadido guard `current_user_can('manage_options')` para que las reglas personalizadas no se evalúen contra administradores logueados.
- **`WPS_Firewall_MuPlugin::firewall_check()`** (Capa 1, MU-plugin): añadida detección de cookie `wordpress_logged_in_` antes del bloque de rate limiting. Como en `muplugins_loaded` la autenticación de WordPress aún no está disponible, se usa la presencia de dicha cookie como señal de sesión activa para omitir el conteo de hits.

### Confirmado: Reglas ya no se aplican a IPs en la whitelist

Se verificó que tanto `WPS_Loader::check_custom_rules()` como `WPS_Loader::check_current_ip()` y `WPS_Firewall_MuPlugin::firewall_check()` comprueban la whitelist antes de cualquier evaluación. El comportamiento era correcto; se documenta explícitamente para claridad.

---

## [0.2.7] — 2026-04-25

### Corrección: Editar regla personalizada no guardaba los cambios
El formulario de edición de reglas en la pantalla **WP Seguro → Reglas** hacía `POST` a la misma URL que incluía `?wps_action=edit&rule_id=X` como parámetros GET. En `handle_actions()`, el bloque que procesa `wps_action=edit` por GET se ejecutaba antes que el bloque POST, por lo que al pulsar "Guardar Cambios" el código recargaba el formulario de edición en lugar de persistir los datos.

- **`WPS_Admin_Custom_Rules::render_rule_form()`**: añadido atributo `action` explícito en el formulario apuntando a la URL limpia de la página (`admin.php?page=wp-secure-rules`), eliminando los parámetros GET que interferían con el POST.

### Corrección: Bloquear IP desde eventos perdía la página y los filtros activos
Al pulsar el botón de bloqueo manual de una IP en la pantalla **WP Seguro → Eventos**, el redirect posterior siempre devolvía al usuario a la primera página de eventos sin filtros, aunque estuviera en una página intermedia con filtros de severidad, tipo o IP aplicados.

- **`WPS_Admin_Events::handle_block_from_events()`**: el `wp_safe_redirect` ahora conserva los parámetros `paged`, `severity`, `event_type` e `ip` del request original, devolviendo al usuario exactamente a la misma página y filtros que tenía activos antes del bloqueo.


## [0.2.6] — 2026-04-19

Indicadores de IP previamente bloqueados en pantalla de eventos

## [0.2.5] — 2026-04-10

### Corrección: Falsos positivos con peticiones WooCommerce AJAX
Las peticiones con parámetro `?wc-ajax=` (como `get_refreshed_fragments`) eran clasificadas como tipo `page` en lugar de `ajax`, lo que provocaba que contaran hacia los límites de rate limiting de páginas y generaran bloqueos falsos en sitios con WooCommerce.

- **`WPS_Request::classify_visitor_type()`**: ahora detecta el parámetro `wc-ajax` en la query string y clasifica estas peticiones como tipo `ajax`, evitando que cuenten como páginas en el rate limiter.

### Corrección: Falso positivo con /.well-known/security.txt
El acceso a `/.well-known/security.txt` (RFC 9116) era detectado erróneamente por el Scanner Detector como ruta de escaneo sospechosa, bloqueando un recurso estándar y legítimo.

- **`WPS_Scanner_Detector::$scanner_paths`**: eliminado el patrón que coincidía con `/.well-known/security.txt` de la lista de rutas de scanner.

### Nuevo: Configuración individual de detectores
Nuevo panel de configuración que permite activar o desactivar individualmente cada detector del firewall. Todos los detectores vienen activados por defecto.

- **Nueva sección "Detectores"** en la página de Configuración con checkboxes para: Login (Fuerza Bruta), XML-RPC, SQL Injection, XSS, Path Traversal, Scanner y REST API.
- **`WPS_Loader::init_detectors()`**: cada detector consulta su setting (`detector_*_enabled`) antes de inicializarse. Si está desactivado, no se registran sus hooks y no analiza peticiones.
- Útil para evitar falsos positivos o limitar el alcance del firewall en entornos específicos.

### Interno
- Versión actualizada a `0.2.5` en cabecera del plugin, constante `WPS_VERSION` y MU-plugin.

## [0.2.4] — 2026-04-09

### Corrección: Fallback de API a base de datos local cuando la API no devuelve resultados
Cuando el modo de resolución IP estaba configurado como "API" y la API de ipinfo.io alcanzaba su límite diario (o devolvía respuestas vacías), el plugin no consultaba la base de datos local MMDB aunque estuviera disponible. Esto provocaba que IPs legítimas (como las de Facebook) fueran identificadas erróneamente como crawlers falsificados (`auto_crawler_spoof`) al no poder resolver su ASN.

- **`WPS_Ipdb_Manager::lookup()`**: cuando el modo es `api` y la respuesta no contiene país ni ASN, ahora se intenta automáticamente una búsqueda en la base de datos local MMDB si el archivo está disponible. Esto complementa el fallback inverso (local→API) que ya existía.

### Corrección: Deprecation warnings en PHP 8.1+ por parámetros null
`add_submenu_page()` de WordPress usa internamente `str_replace()` y `strpos()` sobre el slug del menú padre. Pasar `null` como primer argumento (para páginas ocultas) genera warnings de deprecación en PHP 8.1+.

- **`WPS_Admin::register_menu()`**: cambiado el primer argumento de `add_submenu_page()` de `null` a `''` (string vacío) para la página del Wizard, eliminando los warnings de `str_replace()` y `strpos()` con parámetro null.

### Interno
- Versión actualizada a `0.2.4` en cabecera del plugin, constante `WPS_VERSION` y MU-plugin.

## [0.2.3] — 2026-04-06

### Corrección: IP con puerto rompe funcionamiento general del plugin
Ciertos servidores informan `REMOTE_ADDR` con el número de puerto incluido (ej: `69.171.230.40:53776`). Esto provocaba que un mismo visitante con distintos puertos fuera tratado como IPs diferentes, rompiendo filtros, estadísticas, bloqueos, whitelist y todas las funcionalidades que dependen de la identidad IP.

- **Nuevo método `WPS_Ip_Utils::sanitize_ip()`**: combina `strip_port()` + validación en una sola llamada. Devuelve la IP limpia o `null` si no es válida.
- **Corregido `WPS_Request::resolve_ip()`**: el path de fallback (cuando `WPS_Proxy_Config` no está disponible) ahora aplica `sanitize_ip()` a los headers de proxy y `strip_port()` al `REMOTE_ADDR` final. Este era el punto de entrada principal del bug.
- **Corregido `WPS_Proxy_Config::get_real_ip()`**: ya aplicaba `strip_port()` desde v0.2.2 (parcial).
- **Corregido `WPS_Proxy_Config::extract_ip()`**: ya aplicaba `strip_port()` desde v0.2.2 (parcial).
- **Corregida Capa 0 (`wps-firewall-prepend.php`)**: ya aplicaba strip inline desde v0.2.2 (parcial).
- **Corregidos todos los puntos de entrada de IP en admin**:
  - `WPS_Admin_Ajax::ajax_block_ip()` — bloqueo manual vía AJAX.
  - `WPS_Admin_Ajax::ajax_whitelist_add()` — agregar a whitelist vía AJAX.
  - `WPS_Admin_Ajax::ajax_geo_lookup()` — lookup de geolocalización vía AJAX.
  - `WPS_Admin_Events::render()` — filtro de IP en visor de eventos.
  - `WPS_Admin_Events::handle_block_from_events()` — bloqueo rápido desde eventos.
  - `WPS_Admin_Live_Traffic::render()` — filtro de IP en tráfico en vivo.
  - `WPS_Admin_Blocks::handle_actions()` — formulario de bloqueo manual.
  - `WPS_Admin_Whitelist` — formulario de agregar a whitelist.

### Interno
- Versión actualizada a `0.2.3` en cabecera del plugin, constante `WPS_VERSION` y MU-plugin.
- Nuevos tests unitarios para `sanitize_ip()` en `test-wps-ip-utils.php`.

## [0.2.2] — 2026-04-05

### Nuevo: Modo Inseguro (Learning Mode)
- Botón de un click en el Dashboard → tarjeta "Estado del Sistema" para activar/desactivar el Modo Inseguro.
- Cuando está activo, el firewall **detecta y registra** todos los eventos normalmente pero **no bloquea** ninguna petición (no envía respuesta 403/503 ni hace `exit()`). Útil para auditorías, pruebas de rendimiento o depuración sin interrumpir el tráfico real.
- El estado se almacena en `wp_options` (`wps_unsafe_mode`) para acceso rápido sin consulta a la tabla de settings.
- Aviso de administrador permanente y visible en todas las páginas de WordPress cuando el modo está activo, con botón de desactivación directa.
- La activación/desactivación se registra en el log de eventos de seguridad.
- El estado del Modo Inseguro se muestra en la tarjeta "Estado del Sistema" del dashboard con badge diferenciado.

### Nuevo: Condición `login_username` en Reglas Personalizadas
- Nuevo campo disponible en el editor de reglas: **"Usuario de login (solo en intento de autenticación)"**.
- Permite definir reglas del tipo: `IF login_username equals admin THEN block_temporary 60 min`.
- Soporta todos los operadores existentes: `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`.
- Las reglas con este campo **solo se evalúan durante intentos de autenticación** (filtro `authenticate` de WordPress). En el ciclo normal de petición HTTP se omiten para evitar falsos positivos con operadores negativos como `not_equals`.
- Se muestra un aviso informativo en el formulario de reglas cuando se selecciona este campo.
- La acción se aplica directamente desde `WPS_Login_Detector` sin llamar a `send_block_response()`, devolviendo un `WP_Error` al formulario de login de WordPress.

### Interno
- Versión actualizada a `0.2.2` en cabecera del plugin y constante `WPS_VERSION`.
- Nuevo método público `WPS_Custom_Rules::apply_login_rule_action()` para ejecutar acciones de reglas durante el flujo de autenticación de WordPress.
- **Directorio de datos movido a `wp-content/wps-data/`**: el archivo `wps-blocked-ips.php` (Capa 0) y la base MMDB ahora se almacenan fuera del directorio del plugin, evitando que se pierdan al actualizar desde WordPress.
- **Firewall prepend actualizado**: nuevo método `resolve_data_dir()` que calcula la ruta a `wp-content/wps-data/` de forma autónoma, sin depender de constantes de WordPress (inexistentes en Capa 0).
- **Regeneración automática post-update**: hook `upgrader_process_complete` que regenera el archivo de Capa 0, protege el directorio y reinstala el MU-plugin después de cada actualización del plugin.
- **Botón "Sincronizar Capa 0"** en la página de Bloqueos (tab IPs): permite forzar manualmente la sincronización del archivo de IPs bloqueadas con la base de datos, sin esperar al cron horario. Nuevo endpoint AJAX `wps_sync_blocked_ips`.


## [0.2.1] — 2026-03-25

### Nuevas funcionalidades
- **Contador de bloqueos totales**: nueva tarjeta en el Dashboard que muestra el número total de bloqueos registrados (histórico completo), complementando las estadísticas de 24 horas existentes.
- **Exportar configuración JSON**: desde la página de Configuración se puede exportar toda la configuración del plugin (ajustes y reglas personalizadas) como archivo JSON descargable.
- **Importar configuración JSON**: permite restaurar una configuración previamente exportada subiendo el archivo JSON. Los ajustes se aplican y las reglas personalizadas se crean.
- **Limpiar bloqueos expirados**: nuevo botón "Limpiar Expirados" en la pantalla de Bloqueos (tab IPs) que desactiva todos los bloqueos temporales que ya expiraron, con un solo clic.
- **Bloquear ASN desde detalle de IP**: en la vista de detalle de IP (`admin.php?page=wp-secure-traffic&ip=`) se agrega un botón para bloquear el ASN del proveedor de esa IP, que redirige a la pestaña de ASN con los datos precargados.
- **Acción "Eximir de detección" en reglas personalizadas**: nueva acción `exempt` que permite crear reglas que eximan peticiones específicas de uno o más detectores del firewall (REST API, SQLi, XSS, Path Traversal, Scanner, Login, XML-RPC). Útil para evitar falsos positivos en endpoints legítimos.
  - Las reglas `exempt` se procesan antes que las demás reglas para registrar las eximiciones.
  - Cada detector verifica si hay una eximición activa antes de aplicar su detección.
  - Selector de detectores con checkboxes en el formulario de reglas.
  - Nueva columna `action_params` en la tabla `wps_custom_rules` para almacenar los parámetros de la acción.

### Mejoras
- El formulario de bloqueo de ASN acepta datos precargados vía parámetros URL (`prefill_asn`, `prefill_asn_name`).
- Los strings localizados del panel incluyen la cadena de confirmación de importación.

### Documentación
- Documentados todos los cambios de la versión 0.2.1 en el changelog.

## [0.2.0] — 2026-03-21

### Nuevas funcionalidades
- **Reglas personalizadas**: nuevo módulo que permite al administrador definir reglas manuales de detección con lógica condicional configurable. Las reglas siguen la estructura `IF (condición 1) AND/OR (condición 2) … THEN (acción)`.
  - **Condiciones soportadas**: URI, User-Agent, IP, método HTTP, query string, referer, host, país (ISO), tipo de visitante.
  - **Operadores**: contiene, no contiene, es igual, no es igual, empieza con, termina con, coincide con regex, está en rango CIDR.
  - **Acciones**: bloqueo permanente, bloqueo temporal (duración configurable), agregar a whitelist, solo registrar (log).
  - **Prioridad**: cada regla tiene un valor de prioridad que determina el orden de evaluación.
  - **Panel de administración**: nueva página **WP Seguro → Reglas** con interfaz para crear, editar, activar/desactivar y eliminar reglas. Formulario dinámico para agregar múltiples condiciones encadenadas.
  - **Contador de hits**: cada regla registra cuántas veces ha coincidido.
  - **Protección ReDoS**: las expresiones regulares se ejecutan con límite de backtracking para evitar denegación de servicio.
  - **Nuevo evento `custom_rule_matched`**: se registra en el log de eventos de seguridad cada vez que una regla personalizada coincide.
- **Nueva tabla de base de datos `wps_custom_rules`**: almacenamiento persistente de reglas personalizadas con soporte para condiciones JSON, prioridad, estado activo/inactivo y contador de hits.

### Documentación
- Nueva guía completa de [Reglas Personalizadas](custom-rules.md) con explicación de campos, operadores, acciones, ejemplos y consideraciones de seguridad.
- Regla R14 (Reglas Personalizadas) agregada a la [Referencia de Reglas](rules-reference.md).
- Índice de documentación actualizado en [README](README.md).

## [0.1.4] — 2026-03-20

### Nuevas funcionalidades
- **Enlace de detalle de IP en bloqueos**: las IPs en la lista de bloqueos activos ahora son enlaces clicables que llevan a la vista de detalle de IP (geolocalización, historial, tráfico), con botón de visualización rápida en la columna de acciones, consistente con las vistas de tráfico en vivo y eventos.
- **Gráfico de actividad en widget de escritorio**: el widget de WP Seguro en el dashboard de WordPress ahora incluye un gráfico de líneas con la actividad de peticiones y bloqueos de las últimas 24 horas, además de las estadísticas numéricas existentes.

### Correcciones
- **Notificaciones no se enviaban**: corregido un error crítico donde el módulo de notificaciones (`WPS_Admin_Notifier`) nunca recibía los eventos de cron (`wps_daily_maintenance`) porque su hook se registraba únicamente dentro del contexto de administración (`is_admin()`), pero WordPress cron se ejecuta fuera de dicho contexto. El registro del hook del notificador se movió al `WPS_Loader::init()` para que esté disponible siempre.
- **Auto-reparación de tareas cron**: se agregó verificación automática de que las tareas cron (`wps_daily_maintenance`, `wps_hourly_maintenance`) estén programadas en cada carga del plugin, evitando que se pierdan si WordPress las desregistra accidentalmente.
- **Logging de notificaciones**: se agregó registro en `error_log` para todas las operaciones de envío de email del notificador (éxito, error, configuración desactivada), facilitando el diagnóstico de problemas de entrega.

## [0.1.3] — 2026-03-16

### Nuevas funcionalidades
- **Página de bloqueo personalizada**: nueva opción para configurar una URL de destino a la que se redirige a los usuarios bloqueados, en lugar de mostrar solo un código de error con texto. Configurable en Respuesta de Bloqueo → URL de página de bloqueo.
- **Modo de bloqueo para eventos críticos**: nueva opción para elegir si las detecciones de ataques críticos (SQLi, XSS, Path Traversal, Scanner) generan un bloqueo temporal o permanente. Configurable en Firewall Avanzado → Bloqueo de eventos críticos.
- **Limpieza automática de bloqueos expirados**: el mantenimiento diario ahora elimina los registros de bloqueos temporales ya cumplidos según un período de retención configurable (por defecto 30 días). Configurable en Retención de Datos → Bloqueos expirados.

### Correcciones
- **Falsos positivos en URLs de taxonomías**: los detectores de seguridad (SQLi, XSS, Path Traversal, Scanner) ya no analizan la ruta URI de URLs de taxonomías de WordPress (tags, categorías, taxonomías personalizadas) que contienen slugs de contenido publicado. Esto evita bloqueos incorrectos cuando un visitante o bot de buscador accede a URLs como `/tag/administrador` o `/category/manager` que coinciden con patrones de seguridad. El análisis de query strings, POST y cookies se mantiene activo.

## [0.1.2] — 2026-03-14

### Mejoras
- Widget de seguridad en el dashboard principal de WordPress con estadísticas de peticiones, bloqueos, IPs únicas, eventos críticos y bloqueos activos.
- Botón "Permanente" en la pantalla de bloqueos para convertir bloqueos temporales en permanentes.
- Botón "Detalle IP" en la página de eventos para ver información completa de una IP (geolocalización, historial, tráfico).
- User-Agent: se muestra más contenido (80 caracteres) con botón expandir/colapsar para valores largos en tráfico en vivo y detalle de IP.

### Correcciones
- Filtros de tráfico en vivo: corregidos métodos faltantes `esc_like()` y `prepare()` en `WPS_Db` que impedían el funcionamiento de los filtros por tipo, método e IP.

## [0.1.0] — 2026-03-13

### Fase 1 — Base de Datos y Estructura
- Esquema de 9 tablas con prefijo `wps_`.
- Sistema de migraciones versionado.
- Mantenimiento automático (purga, optimización).
- Activador/desactivador del plugin.
- Autoloader propio por directorio.

### Fase 2 — Motor de Detección
- Clasificación de peticiones (login, REST, XML-RPC, admin, recurso, página).
- Motor de reglas con puntuación de riesgo acumulada.
- Detector de login (fuerza bruta) con bloqueo temporal.
- Detector de XML-RPC con opción de desactivación completa.
- Sistema de logging con 18+ tipos de evento.
- Bloqueador de IP (temporal y permanente).
- Whitelist con soporte para IP, CIDR, IPv6.
- Utilidades de IP: validación, conversión binaria, CIDR matching.

### Fase 3 — Geolocalización
- Integración con bases de datos MMDB (MaxMind GeoLite2/GeoIP2).
- Bloqueo por país con selector visual.
- Bloqueo por ASN (Autonomous System Number).
- Bloqueo por rango CIDR personalizado.
- Panel de selección de países y ASNs.

### Fase 4 — Firewall Avanzado
- Detector de inyección SQL (SQLi) con patrones avanzados.
- Detector de Cross-Site Scripting (XSS).
- Detector de Path Traversal.
- Detector de scanners y herramientas automatizadas.
- Rate limiter por IP configurable.
- Sistema de puntuación de riesgo con umbrales por nivel.
- Capa 0: Firewall PHP vía `auto_prepend_file`.
- Capa 1: MU-Plugin para interceptación temprana.

### Fase 5 — Experiencia de Usuario
- Visor de tráfico en vivo con actualización automática.
- Dashboard completo con gráficas de actividad.
- Vista de detalle de IP con historial de eventos.
- Asistente de configuración inicial (wizard).
- Notificaciones por email (alertas y resúmenes).
- Exportación de logs en formato CSV.
- Internacionalización español/inglés.

### Fase 6 — Optimización y Hardening
- Verificación de crawlers por DNS inverso (rDNS).
  - Soporte para Googlebot, Bingbot, YandexBot, Baiduspider, DuckDuckBot, Applebot, Facebookbot, LinkedInBot.
  - Cache de resultados con transients (24h).
  - Bloqueo automático de crawlers falsos (spoofing).
- Protección de REST API.
  - Bloqueo de acceso público con namespaces permitidos.
  - Bloqueo de enumeración de usuarios (`/wp/v2/users`, `?author=N`).
- Reglas de seguridad adicionales.
  - Headers de seguridad: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection.
  - Bloqueo de métodos HTTP peligrosos (TRACE, TRACK, DEBUG, CONNECT).
  - Bloqueo de User-Agent vacío (opcional).
  - Bloqueo de peticiones sin Host (opcional).
  - Ocultación de versión de WordPress.
- Compatibilidad con CDN/Proxy.
  - Soporte nativo para Cloudflare y Sucuri con verificación de rangos de IP.
  - Auto-detección de CDN.
  - Modo personalizado para otros proxies.
  - Resolución segura de IP real del visitante.
- Optimización de rendimiento.
  - Monitor de rendimiento con tiempos por componente.
  - Indicador en barra de admin (modo debug).
  - Logging de tiempos en error_log.
- Tests unitarios y de integración.
  - PHPUnit con soporte standalone y WP test framework.
  - Tests para IP utilities, crawler verifier, proxy config, security hardener, rules engine.
  - Tests de integración para blocker, detectores, REST API.
- Documentación completa para el usuario.
