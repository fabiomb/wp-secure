# Registro de Cambios

## [0.2.11] — 2026-08-05

Revisión completa del código. Los cambios de seguridad de esta versión afectan cómo se determina la IP del visitante, así que conviene verificar en **WP Seguro → Tráfico en Vivo** que se registran IPs de visitantes reales y variadas antes de dar por buena la actualización en un sitio en producción.

### Seguridad: La IP de origen podía falsificarse con un header

Era posible tanto esquivar el firewall como provocar el bloqueo de un tercero: bastaba enviar `X-Forwarded-For` con la IP de una víctima junto a un patrón de ataque para que el plugin bloqueara esa IP. Se corrigieron cuatro causas independientes.

- **`WPS_Firewall_MuPlugin::load_dependencies()`**: ahora carga `core/class-wps-proxy-config.php`, y lo hace antes que `core/class-wps-request.php`. El MU-plugin carga sus clases a mano porque el autoloader del plugin todavía no está registrado en esa fase; al faltar `WPS_Proxy_Config`, el `class_exists()` de `WPS_Request::resolve_ip()` daba `false` y la resolución caía a un respaldo que leía los headers sin verificar el proxy. Como `WPS_Request` es singleton, la Capa 2 reutilizaba esa misma instancia y el ajuste `proxy_mode` del sitio no se aplicaba nunca.
- **`WPS_Firewall_MuPlugin::firewall_check()`**: inyecta el loader en `WPS_Proxy_Config` antes de construir la petición, para que la configuración de proxy del sitio rija también en la Capa 1.
- **`WPS_Proxy_Config::extract_ip()`**: nuevo parámetro `$from_closest_hop`. `X-Forwarded-For` se recorre ahora de derecha a izquierda. El proxy agrega la IP real de la conexión al final de la cadena, así que la primera IP pública —la que se tomaba antes— es justamente la que el cliente puede prefijar.
- **`WPS_Proxy_Config::extract_from_generic_headers()`**: `X-Forwarded-For` pasa a tener prioridad sobre `X-Real-IP`. Este último es trivial de falsificar si el proxy no lo sobrescribe, y no tiene cadena que permita descartar el valor inyectado por el cliente.
- **`WPS_Proxy_Config::get_real_ip()`**: en modo `auto`, consultar headers genéricos exige ahora que `REMOTE_ADDR` sea una IP privada **válida**. Antes bastaba con que `is_private_ip()` devolviera `true`, cosa que también ocurre con valores ausentes o malformados.
- **`WPS_Proxy_Config::extract_from_configured_header()`**: el modo `custom` aplica el mismo criterio de salto más cercano cuando el header configurado es `X-Forwarded-For`.
- **`WPS_Request::resolve_ip()`**: eliminado el respaldo que leía `CF-Connecting-IP`, `X-Real-IP` y `X-Forwarded-For` por su cuenta. La resolución pasa siempre por `WPS_Proxy_Config`; sin él, sólo se confía en la conexión real.

### Seguridad: Faltaban los rangos IPv6 de Cloudflare

`WPS_Proxy_Config::$cdn_ranges` no incluía ningún rango IPv6. En un origen con registro AAAA, Cloudflare conecta por IPv6, `detect_cdn()` no reconocía la petición como del CDN y `get_real_ip()` devolvía la IP del edge en lugar de la del visitante. El efecto es que todo el tráfico del sitio colapsa en un puñado de direcciones, el rate limiter las bloquea y el sitio queda fuera de servicio.

- **`WPS_Proxy_Config::$cdn_ranges`**: añadidos los siete rangos IPv6 oficiales de Cloudflare (`2400:cb00::/32`, `2606:4700::/32`, `2803:f800::/32`, `2405:b500::/32`, `2405:8100::/32`, `2a06:98c0::/29`, `2c0f:f248::/32`).

### Seguridad: El formulario de login revelaba si una cuenta existía

Un intento con un usuario inexistente devolvía un mensaje propio, distinto del error habitual de WordPress. Eso convierte al login en un oráculo: probando nombres y observando cuál responde distinto se enumeran las cuentas válidas del sitio. Además, el bloqueo se aplicaba al primer intento, de modo que equivocarse de usuario una vez alcanzaba para quedar bloqueado.

- **`WPS_Login_Detector::denied_message()`** (nuevo): mensaje único para todas las rutas de rechazo.
- **`WPS_Login_Detector::should_block_unknown_user()`** (nuevo) y **`count_recent_unknown_user_attempts()`** (nuevo): el bloqueo por usuario inexistente exige superar un umbral de intentos en la última hora. Por debajo del umbral la petición sigue el flujo normal de WordPress, que responde igual que ante una contraseña incorrecta.
- **Nuevo ajuste `login_unknown_user_threshold`** (por defecto `3`, `0` desactiva este bloqueo), en Configuración → Login.

### Corrección: Texto legítimo se detectaba como ataque

Los detectores bloquean la IP de origen, y con `critical_block_mode` en `permanent` lo hacen para siempre. Varios patrones coincidían con prosa común, de modo que escribir un comentario sobre programación bastaba para quedar bloqueado en el propio sitio.

- **`WPS_Xss_Detector::$patterns`**: eliminados los patrones de `Function(`, `eval(`, `atob(`, `innerHTML=`, `window.*` y `document.write`, que coinciden con cualquier texto que hable de JavaScript. Los manejadores `on*=` exigen ahora estar dentro de una etiqueta, para no marcar frases como «el evento onchange = no se dispara». Los protocolos `javascript:` y `vbscript:` exigen que el payload siga pegado a los dos puntos, ya que en prosa siempre hay un espacio («JavaScript: The Good Parts»). La lista de etiquetas se reduce a `iframe`, `object`, `embed` y `applet`: `form`, `input`, `button`, `textarea` y `select` aparecen constantemente en texto normal. Se conserva `document.cookie`, que es el objetivo real de la exfiltración.
- **`WPS_Sqli_Detector::$patterns`**: eliminados `CHAR`, `CHR`, `CONCAT` y `GROUP_CONCAT` de la lista de funciones. `INSERT INTO`, `DELETE FROM`, `UPDATE … SET` y `DROP TABLE` ya no cuentan sueltos: exigen aparecer tras cerrar el valor original, que es lo que distingue una *stacked query* de una frase que menciona SQL. `INFORMATION_SCHEMA` exige la referencia a la tabla. Las tautologías exigen un delimitador previo, para no marcar «llevás 1 y 1 = 2 productos».
- **`WPS_Request::is_trusted_user()`** (nuevo): los detectores de SQLi, XSS, Path Traversal y Scanner eximen ahora a cualquier usuario con capacidad `edit_posts`, no sólo a `manage_options`. Quien publica contenido manipula código como parte de su trabajo, y bloquearle la IP le rompe el sitio que edita.
- **`WPS_Sqli_Detector::detect()`** y **`WPS_Xss_Detector::detect()`** (nuevos): exponen el análisis de un valor suelto, lo que permite cubrir los patrones con tests.

### Corrección: Peticiones REST sin permalinks quedaban mal clasificadas

- **`WPS_Request::classify_visitor_type()`**: buscaba `?rest_route=` dentro del path ya procesado por `wp_parse_url(PHP_URL_PATH)`, que nunca contiene el query string, de modo que la condición no se cumplía jamás. Estas peticiones se clasificaban como `page` y el hardener les bloqueaba `PUT`, `DELETE` y `PATCH`. Ahora se busca sobre la URI completa.

### Rendimiento: Consultas repetidas en cada petición

- **`WPS_Whitelist::is_whitelisted()`**: ejecutaba dos consultas por llamada, y se invoca una decena de veces por petición (loader, cada detector, hardener, rate limiter). La propiedad de cache existía y se invalidaba, pero nunca se leía. Ahora la whitelist se carga entera una vez por petición y las coincidencias se resuelven en memoria. Medido: 8 consultas para 4 comprobaciones, ahora 1.
- **`WPS_Whitelist::matches_entries()`** (nuevo): lógica de coincidencia extraída, sin dependencia de la base de datos.
- **`WPS_Db_Schema::tables_exist()`**: preguntaba tabla por tabla con `SHOW TABLES`, diez consultas en cada carga desde `WPS_Loader::load_settings()`. Ahora resuelve con una sola consulta y memoriza el resultado.
- **`WPS_Db_Schema::table_names()`** (nuevo): lista canónica de tablas, que estaba duplicada entre `drop_tables()` y `tables_exist()`. **`flush_table_cache()`** (nuevo) invalida el resultado memorizado tras crear o eliminar tablas.
- **`WPS_Rate_Limiter::increment()`**: hacía `INSERT` más `SELECT` para recuperar el contador, y se ejecuta dos veces por visita (`total` y `pages`). Ahora recupera el valor en la misma consulta con `LAST_INSERT_ID(request_count + 1)`, distinguiendo alta de actualización por las filas afectadas que devuelve MySQL.

### Corrección: Ajustes que se guardaban pero no controlaban nada

Tres casillas de Configuración se persistían y se mostraban marcadas sin tener efecto alguno sobre el comportamiento del plugin.

- **`WPS_Loader::should_log_traffic()`** (nuevo): `exclude_static_from_log` decide ahora si los recursos estáticos llegan al log de tráfico.
- **`WPS_Loader::is_layer_enabled()`** (nuevo): `firewall_layer1_enabled` apaga realmente el MU-plugin, verificado en `WPS_Firewall_MuPlugin::firewall_check()`. `firewall_layer0_enabled` controla el mantenimiento del archivo de bloqueos en `WPS_Activator::sync_blocked_ips_file()`.
- **`WPS_Db_Migrations::adopt_existing_layer0()`** (nuevo): como el archivo de Capa 0 se escribía siempre, un sitio con la capa configurada en `.htaccess` perdería protección al actualizar. La migración da el ajuste por activado cuando el archivo de datos ya existe.

### Corrección: Log de tráfico sin código de respuesta ni tiempo real

- **`WPS_Loader::log_current_request()`** (nuevo): el registro de tráfico se difiere al `shutdown`. Al hacerse en `plugins_loaded`, `response_time_ms` medía siempre cerca de cero y `http_status` nunca se llenaba, aunque la interfaz mostrara ambas columnas.

### Corrección: Visor de eventos

- **`WPS_Admin_Events::handle_block_from_events()`**: se ejecutaba al final del render, con el HTML ya emitido, de modo que el `wp_safe_redirect()` posterior fallaba con las cabeceras enviadas y la tabla seguía mostrando el estado previo al bloqueo. Pasa a ejecutarse en `admin_init`, e incorpora la verificación de capacidad que antes cubría únicamente el registro del menú.
- **`WPS_Event_Types::all()`** (nuevo): el filtro de tipos listaba ocho de veintisiete, así que no se podía filtrar por scanner, SQLi, XSS ni reglas personalizadas. La lista se deriva ahora por reflexión de las constantes de la clase.
- **`WPS_Admin_Events::render_pagination()`**: imprimía un botón por página. Con decenas de miles de eventos eso son cientos de enlaces; ahora muestra una ventana alrededor de la página actual.
- **`WPS_Admin_Events::get_events()`**: nuevo filtro por URI, que enlaza la vista de patrones con los eventos concretos que la componen.

### Nuevo: Motor de puntuación de riesgo

`WPS_Rules_Engine` no se instanciaba en ninguna parte fuera de los tests. La tabla de puntajes y los umbrales 31/51/81/100 documentados como el núcleo del plugin eran código muerto, igual que el ajuste `risky_countries`, que sólo esa clase consultaba.

- **Nuevo ajuste `risk_engine_mode`**, en Configuración → Firewall Avanzado, con tres valores:
  - `off` (por defecto): no evalúa nada. Reproduce exactamente el comportamiento y el costo de versiones anteriores.
  - `shadow`: puntúa cada petición y registra el evento con el puntaje y los factores que lo formaron, sin bloquear nunca.
  - `enforce`: aplica la acción correspondiente al puntaje.
- El motor viene apagado a propósito. Los puntajes por defecto nunca corrieron contra tráfico real, así que activarlos de golpe empezaría a bloquear visitantes con umbrales que nadie calibró. El camino previsto es encender `shadow`, observar unos días qué puntajes saca el tráfico legítimo del sitio y con qué factores, y recién entonces pasar a `enforce`.
- **`WPS_Rules_Engine::assess()`** (nuevo): devuelve puntaje, factores y acción. `evaluate()` delega en él y mantiene su firma.
- **`WPS_Rules_Engine::mode()`**, **`is_enabled()`**, **`is_enforcing()`**, **`action_for_score()`** (nuevos).
- **`WPS_Rules_Engine::get_instance()`**: ya no falla cuando se lo llama sin loader.
- **`WPS_Loader::init_risk_engine()`** (nuevo): engancha el motor en `init` con prioridad 3, después de los detectores. Si está apagado no registra el hook.
- **`WPS_Loader::build_risk_context()`** y **`resolve_country()`** (nuevos): contexto geográfico compartido. `check_custom_rules()` los reutiliza en lugar de duplicar la resolución.

### Nuevo: Patrones recurrentes y creación de reglas desde un evento

Ver un barrido de bots en el log y actuar sobre él eran dos tareas desconectadas: había que bloquear IP por IP a mano, o escribir la regla desde cero en otra pantalla sin ningún dato del evento delante.

- **Nueva pantalla WP Seguro → Patrones** (`WPS_Admin_Patterns`): agrupa los eventos de seguridad por ruta y muestra intentos, IPs distintas y última aparición, con filtros de período y mínimo de intentos. Una ruta con diez o más IPs distintas se marca como barrido automatizado.
- **`WPS_Custom_Rules::suggest_condition_from_uri()`** y **`suggest_condition_from_user_agent()`** (nuevos): derivan una condición a partir de un evento. Devuelven `null` cuando el valor es demasiado genérico —la raíz, algo vacío, menos de tres caracteres—, porque una regla «uri contiene /» con acción de bloqueo deja el sitio fuera de servicio.
- **`WPS_Custom_Rules::path_is_covered()`** (nuevo): marca los patrones que ya tienen una regla actuando sobre ellos, para no revisar dos veces lo mismo. Las reglas `exempt` y `log_only` no cuentan como cobertura, porque no bloquean.
- **`WPS_Admin_Custom_Rules::prefilled_rule_from_request()`** (nuevo): el botón «Crear regla», disponible en la pantalla de Patrones y en cada fila del visor de eventos, abre el formulario precargado con la condición derivada. No crea nada por su cuenta: la sugerencia automática puede resultar demasiado amplia, así que la decisión final queda en manos del administrador.
- **`WPS_Admin_Custom_Rules::render_rule_form()`**: el modo edición se determina por la presencia de un id, de modo que una regla precargada sin id se trata como alta.

### Interno

- Suite de tests ampliada de 52 a 190 casos. Se corrigen además dos tests que ya fallaban: uno por falta de un stub y otro que afirmaba que `WPS_Rules_Engine` tenía constantes cuando no tiene ninguna, reemplazado por 21 tests de comportamiento.
- **`tests/bootstrap.php`**: stubs de `wp_parse_url`, `current_user_can`, `is_user_logged_in` y transients, constantes `ARRAY_A`, `OBJECT`, `DAY_IN_SECONDS` y `HOUR_IN_SECONDS`, y un doble de `$wpdb` que registra las consultas ejecutadas. Esto permite verificar el costo de acceso a base de datos como comportamiento medible y no como estimación.
- Versión actualizada a `0.2.11` en cabecera del plugin, constante `WPS_VERSION` y MU-plugin, cuyo respaldo de versión había quedado desincronizado en `0.2.7`.

## [0.2.10] — 2026-06-12

### Corrección: Falso positivo de spoofing de Facebook/Twitter en navegadores reales

Algunos navegadores reales (p. ej. webviews in-app de iOS/Safari) anexan tokens de bots de previsualización social al final de un User-Agent de navegador completo, como `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_1) AppleWebKit/601.2.4 (KHTML, like Gecko) Version/9.0.1 Safari/601.2.4 facebookexternalhit/1.1 Facebot Twitterbot/1.0`. El verificador de crawlers identificaba estos UAs como `facebookbot`, la verificación rDNS fallaba (porque la IP es de un visitante real) y la petición se bloqueaba como crawler falsificado.

- **`WPS_Crawler_Verifier::identify_crawler_ua()`**: ya no identifica como `facebookbot` los User-Agents que contienen la firma de un navegador interactivo real.
- **`WPS_Crawler_Verifier::is_interactive_browser_ua()`** (nuevo): detecta navegadores reales mediante el token de versión de Safari (`Version/x.y … Safari/`) y marcadores de webview de iOS (`CriOS`, `FxiOS`, `EdgiOS`, `GSA`). Los bots sociales legítimos y Googlebot nunca emiten estos tokens, por lo que la verificación de spoofing real no se ve afectada.

## [0.2.9] — 2026-05-08

- Fix para detección exagerada de SQL injections

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
