# Registro de Cambios

## [0.4.1] — Sin publicar

### Corrección: El aviso de login desde IP nueva nunca se enviaba

El ajuste **Notificar login desde IP nueva** venía activado por defecto y se mostraba en Configuración → Notificaciones, pero ningún código invocaba el aviso: un administrador que iniciaba sesión desde una red desconocida nunca generaba el mail.

- **`WPS_Admin_Notifier::track_login()`** (nuevo): se llama desde `WPS_Login_Detector::on_login_success()` y avisa cuando un usuario con `manage_options` inicia sesión desde una red que no usó antes. No aplica a clientes, alumnos ni otros usuarios sin permisos de administración, para no inundar el correo en sitios con muchas cuentas.
- **Red conocida**: se identifica con la clave de cliente, así que en IPv6 rotar de dirección dentro del mismo prefijo (por defecto `/64`) no genera avisos. Las redes conocidas se guardan en user meta (`wps_known_login_keys`, hasta 20 por usuario, se descartan las más viejas) y no en la tabla de intentos de login, que se purga a los pocos días.
- **Sin avisos al instalar**: el primer login de un usuario sin historial no avisa, porque toda red sería «nueva». Las redes se registran aunque el aviso esté desactivado, para que activarlo después no dispare un mail por cada red ya usada.
- **`WPS_Admin_Notifier::notify_new_login_ip()`** devuelve ahora si el mail se envió.

## [0.4.0] — 2026-09-22

### Seguridad: En IPv6 bastaba con cambiar de dirección para esquivar el firewall

Un proveedor asigna normalmente un `/64` entero a cada cliente IPv6: 18 trillones de direcciones que el cliente puede usar a voluntad, una distinta en cada petición. El rate limiting, el conteo de intentos de login y los bloqueos automáticos trabajaban con la dirección exacta, así que un atacante con IPv6 rotaba de dirección y ninguno de los tres lo alcanzaba: nunca superaba un límite, nunca acumulaba intentos fallidos y cada bloqueo caía sobre una dirección que ya no usaba.

- **Clave de cliente** (`WPS_Ip_Utils::client_key()`, nuevo): en IPv4 es la IP; en IPv6, la red del prefijo configurado.
- **Nuevo ajuste `ipv6_block_prefix`** (Configuración → Firewall Avanzado → Prefijo IPv6 por cliente): por defecto `64`, admite de `48` a `128`. `128` vuelve al comportamiento anterior (dirección exacta). Un valor fuera de rango vuelve al valor por defecto, para que un campo vacío no termine bloqueando un `/48`.
- **Rate limiting**: `WPS_Rate_Limiter` cuenta por clave de cliente.
- **Intentos de login**: `WPS_Login_Detector` registra y cuenta los intentos por clave de cliente, así que el máximo de intentos fallidos y el umbral de usuarios inexistentes valen para toda la red.
- **Bloqueos automáticos** (`WPS_Blocker::block_offender()`, nuevo): los detectores de SQLi, XSS, path traversal, scanner y crawlers falsificados, el rate limiter, el detector de login y el motor de riesgo bloquean en IPv6 la red completa como rango CIDR. La Capa 0 ya aplicaba rangos, con su vencimiento. Mantiene las salvaguardas de `block_ip()` (nunca el propio servidor ni una IP de la whitelist) y, si la red incluye la IP del servidor, bloquea sólo la dirección exacta: la Capa 0 no exime al servidor y le cortaría wp-cron.
- **Escalada de bloqueos**: `WPS_Blocker::count_previous_blocks()` cuenta los bloqueos de la dirección y los de su red, así que la escalada a bloqueos largos y permanentes sigue funcionando con bloqueos de red.
- **Sin cambios**: los bloqueos manuales, las reglas personalizadas y la whitelist siguen usando la dirección exacta. El log de eventos y el de tráfico siguen registrando la dirección exacta; el evento de bloqueo agrega la red bloqueada en sus detalles.

Algunos proveedores de hosting comparten un `/64` entre servidores de clientes distintos. Si aparecen bloqueos de red que alcanzan a terceros legítimos, se puede subir el prefijo o usar la whitelist.

### Documentación

- **`configuration.md`**: la tabla de rate limiting describía ajustes que no existen («Activar rate limiting», «Ventana de análisis»); ahora lista los reales. Se documenta el prefijo IPv6 y el resultado *no verificado* de la verificación de crawlers.

### Versión

- Versión actualizada a `0.4.0` en la cabecera del plugin, la constante `WPS_VERSION` y el MU-plugin.

## [0.3.1] — 2026-09-22

Continuación de la revisión de la 0.3.0: Capa 0, resiliencia ante fallas externas y documentación.

### Corrección: La Capa 0 aplicaba bloqueos vencidos y no se enteraba de los desbloqueos

La Capa 0 corre antes de WordPress y no consulta la base de datos: sólo conoce lo que dice su archivo de datos, y ese archivo se regeneraba únicamente con el cron horario.

- **Desbloquear una IP desde el panel no tenía efecto en la Capa 0** hasta la siguiente pasada del cron. Lo mismo al agregar una IP a la whitelist, incluso la propia.
- **Los bloqueos temporales no vencían en la Capa 0**: el archivo no guardaba el vencimiento, así que un bloqueo de 15 minutos seguía vigente hasta una hora más, o indefinidamente si el cron no corría.
- **La whitelist por rango CIDR se ignoraba** en la Capa 0.
- **El archivo se escribía en el mismo lugar desde donde se lee**. Una petición que lo incluía a mitad de la escritura recibía un *ParseError*, que el operador `@` no suprime, y fallaba con error fatal.

Cambios:

- **Formato del archivo**: cada IP y cada CIDR bloqueado lleva su vencimiento como timestamp (`0` = permanente), y se agrega `whitelist_cidrs`. `WPS_Firewall_Prepend` descarta los bloqueos vencidos por su cuenta y sigue leyendo el formato anterior (valor `1`, lista plana de CIDRs) como permanente, así que no hay corte durante la actualización.
- **`WPS_Blocker::schedule_layer0_sync()`** (nuevo): bloquear, desbloquear, hacer permanente un bloqueo o modificar la whitelist regenera el archivo al final de la petición, una sola vez aunque haya varios cambios. También funciona cuando el bloqueo ocurre en la Capa 1 y termina con `exit`.
- **Guardar la configuración** regenera el archivo, o lo elimina si se apagó la Capa 0.
- **`WPS_Activator::build_blocked_ips_data()`** (nuevo): arma el contenido del archivo, separado de la escritura para poder testearlo. Si una IP tiene varios bloqueos activos, gana el más largo.
- **Escritura atómica**: el archivo se escribe en un temporal y se renombra, y después se invalida OPcache. Con `opcache.validate_timestamps` desactivado, antes se seguía sirviendo la versión vieja.
- **Whitelist de la Capa 0**: sólo toma las entradas de tipo `global`. Las de tipo `login` eximen del detector de login, no de un bloqueo de IP.

### Corrección: Una actualización del plugin podía dejar todo el sitio en error fatal

La documentación indicaba apuntar `auto_prepend_file` a `plugins/wp-secure/includes/firewall/wps-firewall-prepend.php`. Durante una actualización WordPress borra y vuelve a copiar la carpeta del plugin; mientras el archivo no está, PHP no puede cargar el prepend y **cada** petición del sitio termina en error fatal, incluido wp-admin. Lo mismo al eliminar el plugin o al renombrar su carpeta, que era justamente el procedimiento de recuperación que proponía la guía de solución de problemas.

- **Cargador estable de la Capa 0** (nuevo): el plugin genera `wp-content/wps-data/wps-firewall-loader.php`, fuera de su carpeta, y lo mantiene al activarse, actualizarse o cambiar de versión. El cargador incluye el firewall sólo si existe; si el plugin no está, no hace nada. Corre dentro de una función anónima para no dejar variables en el ámbito global de cada petición.
- **`WPS_Activator::install_prepend_loader()`**, **`build_prepend_loader()`**, **`prepend_loader_path()`** y **`prepend_points_into_plugin()`** (nuevos).
- **Aviso en el panel**: si `auto_prepend_file` apunta todavía al archivo dentro del plugin, se muestra una advertencia con la ruta del cargador. La descripción del ajuste de Capa 0 muestra la ruta exacta a configurar.
- **Desinstalación**: el cargador se conserva a propósito, porque borrarlo con la directiva todavía activa tumbaría el sitio.

### Nuevo: Suspender el bloqueo desde wp-config.php

Hasta ahora, recuperar el acceso tras bloquearse a uno mismo requería borrar el MU-plugin y renombrar la carpeta del plugin. Además de ser riesgoso con la Capa 0 configurada, no alcanzaba: al reactivar, el bloqueo seguía en la base de datos.

- **Constante `WPS_DISABLE_BLOCKING`**: definida en `wp-config.php`, el firewall sigue detectando y registrando pero no bloquea, igual que el Modo Inseguro. El panel muestra un aviso mientras esté activa.
- **`WPS_Blocker::blocking_disabled()`** (nuevo): reúne el Modo Inseguro y la constante.
- **Login con el bloqueo suspendido**: `WPS_Login_Detector::check_before_auth()` rechazaba el login de una IP bloqueada aunque el Modo Inseguro estuviera activo, porque no pasaba por `send_block_response()`. Ahora respeta ambos mecanismos, así que el administrador bloqueado puede entrar a desbloquearse.

### Corrección: Con la API de geolocalización caída, cada visita esperaba 5 segundos

En modo API, la primera petición de cada IP consulta ipinfo.io dentro de la propia petición del visitante, con un timeout de 5 segundos. Sólo se cacheaban las respuestas exitosas. Si el servicio estaba caído, lento o con la cuota agotada (429), cada IP nueva esperaba el timeout completo, y cada petición siguiente de esa misma IP volvía a intentarlo.

- **Pausa ante fallas del servicio**: un timeout, un error de conexión, un 429 o un 5xx suspenden las consultas a la API durante 10 minutos (`WPS_Ipdb_Manager::API_BACKOFF_TTL`). Mientras tanto se usa la base local si existe, o la petición sigue sin datos de país.
- **Cache de fallos por IP**: una IP que no pudo resolverse (respuesta inválida o error propio de esa IP) no se vuelve a consultar durante 15 minutos.
- **Timeout** reducido de 5 a 2 segundos.

### Seguridad: Una regla personalizada podía permitir que cualquiera se agregara a la whitelist

La acción **Agregar a whitelist** aceptaba cualquier condición, y la propia documentación proponía como ejemplo `User-Agent contiene "UptimeRobot"`. Cualquiera que enviara ese User-Agent quedaba en la whitelist global de forma permanente, excluido de todo el firewall. Lo mismo con condiciones sobre headers, la URI, el país (alcanzable con una VPN) o con operadores negativos («IP distinta de X» coincide con el resto de Internet).

- **`WPS_Custom_Rules::whitelist_conditions_allowed()`** (nuevo): la acción `whitelist` sólo admite condiciones sobre el campo `ip` con `equals` o `cidr`. Al guardar una regla que no cumple, el panel explica el motivo.
- **Reglas existentes**: las guardadas con versiones anteriores que no cumplen siguen registrando el evento, pero ya no agregan la IP a la whitelist. Las IPs que ya se hubieran agregado por esa vía siguen en la whitelist y conviene revisarlas: se reconocen por la etiqueta «Auto: regla …».
- **Documentación**: el ejemplo del servicio de monitoreo usa ahora el rango de IPs publicado por el servicio, y explica cuándo conviene la acción *Eximir*.

### Corrección: Acceder a XML-RPC bloqueaba la IP en todo el sitio

Con XML-RPC desactivado (el valor por defecto), cualquier petición a `xmlrpc.php` bloqueaba la IP durante 15 minutos para todo el sitio. Eso dejaba fuera a los servidores de Jetpack, a la app móvil de WordPress y a cualquiera que compartiera IP con ellos. Además, la detección buscaba `xmlrpc.php` en toda la URI, así que bastaba con buscar «xmlrpc.php» en el buscador del sitio.

- **`WPS_Xmlrpc_Detector`**: la petición se sigue rechazando con 403, pero ya no se bloquea la IP. Con XML-RPC desactivado el intento no tiene efecto; el abuso sostenido lo cubre el límite `rate_xmlrpc_per_hour`, que ahora sí recibe los hits de XML-RPC.
- **`WPS_Xmlrpc_Detector::is_xmlrpc_path()`** (nuevo): sólo cuenta la ruta pedida, no el query string. También se reconoce la constante `XMLRPC_REQUEST` que define WordPress.
- **Documentación**: la «excepción para Jetpack» que describía `configuration.md` no existía. Se explica cómo lograrlo con una regla *Eximir* por IP o rango.

### Corrección: Security headers duplicados y filtro XSS heredado

- **`WPS_Security_Hardener::headers_to_send()`** (nuevo): no se envía un header que otro plugin, el tema o el servidor ya definieron. Un `X-Frame-Options` duplicado con valores distintos hace que el navegador lo descarte, y un sitio configurado para embeberse en un dominio propio quedaba roto.
- **`X-XSS-Protection`** pasa de `1; mode=block` a `0`. El filtro fue retirado de los navegadores y, en los que lo conservan, permite ataques de filtrado selectivo. La recomendación actual es desactivarlo.

### Documentación

- **Recuperación de acceso** (`troubleshooting.md`, `faq.md`, `cdn-proxy-setup.md`): se reemplaza «borrar el MU-plugin y renombrar la carpeta» por la constante `WPS_DISABLE_BLOCKING` o, con WP-CLI, el Modo Inseguro. Se advierte no renombrar la carpeta con la Capa 0 apuntando dentro de ella.
- **Nombre del MU-plugin**: la documentación decía `wps-firewall.php` y `wps-muplugin.php`; los archivos reales son `wps-firewall-muplugin.php` en ambos lados.
- **Instalación de la Capa 0**: apunta al cargador y distingue Apache con mod_php (`.htaccess`) de PHP-FPM (`.user.ini`).
- **Desinstalación**: describía que se eliminaban las directivas de `auto_prepend_file`, cosa que el plugin no hace ni puede hacer con seguridad. Ahora explica qué se borra y qué no.
- **Ajustes inexistentes**: se eliminan las menciones a un «Nivel de protección» Bajo/Medio/Alto y a un «Modo de operación», que no existen. El asistente se describe con sus cuatro pasos reales.

### Corrección: La desinstalación dejaba datos atrás

`uninstall.php` borraba la ubicación de datos anterior (dentro de la carpeta del plugin) en lugar de `wp-content/wps-data/`, y no eliminaba la opción `wps_unsafe_mode` ni los transients de geolocalización y verificación de crawlers (uno por IP, potencialmente miles de filas en `wp_options`).

- Se eliminan `wp-content/wps-data/` (salvo el cargador de la Capa 0), `wps_unsafe_mode`, los transients `wps_*` y el MU-plugin, por si el plugin se eliminó sin desactivarse.

### Versión

- Versión actualizada a `0.3.1` en la cabecera del plugin, la constante `WPS_VERSION` y el MU-plugin.

## [0.3.0] — 2026-09-22

Versión centrada en eliminar bloqueos a visitantes legítimos y en una vulnerabilidad XSS del panel. Varios cambios afectan cuánto duran los bloqueos y cuándo se aplican, así que después de actualizar conviene revisar **WP Seguro → Bloqueos** y **Eventos** durante unos días.

### Seguridad: XSS almacenado en Tráfico en Vivo

Un visitante anónimo podía ejecutar JavaScript en la sesión de un administrador. La URI de cada petición se guarda decodificada en el log de tráfico, y la vista en vivo la insertaba dentro de un atributo `title="…"`. La función de escape del panel convertía `<`, `>` y `&`, pero no las comillas, así que una petición a una URI con `%22 onmouseover=…` cerraba el atributo e inyectaba un manejador de eventos. Ningún detector lo frenaba: el patrón de manejadores `on*=` exige una etiqueta `<` previa.

- **`WPS.esc()`** (`assets/js/wps-admin.js`): escapa ahora también `"` y `'`, de modo que es seguro tanto en texto como dentro de atributos. Ya no depende de `innerHTML`, y convierte a texto valores no string (antes un `http_status` de `0` se mostraba vacío).
- **Tráfico en Vivo**: el enlace a la ficha de la IP también pasa por `esc()` al insertarse en `href`.

### Corrección: La duración de los bloqueos dependía de la zona horaria de MySQL

Todas las fechas del plugin se guardan en UTC, pero se comparaban contra `NOW()`, que devuelve la hora en la zona horaria de la sesión MySQL. WordPress no fija esa zona, así que en la práctica rige la del servidor de base de datos.

- **Con MySQL en UTC-3** (lo habitual en hostings argentinos), un bloqueo de 15 minutos duraba 3 h 15 min, la ventana de «intentos de login en la última hora» abarcaba 4 horas y la escalada a bloqueo permanente se alcanzaba mucho antes de lo configurado.
- **Con MySQL en UTC+1 o UTC+2**, los bloqueos temporales vencían en el momento de crearse y el conteo de intentos fallidos de login daba siempre cero: la protección contra fuerza bruta quedaba anulada.
- **Todas las consultas** (`WPS_Blocker`, `WPS_Login_Detector`, `WPS_Db_Maintenance`, `WPS_Activator::sync_blocked_ips_file()`, dashboard, notificador, eventos, tráfico y patrones) usan ahora `UTC_TIMESTAMP()`. Los bloqueos existentes no necesitan migración: ya estaban guardados en UTC y a partir de esta versión se interpretan bien.
- **Nuevo test** que recorre `includes/` y falla si alguna consulta vuelve a usar `NOW()`, `CURDATE()`, `CURTIME()` o `SYSDATE()`.

### Corrección: El rate limit contaba cada visita dos veces y podía bloquear al propio servidor

El MU-plugin (Capa 1) registraba los hits `total` y `pages` en `muplugins_loaded`, y el loader (Capa 2) volvía a registrarlos en `init`. Cada visita anónima sumaba dos, así que el límite de 60 páginas por minuto era en la práctica de 30. Detrás de un NAT de oficina o del CGNAT de una operadora móvil, donde muchos usuarios comparten IP, eso alcanzaba para bloquearlos a todos.

Además, nada eximía al propio servidor. wp-cron, los loopbacks de Site Health y los precargadores de caché (WP Rocket, LiteSpeed Cache) salen de la IP del servidor, y un precargador supera el límite en segundos. Con la IP del servidor bloqueada, el sitio se queda sin tareas programadas.

- **`WPS_Rate_Limiter::record_hit()`**: cuenta cada tipo una sola vez por petición, aunque lo invoquen ambas capas. Las dos siguen registrando, para cubrir a visitantes anónimos (Capa 1) y a usuarios logueados sin `manage_options` (Capa 2).
- **`WPS_Ip_Utils::is_server_ip()`** (nuevo): reconoce loopback (`127.0.0.0/8`, `::1`) y la IP con la que el servidor atiende la petición (`SERVER_ADDR`, o `LOCAL_ADDR` en IIS).
- **El propio servidor ya no se limita ni se bloquea automáticamente**: `record_hit()` lo ignora, `WPS_Blocker::block_ip()` rechaza bloquearlo salvo que el bloqueo sea manual, y tanto el MU-plugin como `WPS_Loader::check_current_ip()` lo dejan pasar aunque una versión anterior lo haya dejado en la lista de bloqueos.
- **MU-plugin**: no aplica rate limit a las peticiones de wp-cron (`DOING_CRON`), igual que ya hacía la Capa 2.
- **`WPS_Ip_Utils::ip_in_cidr()`**: una IP y un CIDR de familias distintas (IPv4/IPv6) ya no coinciden nunca. Antes, una IPv6 contra un rango IPv4 se comparaba con una máscara sin el prefijo de 96 bits y podía coincidir por los ceros iniciales (`::1` coincidía con `127.0.0.0/8`).

Si el sitio está detrás de un CDN, los loopbacks pueden llegar con la IP pública del servidor en `CF-Connecting-IP` en lugar de `SERVER_ADDR`. En ese caso conviene agregar esa IP a la whitelist.

### Corrección: Visitantes bloqueados por abrir un post, buscar o comentar

Los detectores bloquean la IP ante la primera coincidencia, y varios patrones coincidían con tráfico completamente normal. Lo más grave estaba en las rutas: una URL de post la repite cada visitante que llega a ella, así que un solo slug desafortunado bloqueaba a todo el tráfico de esa página.

- **`WPS_Scanner_Detector::$scanner_paths`**: los nombres de directorio (`phpmyadmin`, `pma`, `mysql`, `myadmin`, `administrator`, `manager`) exigen ahora un segmento completo de la ruta. `\b` también corta en un guion, así que `/2024/05/mysql-vs-postgresql/` o `/blog/manager-de-contenidos/` se tomaban por sondas. `admin.php` sólo cuenta fuera de `/wp-admin/`: antes, un usuario con la sesión vencida que volvía a `/wp-admin/admin.php` quedaba bloqueado.
- **`WPS_Scanner_Detector::match_scanner_path()`** (nuevo): las rutas de scanner se evalúan sobre el path, sin el query string.
- **`WPS_Path_Traversal_Detector`**: los archivos sensibles del sitio (`wp-config.php`, `.htaccess`, `.env`, `composer.json`, `debug.log`, volcados `.sql`, etc.) sólo cuentan cuando son la ruta pedida. En el query string y en los formularios son menciones legítimas: buscar «cómo editar el .htaccess» o comentar «mi wp-config.php no carga» bastaba para quedar bloqueado. En cualquier campo se siguen detectando el recorrido de directorios (`../../`, en todas sus codificaciones) y los archivos del sistema (`/etc/passwd`, `/proc/self/environ`).
- **`WPS_Path_Traversal_Detector`**: el patrón de copias de seguridad (`backup|dump|database … .zip`) cruzaba todo el valor con `.*`; ahora exige que sea el nombre del archivo pedido. Los volcados `.sql` también.
- **`WPS_Path_Traversal_Detector::detect_in_path()`** y **`detect_in_value()`** (nuevos): exponen el análisis de cada contexto, lo que permite cubrirlo con tests.
- **`WPS_Sqli_Detector::$patterns`**: eliminado `' OR '` suelto, que coincidía con «¿elijo 'sí' or 'no'?»; la forma de ataque real (`' OR '1'='1`) la sigue cubriendo el patrón de tautologías. El patrón de comentarios SQL ya no considera el guion doble, habitual en prosa («I tried it -- and it worked»); se mantienen `/**/` y `/*!…*/`, que sí se usan para partir palabras clave.
- **`WPS_Xss_Detector::$patterns`**: `expression(` sólo cuenta como valor de una propiedad CSS (`: expression(`). Antes coincidía con «una regular expression (regex)».
- **Nuevos tests** de rutas legítimas y sondas reales para scanner y path traversal, y casos nuevos en los de SQLi y XSS.

### Corrección: Googlebot real se bloqueaba como crawler falsificado

La verificación de crawlers (PTR + resolución directa) tenía dos fallos que terminaban bloqueando a buscadores reales, con impacto directo en el posicionamiento.

- **IPv6**: la resolución directa usaba `gethostbyname()`, que sólo devuelve IPv4. Googlebot rastrea por IPv6 cuando el sitio tiene registro AAAA (o está detrás de Cloudflare), y en ese caso la IP resuelta nunca coincidía con la del visitante.
- **Fallas de DNS**: `gethostbyaddr()` no distingue «esta IP no tiene PTR» de «el DNS no respondió». Un timeout se trataba como falsificación, se bloqueaba la IP y el veredicto quedaba en cache 24 horas.

Cambios:

- **`WPS_Crawler_Verifier::verify_rdns()`**: usa `dns_get_record()`, que devuelve una lista vacía ante NXDOMAIN y `false` ante un error del servidor. La resolución directa consulta A y AAAA, y las IPs se comparan en binario (`inet_pton`), así que la notación abreviada o expandida de IPv6 da igual. Se revisan todos los nombres PTR, no sólo el primero.
- **`WPS_Crawler_Verifier::RESULT_UNVERIFIED`** (nuevo): resultado para cuando el DNS no respondió o no hay datos de ASN. No aplica el bloqueo por spoofing (la petición sigue el análisis normal) y se cachea 10 minutos en lugar de 24 horas.
- **`WPS_Crawler_Verifier::verify_asn()`**: sin base local ni API de geolocalización devuelve `unverified` en lugar de `spoofed`. Antes, el rastreador de Facebook que llegaba por IPv6 se bloqueaba en cualquier sitio sin datos de ASN.
- **Crawler de Facebook**: se agrega `.fbsv.net` a sus dominios de rDNS, que es el que usan sus IPs IPv6.
- **Cache**: la clave incluye el crawler además de la IP, para que el veredicto de un UA no se reutilice con otro.
- **`WPS_Crawler_Verifier::set_resolver()`** y **`arpa_name()`** (nuevos): permiten testear la verificación con un resolver falso. Los tests ya no dependen de la red.

### Corrección: Cada intento de login con usuario inexistente contaba doble

Con un usuario inexistente, `check_before_auth()` grababa el intento antes de autenticar, para poder contarlo y bloquear en el acto. Después WordPress disparaba `wp_login_failed` por ese mismo intento y `on_login_failed()` lo grababa otra vez. Con el umbral por defecto de 3, bastaban **dos** errores de tipeo en el usuario o el email para bloquear la IP, y el máximo de 5 intentos fallidos se alcanzaba en el tercero.

- **`WPS_Login_Detector`**: si `check_before_auth()` ya grabó el intento, `on_login_failed()` no lo vuelve a grabar. Se sigue registrando el evento y evaluando el bloqueo.
- **Tests**: el doble de `$wpdb` registra ahora los inserts, y se agregan stubs de `get_user_by()`, `wp_json_encode()` y `current_time()`. Esto permite verificar el flujo completo `authenticate` → `wp_login_failed`.

### Versión

- Versión actualizada a `0.3.0` en la cabecera del plugin, la constante `WPS_VERSION` y el MU-plugin. Al cambiar la cabecera del MU-plugin, `WPS_Loader::maybe_sync_muplugin()` reinstala automáticamente la copia de `wp-content/mu-plugins/`, que incluye los cambios de la Capa 1 de esta versión.

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
