# Configuración

Todos los ajustes de WP Seguro se gestionan desde **WP Seguro → Configuración**. Las opciones se almacenan en la tabla propia del plugin, no en `wp_options`.

---

## General

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Modo Inseguro | Desde el dashboard. El firewall detecta y registra, pero no bloquea. Equivale a definir `WPS_DISABLE_BLOCKING` en `wp-config.php`. | Desactivado |
| Email de notificaciones | Dirección para alertas de seguridad. | Email del administrador |

---

## Login

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Intentos máximos antes de bloqueo | Intentos fallidos desde un mismo cliente en la última hora antes de bloquearlo. | 5 |
| Intentos fallidos por cuenta/hora | Contra una misma cuenta, desde cualquier IP (ver abajo). `0` lo desactiva. | 10 |
| Sesiones simultáneas por administrador | Al iniciar una sesión nueva se cierran las más viejas que excedan el límite. `0` = sin límite. | 0 |
| Duración del bloqueo temporal | Minutos. | 15 |
| Escalar bloqueo tras N bloqueos temporales | Bloqueos previos en 48 h que llevan a un bloqueo largo. | 3 |
| Duración del bloqueo escalado | Horas. | 24 |
| Bloquear usuario inexistente | Bloquea al cliente tras varios intentos con usuarios que no existen. | Activado |
| Intentos con usuario inexistente | Umbral para el punto anterior. `0` lo desactiva. | 3 |
| Login sólo desde whitelist | Rechaza todo login desde IPs fuera de la whitelist de login. | Desactivado |

### Intentos fallidos por cuenta

Los límites por IP no frenan a una botnet: miles de IPs prueban contraseñas contra la misma cuenta y ninguna llega a su propio límite. Por eso también se cuentan los intentos fallidos **contra cada cuenta**, desde cualquier IP, por nombre de usuario o por email.

Superado el límite en la última hora, la cuenta sólo acepta logins desde **redes donde su dueño ya inició sesión** (en IPv6, su prefijo configurado); a los demás se los rechaza sin comprobar la contraseña, así que el atacante no puede seguir probando. El bloqueo se levanta solo cuando los fallos salen de la ventana de una hora.

Si el dueño tiene que entrar desde una red nueva mientras la cuenta está bajo ataque, puede restablecer la contraseña: la red desde la que lo hace pasa a ser conocida.

---

## XML-RPC

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Desactivar XML-RPC | Rechaza con 403 las peticiones a `xmlrpc.php` y desactiva pingbacks. No bloquea la IP: el abuso sostenido lo limita **Rate limit de XML-RPC** (`rate_xmlrpc_per_hour`). | Activado |

Para permitir un servicio que necesita XML-RPC (Jetpack, la app móvil), creá una regla personalizada con acción **Eximir** del detector *XML-RPC* y condición sobre la **IP** o el **rango CIDR** del servicio.

---

## REST API

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Bloquear acceso público | Requiere autenticación para acceder a la API REST. | Desactivado |
| Bloquear enumeración de usuarios | Impide averiguar qué usuarios existen: bloquea `/wp/v2/users` y `?author=`, quita el sitemap de usuarios y el autor de oEmbed, unifica los errores de login y responde igual en la recuperación de contraseña exista o no la cuenta. | Activado |
| Namespaces permitidos | Lista de namespaces excluidos del bloqueo (uno por línea). `oembed/1.0` siempre se permite. | contact-form-7, woocommerce |

**Nota:** Si usas plugins que dependen de la API REST pública (WooCommerce, Contact Form 7, etc.), añade sus namespaces a la lista de permitidos.

---

## Rate Limiting

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Páginas por minuto | Peticiones que cargan WordPress (páginas, admin, REST, AJAX). `0` desactiva el límite. | 60 |
| Peticiones totales por minuto | Todas las peticiones que llegan a PHP, incluidos recursos estáticos servidos por WordPress. | 240 |
| Errores 404 por minuto | Útil contra la enumeración de rutas. | 10 |
| Intentos de login por hora | | 5 |
| Peticiones XML-RPC por hora | `0` desactiva el límite. | 0 |
| Búsquedas por minuto | En el buscador del sitio (`?s=`) y en las búsquedas de la REST API. Al superarlo se responde 429, sin bloquear la IP. `0` desactiva el límite. | 20 |
| Recuperaciones de contraseña por hora | Al superarlo se rechaza el pedido, sin bloquear la IP. `0` desactiva el límite. | 5 |
| Registros de usuario por hora | En el registro de WordPress. Al superarlo se rechaza el registro, sin bloquear la IP. `0` desactiva el límite. | 3 |
| Duración del bloqueo (minutos) | Cuánto dura el bloqueo al superar un límite. | 15 |

Los límites se cuentan por **cliente**: en IPv4 es la dirección IP; en IPv6, la red del prefijo configurado en **Firewall → Prefijo IPv6 por cliente** (ver abajo). El propio servidor (wp-cron, loopbacks) nunca se limita.

---

## Firewall

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Verificación rDNS de crawlers | Verificar la legitimidad de bots conocidos mediante DNS inverso. | Activado |
| Headers de seguridad | Enviar cabeceras HTTP de seguridad (X-Content-Type-Options, X-Frame-Options, etc.). | Activado |
| Ocultar versión de WP | Eliminar meta tags y parámetros `?ver=` que revelan la versión de WordPress. | Activado |
| Bloquear métodos HTTP peligrosos | Bloquear TRACE, TRACK, DEBUG, CONNECT. | Activado |
| Bloquear User-Agent vacío | Bloquear peticiones sin cabecera User-Agent. | Desactivado |
| Bloquear peticiones sin Host | Bloquear peticiones sin cabecera Host válida. | Activado |
| Prefijo IPv6 por cliente | Tamaño de la red IPv6 que se trata como un solo cliente (48–128). `128` = dirección exacta. | 64 |
| Rutas trampa | Bloquear de inmediato a quien pida una ruta trampa. | Activado |
| Lista de rutas trampa | Una por línea (ver abajo). | `/.env`, copias de `wp-config.php`, `/.git/*`, … |
| Duración del bloqueo por ruta trampa | En minutos. | 1440 (24 h) |
| Protección de formularios | Campo trampa y tiempo mínimo en login y comentarios (ver abajo). | Activado |
| Tiempo mínimo para comentar | Segundos entre la carga de la página y el envío. `0` desactiva el control. | 3 |
| Tiempo mínimo para iniciar sesión | Igual, para `wp-login.php`. | 0 (desactivado) |

### Rutas trampa

Son rutas que ningún visitante legítimo pide pero que todo scanner automatizado prueba: `/.env`, copias de `wp-config.php` (`.bak`, `.old`, `~`…), `/.git/`, `/.aws/`, `/phpinfo.php`, `/vendor/phpunit/`. Quien pide una queda bloqueado de inmediato y por más tiempo que un bloqueo común, porque la señal es inequívoca.

- Se compara el **final** de la ruta, sin distinguir mayúsculas, así que funciona con WordPress en un subdirectorio.
- Un `*` al final abarca todo lo que haya debajo: `/.git/*` coincide con `/.git/config` y `/.git/HEAD`.
- Podés agregar rutas propias, por ejemplo la URL de un panel de administración que no existe en tu sitio.
- Nunca se bloquea a usuarios logueados con permisos de edición, a la whitelist ni al propio servidor.

### Protección de formularios

Frena bots en el login (`wp-login.php` y `wp_login_form()`) y en los comentarios, sin captcha ni servicios externos:

- **Campo trampa**: un campo oculto a la vista y a los lectores de pantalla. Un humano no lo completa; los bots completan todo. Si viene completo, el envío se rechaza.
- **Tiempo mínimo**: el formulario lleva la hora en que se cargó, firmada para que no se pueda falsificar. Un envío más rápido que el mínimo se rechaza.
- **Envíos sin los campos del plugin**: un comentario que no los trae (un bot que postea directo, o una página cacheada desde antes de activar la función) **va a la cola de spam** en lugar de rechazarse, así no se pierde ningún comentario legítimo. En el login se deja pasar, porque los formularios de login de temas y plugins (por ejemplo, el de WooCommerce) no usan los hooks estándar; la fuerza bruta la frena el límite de intentos.
- El tiempo mínimo del login viene desactivado: los gestores de contraseñas con envío automático completan el formulario en menos de un segundo.
- No se bloquea la IP: sólo se rechaza el envío y se registra el evento «Bot en formulario». Los usuarios logueados, la whitelist y el propio servidor quedan exentos, y con el Modo Inseguro activo no se rechaza nada.

### Prefijo IPv6 por cliente

En IPv6 un proveedor asigna normalmente un `/64` entero a cada cliente, y el cliente puede usar una dirección distinta en cada petición. Si el firewall trabajara con la dirección exacta, bastaría con rotarla para esquivar el rate limiting, el conteo de intentos de login y cualquier bloqueo.

Por eso, con el valor por defecto (`64`):

- El **rate limiting** y los **intentos de login** se cuentan por red `/64`.
- Los **bloqueos automáticos** (detectores, rate limit, login, motor de riesgo) bloquean la red `/64` como rango CIDR. Si la red incluye la IP del propio servidor, se bloquea sólo la dirección exacta.
- Los **bloqueos manuales**, las **reglas personalizadas** y la **whitelist** siguen usando la dirección exacta.

Algunos proveedores de hosting comparten un `/64` entre varios servidores de clientes distintos. Si ves bloqueos de red que alcanzan a terceros legítimos, podés subir el valor (p. ej. `128`) o agregar esas direcciones a la whitelist.

### Verificación rDNS de Crawlers

Cuando está activo, WP Seguro verifica que los bots que se identifican como Google, Bing, etc., realmente provienen de los servidores de esas empresas:

1. Se realiza una consulta DNS inversa (PTR) de la IP del visitante.
2. Se verifica que el dominio obtenido corresponda al crawler declarado.
3. Se realiza una consulta DNS directa para confirmar que el dominio resuelve a la misma IP.

Los crawlers verificados se excluyen de las reglas del scanner. Los crawlers falsos (spoofed) se bloquean automáticamente. Si el DNS no responde, el resultado queda como *no verificado*: no se bloquea y se reintenta a los 10 minutos. Los resultados firmes se cachean durante 24 horas.

**Crawlers soportados:** Googlebot, Bingbot, YandexBot, Baiduspider, DuckDuckBot, Applebot, Facebookbot, LinkedInBot.

---

## Geolocalización

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Base de datos MMDB | Ruta al archivo MaxMind GeoLite2 o GeoIP2. | data/geolite2-country.mmdb |
| Países bloqueados | Lista de códigos de país a bloquear. | (ninguno) |
| ASNs bloqueados | Lista de números de sistema autónomo a bloquear. | (ninguno) |

---

## Proxy / CDN

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Modo de proxy | Método para resolver la IP real del visitante. | Auto-detectar |
| IPs de proxy confiables | Lista de IPs/CIDRs de proxies confiables (uno por línea). Solo para modo «Personalizado». | (vacío) |
| Cabecera de IP | Cabecera HTTP que contiene la IP real del visitante. | X-Forwarded-For |

### Modos de Proxy

| Modo | Descripción |
|------|-------------|
| **Auto-detectar** | WP Seguro detecta automáticamente si el tráfico viene de Cloudflare o Sucuri. |
| **Cloudflare** | Usa la cabecera `CF-Connecting-IP` y valida que la IP del servidor está en los rangos de Cloudflare. |
| **Sucuri** | Usa la cabecera `X-Sucuri-ClientIP` y valida los rangos de IP de Sucuri. |
| **Personalizado** | Usa la cabecera y lista de IPs confiables configuradas manualmente. |
| **Ninguno** | Usa `REMOTE_ADDR` directamente. Para servidores sin proxy. |

Consulta [Configuración de CDN/Proxy](cdn-proxy-setup.md) para instrucciones detalladas.

---

## Respuesta de Bloqueo

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Código HTTP | Código de respuesta para peticiones bloqueadas (403, 444, 503). | 403 |
| Página personalizada | HTML personalizado para la página de bloqueo. | Página por defecto del plugin |
| Incluir ID de incidente | Mostrar un código de referencia en la página de bloqueo. | Activado |

---

## Retención de Datos

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Retención de eventos | Días que se conservan los registros de eventos. | 30 |
| Retención de sesiones | Días que se conservan los datos de sesión/tráfico. | 7 |
| Limpieza automática | Ejecutar purga de datos antiguos automáticamente. | Activado |

---

## Notificaciones

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Email de destino | Dirección de correo para recibir alertas. | Email del administrador |
| Notificar bloqueos automáticos | Un resumen por hora con los bloqueos automáticos aplicados (sólo si hubo alguno). Los bloqueos manuales no se notifican. | Desactivado |
| Notificar login desde IP nueva | Aviso cuando un administrador inicia sesión desde una red que no usó antes. En IPv6 se considera la red del prefijo configurado. El primer login sin historial no avisa. | Activado |
| Notificar cambios de privilegios | Aviso al crear un administrador, dar permisos de administración a un usuario (cualquier rol con `manage_options`), instalar o activar un plugin o tema, desactivar un plugin (incluido WP Seguro), cambiar el tema o editar un archivo desde el panel. Incluye quién lo hizo y desde qué IP. | Activado |
| Notificar cambios de configuración | Aviso al guardar la configuración, activar o desactivar el Modo Inseguro o importar una configuración, con usuario e IP. | Activado |
| Resumen diario | Resumen de las últimas 24 horas: peticiones, eventos y bloqueos. | Activado |

---

## Rendimiento

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Modo debug de rendimiento | Mostrar tiempos de ejecución del plugin en la barra de admin y error_log. | Desactivado |

Cuando está activo, muestra en la barra de administración:
- Tiempo total de overhead del plugin.
- Uso de memoria.
- Detalle de tiempo por componente (detección, logging, DNS, etc.).
