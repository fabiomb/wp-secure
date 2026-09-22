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
| Protección de login | Activar/desactivar protección contra fuerza bruta. | Activado |
| Intentos máximos | Número de intentos fallidos antes del bloqueo temporal. | 5 |
| Ventana de tiempo | Período en minutos para contar intentos. | 15 |
| Duración del bloqueo | Minutos que dura el bloqueo temporal. | 30 |

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
| Bloquear enumeración de usuarios | Impide acceso a `/wp/v2/users` y `?author=N`. | Activado |
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
