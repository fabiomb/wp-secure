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
| Activar rate limiting | Limitar el número de peticiones por IP. | Activado |
| Peticiones por minuto | Máximo de peticiones permitidas por minuto por IP. | 60 |
| Ventana de análisis | Período en segundos para evaluar el rate limit. | 60 |

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

### Verificación rDNS de Crawlers

Cuando está activo, WP Seguro verifica que los bots que se identifican como Google, Bing, etc., realmente provienen de los servidores de esas empresas:

1. Se realiza una consulta DNS inversa (PTR) de la IP del visitante.
2. Se verifica que el dominio obtenido corresponda al crawler declarado.
3. Se realiza una consulta DNS directa para confirmar que el dominio resuelve a la misma IP.

Los crawlers verificados se excluyen de las reglas del scanner. Los crawlers falsos (spoofed) se bloquean automáticamente. Los resultados se cachean durante 24 horas.

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
| Notificaciones por email | Activar/desactivar envío de alertas por correo. | Desactivado |
| Email de destino | Dirección de correo para recibir alertas. | Email del administrador |
| Frecuencia de resumen | Intervalo del resumen periódico: diario, semanal, o desactivado. | Semanal |

---

## Rendimiento

| Opción | Descripción | Valor por defecto |
|--------|-------------|-------------------|
| Modo debug de rendimiento | Mostrar tiempos de ejecución del plugin en la barra de admin y error_log. | Desactivado |

Cuando está activo, muestra en la barra de administración:
- Tiempo total de overhead del plugin.
- Uso de memoria.
- Detalle de tiempo por componente (detección, logging, DNS, etc.).
