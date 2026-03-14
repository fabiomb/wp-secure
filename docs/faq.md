# Preguntas Frecuentes

## General

### ¿WP Seguro es compatible con mi hosting?

WP Seguro funciona en cualquier hosting que cumpla los requisitos mínimos (PHP 7.4+, WordPress 6.0+, MySQL 5.7+). Las tres capas del firewall tienen diferentes requisitos:

- **Capa 2** (plugin): Funciona en todos los hostings. No requiere nada especial.
- **Capa 1** (MU-Plugin): Requiere permisos de escritura en `wp-content/mu-plugins/`.
- **Capa 0** (auto_prepend): Requiere acceso a configuración de PHP. No disponible en algunos hostings compartidos.

### ¿Puedo usar WP Seguro con otros plugins de seguridad?

No se recomienda. Múltiples plugins de seguridad pueden interferir entre sí, causando bloqueos falsos o reduciendo el rendimiento. Si necesitas mantener ambos temporalmente, desactiva las funciones duplicadas en uno de los dos plugins.

### ¿WP Seguro ralentiza mi sitio?

WP Seguro está diseñado para añadir **menos de 5ms** al tiempo de carga de una página normal. En la mayoría de sitios, el overhead es de 1-3ms. Puedes verificar esto activando el **Modo debug de rendimiento** en la configuración.

### ¿Qué pasa si me bloqueo a mí mismo?

Tu IP se añade automáticamente a la whitelist durante la configuración inicial. Si aun así te bloqueas:

1. Accede al servidor por FTP/SSH.
2. Elimina `wp-content/mu-plugins/wps-firewall.php`.
3. Renombra la carpeta del plugin.
4. Accede al panel y reconfigura.

Consulta [Solución de Problemas](troubleshooting.md) para más detalles.

---

## Funcionalidad

### ¿Qué es la verificación rDNS de crawlers?

Es un mecanismo para verificar que los bots que dicen ser de Google, Bing, etc., realmente lo son. Se hace una consulta DNS inversa de la IP y se comprueba que el dominio pertenece a la empresa declarada. Los bots falsos se bloquean automáticamente. Los legítimos se excluyen de las reglas del scanner.

### ¿Qué hace la opción «Bloquear acceso público a REST API»?

Cuando está activa, solo los usuarios autenticados (logueados en WordPress) pueden usar la API REST. Las IPs en la whitelist también tienen acceso. Los namespaces configurados como permitidos (por ejemplo, `contact-form-7`, `woocommerce`) se excluyen del bloqueo. El namespace `oembed/1.0` siempre está permitido para que los embeds funcionen.

### ¿Qué son los «Headers de seguridad»?

Son cabeceras HTTP que WP Seguro envía en cada respuesta para mejorar la seguridad del navegador:

| Header | Función |
|--------|---------|
| `X-Content-Type-Options: nosniff` | Previene MIME sniffing |
| `X-Frame-Options: SAMEORIGIN` | Previene clickjacking |
| `Referrer-Policy: strict-origin-when-cross-origin` | Controla información de referrer |
| `Permissions-Policy` | Restringe APIs del navegador (geolocation, camera, etc.) |
| `X-XSS-Protection: 1; mode=block` | Activa filtro XSS del navegador |

### ¿Cómo funciona la puntuación de riesgo?

Cada regla activada suma puntos al score de una IP. Cuando el score supera un umbral, se toma acción (log, bloqueo temporal, o bloqueo permanente). Los umbrales dependen del nivel de protección configurado (Bajo, Medio, Alto). Consulta [Referencia de Reglas](rules-reference.md) para los valores.

### ¿Qué métodos HTTP se bloquean?

- **Siempre bloqueados:** TRACE, TRACK, DEBUG, CONNECT — estos métodos no tienen uso legítimo en un sitio WordPress y son usados para ataques.
- **Bloqueados fuera de contexto:** DELETE, PUT, PATCH — solo se permiten en peticiones a la API REST o AJAX de WordPress.

### ¿Por qué bloquear el User-Agent vacío?

La mayoría de navegadores y bots legítimos envían una cadena User-Agent. Las peticiones sin User-Agent suelen ser scripts automatizados o herramientas de ataque. Esta opción está desactivada por defecto porque algunos APIs legítimos pueden no enviar User-Agent.

---

## CDN y Proxy

### ¿Cómo sabe WP Seguro que uso Cloudflare?

En modo **Auto-detectar**, WP Seguro verifica dos cosas:

1. Que existe la cabecera `CF-Connecting-IP` en la petición.
2. Que la IP que conecta al servidor (`REMOTE_ADDR`) pertenece a los rangos de IP publicados por Cloudflare.

Solo si ambas condiciones se cumplen, se confía en la cabecera para obtener la IP real.

### ¿Qué pasa si configuro mal el proxy?

- Si configuras un proxy que no usas: WP Seguro buscará cabeceras que no existen y caerá al fallback (`REMOTE_ADDR`). No debería causar problemas.
- Si no configuras un proxy que sí usas: Todas las IPs aparecerán como la dirección del proxy/CDN. Los bloqueos afectarán a todos los visitantes.

### ¿Puedo usar WP Seguro con un CDN que no es Cloudflare ni Sucuri?

Sí. Usa el modo **Personalizado** y configura las IPs de confianza de tu CDN y la cabecera HTTP que usa para enviar la IP real. Consulta [Configuración de CDN/Proxy](cdn-proxy-setup.md#proxy-personalizado).

---

## Datos y Privacidad

### ¿Qué datos almacena WP Seguro?

- IPs de visitantes y sus eventos de seguridad.
- Datos de geolocalización (país, ASN) derivados de la IP.
- User-Agent, URL y método HTTP de cada petición registrada.
- No almacena contenido de formularios, contraseñas, ni datos personales más allá de la IP.

### ¿Se eliminan los datos al desinstalar?

Sí. Al **desinstalar** (eliminar) el plugin desde el panel de WordPress, se eliminan todas las tablas de la base de datos, los transients, y los archivos auxiliares (MU-Plugin, archivos de Capa 0).

**Nota:** Desactivar el plugin NO elimina los datos. Solo la desinstalación completa los elimina.

### ¿WP Seguro es compatible con GDPR?

Las IPs se consideran datos personales bajo el GDPR. WP Seguro proporciona:

- Retención configurable con purga automática.
- Exportación de datos (CSV).
- Eliminación de registros asociados a una IP específica.

Consulta con tu asesor legal para determinar si el procesamiento de IPs para seguridad está cubierto por la base legal de «interés legítimo» en tu caso específico.
