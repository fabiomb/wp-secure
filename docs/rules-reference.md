# Referencia de Reglas

WP Seguro evalúa cada petición contra un conjunto de reglas. Cada regla detectada suma puntos al **score de riesgo** de la IP. Cuando el score supera el umbral configurado, la IP se bloquea.

---

## Reglas de Detección

### R01 — Inyección SQL (SQLi)

Detecta patrones de inyección SQL en parámetros GET, POST, cookies y cabeceras.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Alta |
| Patrones | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `--`, hex encoding, etc. |
| Acción | Suma puntos al score + log del evento. |

### R02 — Cross-Site Scripting (XSS)

Detecta intentos de inyección de JavaScript en parámetros de la petición.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Alta |
| Patrones | `<script>`, `javascript:`, event handlers (`onerror`, `onload`), etc. |
| Acción | Suma puntos al score + log del evento. |

### R03 — Path Traversal

Detecta intentos de acceder a archivos fuera del directorio web.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Alta |
| Patrones | `../`, `..\\`, `/etc/passwd`, `/proc/self`, etc. |
| Acción | Suma puntos al score + log del evento. |

### R04 — Fuerza Bruta en Login

Protege `wp-login.php` contra ataques de fuerza bruta.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Media |
| Detección | Contador de intentos fallidos por IP en ventana de tiempo configurable. |
| Acción | Bloqueo temporal tras N intentos fallidos. |

### R05 — Abuso de XML-RPC

Protege contra ataques de amplificación y fuerza bruta vía `xmlrpc.php`.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Media |
| Detección | Peticiones a `xmlrpc.php`, métodos `system.multicall`, `wp.getUsersBlogs`. |
| Acción | Bloqueo de la petición. Opcionalmente desactiva XML-RPC completamente. |

### R06 — Scanner / Bot Malicioso

Detecta herramientas automatizadas de escaneo de vulnerabilidades.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Media |
| Detección | User-Agent de scanners conocidos (WPScan, Nikto, sqlmap, etc.) y acceso a paths sospechosos (`/wp-config.php.bak`, `/.env`, `/debug.log`). |
| Acción | Suma puntos al score. |

### R07 — Rate Limiting

Limita el número de peticiones por IP en un período de tiempo.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Baja |
| Detección | Contador de peticiones por IP por minuto. |
| Acción | Bloqueo temporal cuando se excede el límite. |

### R08 — Bloqueo por País

Bloquea tráfico de países específicos usando la base de datos de geolocalización.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Media |
| Detección | Lookup de IP → país vía MMDB. |
| Acción | Bloqueo inmediato si el país está en la lista. |

### R09 — Bloqueo por ASN

Bloquea tráfico de redes (Autonomous System Numbers) específicas.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Media |
| Detección | Lookup de IP → ASN vía MMDB. |
| Acción | Bloqueo inmediato si el ASN está en la lista. |

### R10 — Bloqueo por CIDR

Bloquea rangos de IP específicos configurados manualmente.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Media |
| Detección | Comparación de IP contra rangos CIDR configurados. |
| Acción | Bloqueo inmediato. |

### R11 — Crawler Spoofing

Detecta bots que se hacen pasar por crawlers legítimos (Google, Bing, etc.).

| Aspecto | Detalle |
|---------|---------|
| Severidad | Alta |
| Detección | Verificación rDNS: consulta PTR → validación de dominio → consulta A directa → comparación de IP. |
| Acción | Bloqueo inmediato + log. Los crawlers verificados como legítimos se excluyen de las demás reglas del scanner. |

### R12 — Protección REST API

Controla el acceso a la API REST de WordPress.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Baja |
| Detección | Peticiones REST de usuarios no autenticados. Acceso a `/wp/v2/users`. Parámetro `?author=N`. |
| Acción | Bloqueo de la petición (no de la IP). |

### R13 — Métodos HTTP y Cabeceras

Bloquea peticiones con métodos HTTP peligrosos o cabeceras faltantes.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Baja-Media |
| Detección | Métodos TRACE, TRACK, DEBUG, CONNECT. User-Agent vacío. Cabecera Host faltante. |
| Acción | Bloqueo de la petición + log. |

### R14 — Reglas Personalizadas

Reglas definidas manualmente por el administrador con condiciones y acciones configurables.

| Aspecto | Detalle |
|---------|---------|
| Severidad | Configurable |
| Detección | Condiciones del tipo IF/AND/OR sobre campos HTTP: URI, User-Agent, IP, método, query string, referer, host, país, tipo de visitante. Operadores: contiene, igual, empieza con, termina con, regex, CIDR. |
| Acción | Configurable: bloqueo permanente, bloqueo temporal, whitelist, o solo log. |

Consulta la [documentación de Reglas Personalizadas](custom-rules.md) para más detalles.

---

## Puntuación de Riesgo

Cada regla activada suma puntos al score acumulado de la IP. Los umbrales dependen del nivel de protección configurado:

| Nivel | Umbral de log | Umbral de bloqueo temporal | Umbral de bloqueo permanente |
|-------|---------------|---------------------------|------------------------------|
| Bajo | 30 | 60 | 100 |
| Medio | 20 | 40 | 80 |
| Alto | 10 | 25 | 50 |

### Puntuación por Regla (valores por defecto)

| Regla | Puntos |
|-------|--------|
| SQLi | 25 |
| XSS | 25 |
| Path Traversal | 25 |
| Login fallido | 5 |
| XML-RPC | 15 |
| Scanner UA | 10 |
| Scanner path | 10 |
| Rate limit excedido | 5 |
| Crawler spoofed | 30 |
| Método HTTP bloqueado | 15 |
| UA vacío | 5 |
| Host faltante | 10 |

---

## Whitelist

Las IPs en la whitelist se excluyen de **todas** las reglas de detección. La whitelist se evalúa siempre al inicio del proceso, antes de cualquier regla.

Tipos de entradas soportadas:
- IP individual: `192.168.1.100`
- Rango CIDR: `10.0.0.0/8`
- IPv6: `2001:db8::1`

La IP del administrador se añade automáticamente a la whitelist durante la configuración inicial.
