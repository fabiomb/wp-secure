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

## Motor de Puntuación de Riesgo

Además de los detectores, que bloquean por sí solos cuando encuentran un patrón claro, el **motor de riesgo** suma puntos por señales débiles de una misma petición y actúa según el total. Se configura en **Configuración → Firewall Avanzado** («Motor de puntuación de riesgo») y tiene tres modos:

| Modo | Qué hace |
|------|----------|
| Desactivado (por defecto) | No evalúa nada. |
| Modo sombra | Puntúa y registra qué habría hecho, sin bloquear nunca. |
| Activo | Puntúa y aplica la acción. |

### Puntos por factor

| Factor | Puntos | De dónde sale |
|--------|--------|---------------|
| Ruta sospechosa (`install.php`, `setup-config.php`, `wp-trackback.php`, `wp-cron.php` con parámetros) | 30 | La petición. |
| User-Agent de herramienta (curl, wget, python-requests, Go, axios, …) | 25 | La petición. |
| Usuario inexistente | 25 | Algún login fallido del cliente con un usuario que no existe en la última hora. |
| User-Agent vacío | 20 | La petición. |
| Tasa de peticiones por encima del 70 % del límite de páginas | 20 | Contador de páginas del rate limiter (minuto actual). |
| Cada login fallido | 15 | Logins fallidos del cliente en la última hora. |
| Cada error 404 | 5 | Contador de 404 del rate limiter (minuto actual). |
| País de la lista «Países de alto riesgo» | 15 | Geolocalización, sólo si configuraste la lista. |

Los factores de comportamiento (404, logins fallidos, usuario inexistente, tasa) son los que justifican el motor: ninguno alcanza para que un detector bloquee, pero juntos describen a un cliente que tantea el sitio. Cuestan dos consultas por petición evaluada, y sólo con el motor encendido.

**SQLi, XSS, path traversal y XML-RPC no suman en el motor.** Sus detectores bloquean la petición antes de que el motor la evalúe, así que lo que bloquean nunca llega a puntuarse; el reporte del modo sombra cuenta esas IPs como atacantes confirmados.

Sólo se registran las peticiones de 31 puntos o más. Un bot que pide páginas normales con un User-Agent de curl suma 25 y no deja rastro: que el reporte esté vacío con mucho tráfico significa que nada combinó señales suficientes, no que el motor no mida. La página **Motor de riesgo** muestra cuántas peticiones hubo en el período y qué factores aparecieron.

### Umbrales

| Puntaje | Acción |
|---------|--------|
| 31–50 | Se registra como riesgo bajo. |
| 51 hasta el umbral de bloqueo | Se registra como riesgo medio. |
| Desde el **umbral de bloqueo** (81 por defecto) | Bloqueo temporal (la duración de «Duración del bloqueo» de Rate Limiting). |
| Desde el **umbral de bloqueo permanente** (101 por defecto) | Bloqueo permanente. Con `0`, nunca es permanente. |

Los dos umbrales de bloqueo se configuran («Umbral de bloqueo por riesgo» y «Umbral de bloqueo permanente»). Los usuarios con sesión iniciada y las IPs de la whitelist no se evalúan.

### Calibración con el modo sombra

Los puntajes por defecto no se calibraron contra el tráfico de tu sitio: activarlos de golpe puede bloquear visitantes legítimos (un monitor de disponibilidad con curl, una integración). El camino es:

1. Activar el **modo sombra** y dejarlo unos días (al menos 3).
2. Revisar **WP Seguro → Motor de riesgo**, que para el período elegido (24 h, 7 o 30 días) muestra:
   - **Qué pasaría con cada umbral** (51 a 201 y el actual): cuántos clientes se bloquearían, cuántos ya había bloqueado otra regla (detectores, rutas trampa, bloqueos manuales: atacantes confirmados) y cuántos serían **bloqueos nuevos**.
   - **Umbral sugerido**: el más bajo con el que el motor sólo habría bloqueado atacantes confirmados.
   - **Factores que más pesan** en los clientes que se bloquearían, primero los que aparecen en bloqueos nuevos: si un factor empuja falsos positivos, se ve ahí.
   - **Clientes que sólo bloquearía el motor**, con su peor puntaje y sus factores, para revisarlos uno por uno.
3. Fijar el umbral sugerido (o whitelistear el tráfico legítimo) y pasar a **Activo**.

---

## Whitelist

Las IPs en la whitelist se excluyen de **todas** las reglas de detección. La whitelist se evalúa siempre al inicio del proceso, antes de cualquier regla.

Tipos de entradas soportadas:
- IP individual: `192.168.1.100`
- Rango CIDR: `10.0.0.0/8`
- IPv6: `2001:db8::1`

La IP del administrador se añade automáticamente a la whitelist durante la configuración inicial.
