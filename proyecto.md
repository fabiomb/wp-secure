# Proyecto WP Seguro

## Visión General

Plugin de seguridad para WordPress orientado a **performance** y **claridad hacia el usuario**. Su objetivo principal es detectar, clasificar y bloquear tráfico malicioso (bots, spiders, intrusiones, fuerza bruta) interceptando las peticiones lo más temprano posible en el ciclo de ejecución de PHP/WordPress.

A diferencia de soluciones como Wordfence (que penalizan el rendimiento del sitio con escaneos pesados y tablas compartidas con WordPress), WP Seguro se diseña desde cero para ser liviano, autónomo en sus datos y transparente para el administrador.

---

## 1. Arquitectura General

### 1.1 Interceptación Temprana (Crítico)

Un plugin convencional de WordPress se carga **después** del core, los mu-plugins y otros plugins. Para cumplir el objetivo de interceptar tráfico *antes de que WordPress renderice o ejecute funciones*, se necesita una estrategia en dos capas:

| Capa | Mecanismo | Cuándo se ejecuta | Propósito |
|------|-----------|-------------------|-----------|
| **Capa 0 — Firewall PHP** | `auto_prepend_file` vía `.htaccess` o `.user.ini` | Antes de que PHP ejecute cualquier script | Bloqueo inmediato de IPs/rangos/países ya conocidos como bloqueados. Cero carga de WordPress. Máximo rendimiento. |
| **Capa 1 — MU-Plugin** | Archivo en `wp-content/mu-plugins/` | Después del core pero antes de plugins y themes | Análisis de la petición, detección de patrones, logging, resolución de reglas complejas. |
| **Capa 2 — Plugin Principal** | Plugin convencional en `wp-content/plugins/wp-secure/` | Carga normal de WordPress | Panel de administración, configuración, visualización de logs, gestión de reglas, actualizaciones de base de datos IP. |

**Flujo de decisión por petición:**

```
Petición HTTP entrante
    │
    ▼
[Capa 0: auto_prepend_file]
    ├── ¿IP en lista negra local (archivo/cache)?  → 403 + log mínimo → FIN
    ├── ¿IP en whitelist?                          → Continuar sin restricciones
    └── No decidido                                → Pasar a Capa 1
    │
    ▼
[Capa 1: MU-Plugin]
    ├── Registrar sesión/visita
    ├── Clasificar tipo de petición (login, xmlrpc, REST, admin, página, recurso)
    ├── Evaluar reglas (país, ASN, rate-limit, patrones de ataque)
    ├── ¿Bloquear?  → 403 + log detallado → FIN
    └── Permitir    → Continuar carga normal de WordPress
    │
    ▼
[Capa 2: Plugin - solo en /wp-admin/]
    └── Panel, configuración, reportes
```

### 1.2 Principio de Rendimiento

- **La Capa 0 no debe incluir WordPress ni conectarse a la base de datos.** Trabaja exclusivamente con archivos planos o caches en disco (un archivo `.php` con un array serializado de IPs bloqueadas, o un archivo binario de lookup rápido).
- **La Capa 1 se conecta a la base de datos propia** del plugin solo cuando es necesario. Las lookups frecuentes (IP→país, IP→ASN) se hacen contra la base de datos local MMDB si está disponible, o contra cache en archivo.
- **Escrituras en batch:** los logs de sesión se acumulan en un buffer y se escriben al final de la petición (`register_shutdown_function`) para no bloquear la respuesta.

### 1.3 Estructura de Archivos del Plugin

```
wp-secure/
├── proyecto.md                          # Este documento
├── wp-secure.php                        # Archivo principal del plugin (bootstrap)
├── uninstall.php                        # Limpieza al desinstalar
│
├── includes/
│   ├── class-wps-loader.php             # Carga y orquestación del plugin
│   ├── class-wps-activator.php          # Lógica de activación (crear tablas, mu-plugin, prepend)
│   ├── class-wps-deactivator.php        # Lógica de desactivación
│   │
│   ├── firewall/
│   │   ├── wps-firewall-prepend.php     # Script para auto_prepend_file (Capa 0)
│   │   └── wps-firewall-muplugin.php    # MU-Plugin (Capa 1)
│   │
│   ├── core/
│   │   ├── class-wps-request.php        # Objeto Request: IP, URI, método, headers, user-agent, fingerprint
│   │   ├── class-wps-ip-utils.php       # Utilidades: validación IP, CIDR, rango, IPv4/IPv6
│   │   ├── class-wps-geo.php            # Resolución IP→País, IP→ASN (MMDB local o API)
│   │   ├── class-wps-classifier.php     # Clasificación de la petición (humano/bot, tipo)
│   │   ├── class-wps-rules-engine.php   # Motor de evaluación de reglas
│   │   ├── class-wps-blocker.php        # Ejecuta bloqueos (respuesta 403, log)
│   │   └── class-wps-rate-limiter.php   # Control de tasa de peticiones
│   │
│   ├── detectors/
│   │   ├── class-wps-login-detector.php       # Intentos de login
│   │   ├── class-wps-xmlrpc-detector.php      # Uso de XML-RPC
│   │   ├── class-wps-sqli-detector.php        # Inyecciones SQL
│   │   ├── class-wps-path-traversal-detector.php  # Path traversal
│   │   ├── class-wps-xss-detector.php         # Cross-site scripting
│   │   ├── class-wps-restapi-detector.php     # Abuso de REST API
│   │   └── class-wps-scanner-detector.php     # Escaneo de vulnerabilidades (patrones conocidos)
│   │
│   ├── logging/
│   │   ├── class-wps-logger.php         # Sistema de logging con buffer
│   │   ├── class-wps-session-tracker.php # Seguimiento de sesiones/visitas
│   │   └── class-wps-event-types.php    # Definición de tipos de eventos
│   │
│   ├── database/
│   │   ├── class-wps-db.php             # Acceso a base de datos propia
│   │   ├── class-wps-db-schema.php      # Definición de esquemas/tablas
│   │   ├── class-wps-db-migrations.php  # Migraciones de esquema entre versiones
│   │   └── class-wps-db-maintenance.php # Limpieza, optimización, archivado
│   │
│   ├── ipdb/
│   │   ├── class-wps-ipdb-manager.php   # Gestión de la base de datos IP local
│   │   ├── class-wps-mmdb-reader.php    # Lector de archivos MMDB (MaxMind format)
│   │   └── class-wps-ipdb-updater.php   # Actualización periódica de la base de datos IP
│   │
│   └── admin/
│       ├── class-wps-admin.php          # Controlador principal del panel
│       ├── class-wps-admin-dashboard.php    # Dashboard/resumen
│       ├── class-wps-admin-live-traffic.php # Visor de tráfico en vivo
│       ├── class-wps-admin-blocks.php       # Visor de bloqueos
│       ├── class-wps-admin-rules.php        # Gestión de reglas
│       ├── class-wps-admin-firewall.php     # Estado del firewall
│       ├── class-wps-admin-ipdb.php         # Estado de base de datos IP
│       ├── class-wps-admin-settings.php     # Configuración general
│       ├── class-wps-admin-ajax.php         # Endpoints AJAX para el panel
│       └── class-wps-admin-rest.php         # Endpoints REST para el panel
│
├── assets/
│   ├── css/
│   │   └── wps-admin.css
│   └── js/
│       ├── wps-admin.js
│       └── wps-live-traffic.js          # WebSocket o polling para tráfico en vivo
│
├── data/
│   └── .htaccess                        # Deny from all (proteger datos locales)
│
├── languages/
│   ├── wp-secure-es_ES.po
│   └── wp-secure-en_US.po
│
└── vendor/                              # Dependencias (MMDB reader, etc.)
```

---

## 2. Funciones Detalladas

### 2.1 Detección y Clasificación de Tráfico

Cada petición se analiza y clasifica según múltiples criterios:

#### Datos capturados por petición:
| Dato | Fuente | Uso |
|------|--------|-----|
| IP del visitante | `REMOTE_ADDR`, headers proxy (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`) | Identificación, geolocalización, bloqueo |
| URI solicitada | `REQUEST_URI` | Clasificación de tipo de acceso |
| Método HTTP | `REQUEST_METHOD` | Detección de métodos inusuales (PUT, DELETE, PATCH en contextos no REST) |
| User-Agent | `HTTP_USER_AGENT` | Clasificación humano/bot, detección de bots conocidos |
| Referer | `HTTP_REFERER` | Detección de patrones de spam/phishing |
| País | Lookup IP→País (MMDB/API) | Bloqueo por país |
| ASN / Proveedor | Lookup IP→ASN (MMDB/API) | Bloqueo por proveedor (hosting, VPN, datacenters) |
| Reverse DNS | Lookup PTR (con cache) | Verificación de crawlers legítimos (Googlebot, Bingbot) |
| Fingerprint de sesión | Hash de IP + User-Agent + Accept-Language | Agrupación de peticiones por "visitante" |
| Cuerpo del POST | `php://input` (solo en contextos sospechosos) | Detección de inyecciones |
| Query string | `QUERY_STRING` | Detección de inyecciones, path traversal |
| Cookies | `$_COOKIE` | Detección de sesiones WordPress activas |
| Headers completos | `getallheaders()` o `$_SERVER` | Detección de anomalías |

#### Clasificación del tipo de visita:
| Tipo | Criterio | Nivel de riesgo base |
|------|----------|---------------------|
| **Página normal** | URI sin patrones especiales | Bajo |
| **Recurso estático** | `.css`, `.js`, `.jpg`, `.png`, etc. | Ninguno (no procesar) |
| **Login** | `/wp-login.php`, `/wp-admin/` sin cookie auth | Alto |
| **XML-RPC** | `/xmlrpc.php` | Alto |
| **REST API** | `/wp-json/` | Medio |
| **WP-Cron** | `/wp-cron.php` | Medio |
| **Feed** | `/feed/`, `/rss/` | Bajo |
| **Admin AJAX** | `/wp-admin/admin-ajax.php` | Medio |
| **Archivo no existente** | URI que resulta en 404 | Medio-Alto |
| **Ruta sospechosa** | `/wp-config.php`, `/.env`, `/debug.log`, `/vendor/`, `/.git/` | Crítico |
| **Upload directo** | `/wp-content/uploads/` con extensiones ejecutables | Crítico |

#### Clasificación humano vs. bot:
| Señal | Peso | Tipo |
|-------|------|------|
| User-Agent de bot conocido (Google, Bing, etc.) | Alto | Bot legítimo (verificar con rDNS) |
| User-Agent vacío o genérico ("Mozilla/5.0") | Medio | Sospechoso |
| User-Agent de herramienta (curl, wget, python-requests, Go-http-client) | Alto | Bot/herramienta |
| Tasa de peticiones > N/minuto | Alto | Bot probable |
| No carga recursos estáticos (CSS/JS/imágenes) | Medio | Bot probable |
| Cookie de WordPress presente y válida | Alto | Humano autenticado |
| Patrón de navegación lineal (sin ramificación) | Bajo | Bot probable |
| Accept-Language presente y coherente | Bajo | Humano probable |
| JavaScript fingerprint (si se implementa) | Alto | Humano confirmado |

### 2.2 Detección de Ataques

#### 2.2.1 Fuerza Bruta en Login
- Contar intentos fallidos por IP en ventana de tiempo configurable
- Contar intentos con **usuario inexistente** (indicador fuerte de ataque)
- Bloqueo progresivo: primero temporal (15 min), luego escalado (1h, 24h, permanente)
- Opción: bloqueo inmediato si el usuario no existe en el sistema
- Opción: limitar login solo a IPs en whitelist

#### 2.2.2 Abuso de XML-RPC
- `xmlrpc.php` es vector de ataque común (pingback DDoS, fuerza bruta multicanal)
- Opciones: 
  - Bloquear completamente (recomendado para la mayoría de sitios)
  - Bloquear métodos específicos (pingback, system.multicall)
  - Permitir solo desde IPs en whitelist

#### 2.2.3 Inyección SQL (SQLi)
- Análisis de `QUERY_STRING`, `POST body`, `Cookie values` y `URI`
- Patrones a detectar:
  - `UNION SELECT`, `UNION ALL SELECT`
  - `OR 1=1`, `AND 1=1`, `' OR '`
  - `DROP TABLE`, `INSERT INTO`, `UPDATE...SET`
  - `SLEEP(`, `BENCHMARK(`, `WAITFOR`
  - Comentarios SQL: `--`, `/**/`, `#`
  - Funciones peligrosas: `LOAD_FILE(`, `INTO OUTFILE`, `INTO DUMPFILE`
  - Encodings alternativos: hex, URL-encoded, double-encoded
- **Importante:** Minimizar falsos positivos. No analizar peticiones de usuarios autenticados como administradores en el panel de WordPress (pueden tener contenido legítimo con sintaxis SQL).

#### 2.2.4 Cross-Site Scripting (XSS)
- Patrones en parámetros de entrada:
  - `<script`, `javascript:`, `onerror=`, `onload=`, `eval(`
  - Encodings alternativos: HTML entities, Unicode escapes
- Solo en parámetros de usuario, no en respuestas

#### 2.2.5 Path Traversal / File Inclusion
- Patrones: `../`, `..%2f`, `..%255c`, `/etc/passwd`, `/proc/self`
- Acceso directo a archivos sensibles: `.env`, `wp-config.php`, `.htaccess`, `debug.log`

#### 2.2.6 Escaneo de Vulnerabilidades
- Detección de herramientas conocidas por User-Agent y patrones de comportamiento:
  - WPScan, Nikto, sqlmap, Acunetix, Nessus, Burp Suite
- Accesos rápidos y secuenciales a rutas conocidas de vulnerabilidades
- Intentos de acceso a plugins/themes no instalados

#### 2.2.7 REST API  
- Enumeración de usuarios vía `/wp-json/wp/v2/users`
- Acceso no autenticado a endpoints sensibles
- Opción de desactivar la REST API para usuarios no autenticados (con excepciones configurables)

### 2.3 Sistema de Bloqueo

#### Tipos de bloqueo:
| Tipo | Granularidad | Ejemplo |
|------|-------------|---------|
| **IP individual** | Una IP específica | `192.168.1.100` |
| **Rango CIDR** | Subred | `192.168.1.0/24` |
| **Rango arbitrario** | Desde-hasta | `192.168.1.1 - 192.168.1.50` |
| **País** | Código ISO 3166-1 | `CN`, `RU`, `KP` |
| **ASN** | Número de sistema autónomo | `AS14061` (DigitalOcean), `AS16509` (Amazon AWS) |
| **User-Agent** | Coincidencia parcial o regex | `*python-requests*`, `*sqlmap*` |

#### Temporalidad del bloqueo:
| Duración | Uso |
|----------|-----|
| Temporal automático | Resultado de detección de ataque (configurable: 15m, 1h, 24h) |
| Escalado automático | Reincidencia incrementa duración exponencialmente |
| Permanente manual | Administrador bloquea explícitamente |
| Permanente automático | Tras N bloqueos temporales del mismo origen |

#### Respuesta al bloqueo:
- HTTP 403 Forbidden con página mínima (sin cargar WordPress)
- Header `Retry-After` para bloqueos temporales
- Opcionalmente: HTTP 503 (para simular mantenimiento) o HTTP 444 (cerrar conexión sin respuesta, estilo Nginx)
- Logging del intento bloqueado con detalle mínimo (IP, URI, razón, timestamp)

### 2.4 Whitelists

#### Whitelist global de IPs:
- IPs/rangos que nunca se bloquean
- Usar para: IP del administrador, servicios de monitoreo, IPs de oficina
- Se evalúa PRIMERO en cada petición (antes de cualquier regla)

#### Whitelist para login:
- IPs desde las cuales se permite acceder a `wp-login.php` y `wp-admin`
- Si está activa, cualquier acceso desde IP no listada recibe 403 directo
- Opción de auto-agregar la IP actual del administrador al configurar

#### Whitelist de bots verificados:
- Verificación de crawlers legítimos por reverse DNS:
  - Googlebot → `*.googlebot.com` / `*.google.com`
  - Bingbot → `*.search.msn.com`
  - Otros crawlers verificables
- Se verifica User-Agent + rDNS para evitar spoofing

### 2.5 Rate Limiting

Independiente de los detectores de ataque específicos, un limitador general de tasa:

| Parámetro | Default | Descripción |
|-----------|---------|-------------|
| Peticiones por IP por minuto (páginas) | 60 | Peticiones a URIs que generan carga de WordPress |
| Peticiones por IP por minuto (total) | 240 | Incluyendo recursos estáticos |
| Peticiones a wp-login.php por IP por hora | 5 | Intentos de login |
| Peticiones a xmlrpc.php por IP por hora | 0 | Deshabilitado por defecto |
| Peticiones 404 por IP por minuto | 10 | Indicador de escaneo |

Cuando se excede el límite → bloqueo temporal automático.

---

## 3. Base de Datos

### 3.1 Principio: Tablas Propias

**No usar `wp_options` ni ninguna tabla nativa de WordPress** para datos operativos del plugin. Razones:
- `wp_options` con autoload es un cuello de botella conocido
- Las tablas de WordPress no están diseñadas para datos de alta frecuencia de escritura
- El plugin debe poder operar incluso cuando WordPress está parcialmente cargado

**Prefijo de tablas:** `wps_` (configurable en instalación para evitar colisiones)

### 3.2 Esquema de Tablas

#### `wps_settings`
Configuración del plugin. Se carga una vez y se cachea.
```sql
CREATE TABLE wps_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value LONGTEXT NOT NULL,
    autoload TINYINT(1) DEFAULT 1,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_blocked_ips`
IPs y rangos bloqueados activos.
```sql
CREATE TABLE wps_blocked_ips (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NULL,              -- IP individual (IPv4 o IPv6)
    ip_range_start VARBINARY(16) NULL,        -- Inicio de rango (binario para comparación eficiente)
    ip_range_end VARBINARY(16) NULL,          -- Fin de rango
    cidr VARCHAR(49) NULL,                    -- Notación CIDR original si aplica
    block_type ENUM('manual','auto_login','auto_xmlrpc','auto_sqli','auto_xss','auto_rate','auto_scanner','auto_traversal') NOT NULL,
    reason VARCHAR(500) NOT NULL,
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,                 -- NULL = permanente
    hit_count INT UNSIGNED DEFAULT 0,         -- Veces que intentó acceder estando bloqueado
    is_active TINYINT(1) DEFAULT 1,
    INDEX idx_ip (ip_address),
    INDEX idx_range (ip_range_start, ip_range_end),
    INDEX idx_expires (expires_at),
    INDEX idx_active (is_active, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_blocked_countries`
Países bloqueados.
```sql
CREATE TABLE wps_blocked_countries (
    country_code CHAR(2) PRIMARY KEY,         -- ISO 3166-1 alpha-2
    country_name VARCHAR(100) NOT NULL,
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    blocked_by VARCHAR(100) DEFAULT 'admin'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_blocked_asns`
ASNs bloqueados.
```sql
CREATE TABLE wps_blocked_asns (
    asn INT UNSIGNED PRIMARY KEY,             -- Número ASN sin prefijo "AS"
    asn_name VARCHAR(255) NOT NULL,
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    blocked_by VARCHAR(100) DEFAULT 'admin'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_whitelist`
IPs/rangos en lista blanca.
```sql
CREATE TABLE wps_whitelist (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NULL,
    cidr VARCHAR(49) NULL,
    label VARCHAR(255) NOT NULL,              -- Descripción: "IP oficina", "Mi casa", etc.
    whitelist_type ENUM('global','login') NOT NULL DEFAULT 'global',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_type (whitelist_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_traffic_log`
Registro de peticiones (tabla de alto volumen).
```sql
CREATE TABLE wps_traffic_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    country_code CHAR(2) NULL,
    asn INT UNSIGNED NULL,
    request_uri VARCHAR(2048) NOT NULL,
    request_method VARCHAR(10) NOT NULL,
    user_agent VARCHAR(1024) NULL,
    referer VARCHAR(2048) NULL,
    http_status SMALLINT UNSIGNED NULL,
    is_human TINYINT(1) NULL,                 -- NULL=no determinado, 1=humano, 0=bot
    visitor_type ENUM('page','login','xmlrpc','restapi','admin','ajax','cron','feed','static','unknown') NOT NULL DEFAULT 'unknown',
    session_hash VARCHAR(64) NULL,            -- Fingerprint de sesión
    response_time_ms INT UNSIGNED NULL,       -- Tiempo de respuesta en milisegundos
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_time (ip_address, created_at),
    INDEX idx_created (created_at),
    INDEX idx_type (visitor_type, created_at),
    INDEX idx_session (session_hash, created_at),
    INDEX idx_country (country_code, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_security_events`
Eventos de seguridad (ataques detectados, bloqueos ejecutados).
```sql
CREATE TABLE wps_security_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type ENUM('login_failed','login_blocked','login_success','xmlrpc_blocked','sqli_detected','xss_detected','traversal_detected','rate_limited','scanner_detected','country_blocked','asn_blocked','ip_blocked','whitelist_bypass','manual_block','manual_unblock','settings_changed') NOT NULL,
    severity ENUM('info','warning','critical') NOT NULL DEFAULT 'warning',
    ip_address VARCHAR(45) NULL,
    country_code CHAR(2) NULL,
    asn INT UNSIGNED NULL,
    details TEXT NULL,                        -- JSON con detalles específicos del evento
    request_uri VARCHAR(2048) NULL,
    user_agent VARCHAR(1024) NULL,
    wp_user_id BIGINT UNSIGNED NULL,          -- Si aplica (login exitoso, cambio de config)
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type_time (event_type, created_at),
    INDEX idx_severity_time (severity, created_at),
    INDEX idx_ip_time (ip_address, created_at),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_login_attempts`
Tabla específica para tracking de intentos de login (para rate limiting preciso).
```sql
CREATE TABLE wps_login_attempts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(255) NOT NULL,
    user_exists TINYINT(1) NOT NULL,          -- Si el usuario existe en WordPress
    success TINYINT(1) NOT NULL DEFAULT 0,
    attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_time (ip_address, attempted_at),
    INDEX idx_user_time (username, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

#### `wps_rate_limits`  
Contadores de rate limiting (tabla de alta frecuencia, registros de corta vida).
```sql
CREATE TABLE wps_rate_limits (
    ip_address VARCHAR(45) NOT NULL,
    limit_type VARCHAR(30) NOT NULL,          -- 'page', 'total', 'login', 'xmlrpc', '404'
    window_start DATETIME NOT NULL,           -- Inicio de la ventana temporal
    request_count INT UNSIGNED DEFAULT 1,
    PRIMARY KEY (ip_address, limit_type, window_start),
    INDEX idx_window (window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```
> **Nota de rendimiento:** Esta tabla tiene actualizaciones muy frecuentes. Considerar usar tabla MEMORY como alternativa si el servidor lo soporta, con respaldo periódico a disco. También se puede manejar con archivos cache en disco si se busca eliminardependencia de BD para rate limiting.

### 3.3 Mantenimiento de Base de Datos

Tarea programada (WP-Cron o cron real del sistema):

| Tarea | Frecuencia | Descripción |
|-------|-----------|-------------|
| Purgar logs de tráfico | Diaria | Eliminar registros mayores a N días (configurable, default: 30) |
| Purgar eventos de seguridad | Semanal | Eliminar registros mayores a N días (configurable, default: 90) |
| Purgar intentos de login | Diaria | Eliminar registros mayores a 7 días |
| Purgar rate limits expirados | Cada hora | Eliminar ventanas temporales pasadas |
| Desbloquear IPs expiradas | Cada 5 minutos | Desactivar bloqueos temporales cuyo `expires_at` ya pasó |
| Optimizar tablas | Semanal | `OPTIMIZE TABLE` en tablas de alto volumen |
| Sincronizar archivo de bloqueo (Capa 0) | Cada 5 minutos | Regenerar el archivo plano de IPs bloqueadas desde la BD |

### 3.4 Base de Datos IP Local (ipinfo.io)

#### Opción A: API en línea (modo básico)
- Consultar `https://ipinfo.io/{ip}?token={api_key}` por cada IP nueva
- Cachear resultado en tabla local o archivo por N horas
- **Ventaja:** sin almacenamiento local, siempre actualizado
- **Desventaja:** latencia, dependencia de servicio externo, límites de API

#### Opción B: Base de datos local MMDB (modo recomendado)
- Descargar la base de datos de ipinfo.io en formato MMDB (MaxMind DB)
- Bases de datos disponibles de ipinfo.io:
  - **Country** (~10 MB): IP → País
  - **ASN** (~20 MB): IP → ASN + nombre del proveedor
  - **Country + ASN** (~25 MB): Combinada (la ideal para este plugin)
- Usar librería PHP `maxmind-db/reader` (pura PHP, sin extensiones C requeridas)
- Lookups locales en ~microsegundos vs ~100ms de la API
- **Actualización:** configurable, recomendado mensual. Descargar desde la API de ipinfo.io con token

#### Implementación propuesta:
1. En la **instalación** del plugin, ofrecer dos modos:
   - **Modo API:** solo requiere API key; consultas en vivo con cache
   - **Modo Local:** descarga la base de datos MMDB automáticamente (requiere API key con permisos de descarga)
2. En **configuración**, permitir cambiar entre modos
3. Botón de **actualización manual** + actualización automática periódica (cron)
4. Mostrar fecha de última actualización y tamaño de la base de datos en el panel
5. **Fallback:** si la base de datos local falla, usar API como respaldo

#### Almacenamiento:
```
wp-secure/data/
├── .htaccess              # Deny from all
├── ipinfo-country-asn.mmdb    # Base de datos combinada
└── wps-blocked-ips.php    # Array serializado para Capa 0 (auto_prepend_file)
```

---

## 4. Módulos del Plugin

### 4.1 Detector de Sesiones

**Propósito:** Rastrear la actividad de cada visitante como una "sesión" cohesiva.

- Generar un `session_hash` basado en: IP + User-Agent + Accept-Language
- No usar cookies para tracking (el plugin opera antes de WordPress en muchos casos)
- Agrupar peticiones del mismo hash para mostrar la actividad de un visitante
- Determinar si el visitante es humano o bot en base al patrón acumulado
- Expiración de sesión: 30 minutos sin actividad

**Datos de sesión:**
- IP de origen
- País / ASN / Proveedor
- User-Agent
- Páginas visitadas (lista de URIs con timestamps)
- Clasificación: humano / bot conocido / bot desconocido / atacante
- Duración
- Acciones de seguridad aplicadas (bloqueos, alertas)

### 4.2 Identificador de Riesgos/Ataques

**Propósito:** Asignar un nivel de riesgo a cada petición y sesión.

Sistema de puntuación:
| Factor | Puntos |
|--------|--------|
| IP de datacenter/hosting/VPN | +10 |
| País en lista de alto riesgo (configurable) | +15 |
| User-Agent vacío | +20 |
| User-Agent de herramienta | +25 |
| Tasa de peticiones elevada | +20 |
| Acceso a ruta sospechosa | +30 |
| Intento de login fallido | +15 por intento |
| Acceso a xmlrpc.php | +20 |
| Patrón de SQLi detectado | +50 |
| Patrón de XSS detectado | +40 |
| Patrón de path traversal | +40 |
| Petición con user inexistente | +25 |
| Múltiples errores 404 | +5 por error |

**Umbrales:**
| Puntuación | Acción |
|-----------|--------|
| 0-30 | Sin acción |
| 31-50 | Registro en log como sospechoso |
| 51-80 | Alta vigilancia, rate limiting estricto |
| 81-100 | Bloqueo temporal (configurable) |
| >100 | Bloqueo inmediato |

### 4.3 Log de Eventos

**Propósito:** Registro organizado de todos los eventos de seguridad.

- **Niveles:** info, warning, critical
- **Formato de almacenamiento:** tabla `wps_security_events` con columna `details` en JSON
- **Retención:** configurable (default 90 días)
- **Exportación:** CSV desde el panel de administración
- **Búsqueda:** por tipo, IP, país, rango de fechas, severidad

### 4.4 Definición de Reglas

**Propósito:** Permitir al administrador crear reglas personalizadas de bloqueo/permiso.

Reglas predefinidas (activables/desactivables):
| Regla | Default | Descripción |
|-------|---------|-------------|
| Bloquear login con usuario inexistente | ON | Bloqueo inmediato si se intenta login con un nombre de usuario que no existe |
| Bloquear XML-RPC completo | ON | Bloquear todo acceso a xmlrpc.php |
| Bloquear enumeración de usuarios REST | ON | Bloquear `/wp-json/wp/v2/users` para no autenticados |
| Bloquear acceso directo a wp-config.php | ON | Siempre |
| Desactivar REST API para no autenticados | OFF | Solo permitir REST API a usuarios logueados |
| Forzar HTTPS en login | ON | Redirigir login a HTTPS si no lo es |
| Ocultar versión de WordPress | ON | Eliminar meta generator |
| Bloquear acceso a archivos .sql | ON | Desde la web |
| Bloquear archivos de respaldo (.bak, .old, .orig) | ON | Desde la web |
| Bloquear ejecución PHP en /uploads/ | ON | Prevenir shells subidos |

### 4.5 Visor de Visitas en Vivo

**Propósito:** Mostrar en tiempo real el tráfico del sitio.

**Implementación técnica:**
- Polling AJAX cada 5 segundos (más compatible) o WebSocket (mejor rendimiento)
- Consulta los últimos N registros de `wps_traffic_log` con timestamp > última consulta
- Filtros en vivo: por tipo de tráfico, país, estado de bloqueo, humano/bot

**Columnas del visor:**
| Columna | Dato |
|---------|------|
| Hora | Timestamp de la petición |
| IP | Dirección IP (con link a detalle) |
| País | Bandera + código |
| Proveedor | ASN + nombre |
| Tipo | Icono de clasificación (humano/bot/bloqueado) |
| Método | GET/POST/etc. |
| URI | Ruta solicitada |
| Status | Código HTTP de respuesta |
| User-Agent | Abreviado |
| Acciones | Botones: bloquear IP, whitelistear, ver detalle |

**Vista de detalle de IP:**
- Todas las peticiones de esa IP (paginadas)
- Geolocalización completa
- ASN y proveedor
- Reverse DNS
- Historial de bloqueos
- Puntuación de riesgo actual
- Acciones: bloquear IP, bloquear rango /24, bloquear ASN, bloquear país, agregar a whitelist

### 4.6 Visor de Bloqueos

**Propósito:** Panel de gestión de todos los bloqueos activos y su historial.

**Secciones:**
1. **Bloqueos activos:** tabla de IPs/rangos/países/ASNs bloqueados con opción de desbloquear
2. **Bloqueos expirados:** historial de bloqueos temporales que ya vencieron
3. **Estadísticas:** gráficas de bloqueos por tipo, por día, por país
4. **Acciones masivas:** desbloquear todos los temporales, desbloquear por tipo

---

## 5. Reglas y Configuraciones

### 5.1 Configuración General

```
[API y Datos]
• API Key ipinfo.io: _____________
• Modo de datos: ○ API en línea  ○ Base de datos local (MMDB)
• Última actualización MMDB: 2026-02-15 (botón: Actualizar ahora)

[Protección de Login]
• Intentos máximos antes de bloqueo temporal: [5]
• Duración del bloqueo temporal (minutos): [15]
• Escalar bloqueo tras N bloqueos temporales: [3] → bloqueo de [24] horas
• Bloqueo permanente tras N bloqueos escalados: [3]
• Bloquear IP inmediatamente si el usuario no existe: ☑
• Limitar login solo a IPs en whitelist: ☐

[XML-RPC]
• Bloquear XML-RPC completamente: ☑
• (Si no bloqueado) Bloquear métodos: ☑ pingback  ☑ system.multicall
• Permitir XML-RPC solo desde whitelist: ☐

[REST API]
• Bloquear enumeración de usuarios: ☑
• Desactivar REST API para no autenticados: ☐
• Excepciones de namespaces REST: [contact-form-7, woocommerce]

[Rate Limiting]
• Peticiones por IP / minuto (páginas): [60]
• Peticiones totales por IP / minuto: [240]
• Errores 404 por IP / minuto: [10]
• Duración del bloqueo por rate limit (minutos): [15]

[Bloqueo por País]
• Países bloqueados: [selector múltiple con banderas y nombres]

[Bloqueo por ASN]
• ASNs bloqueados: [buscador por número o nombre de proveedor]

[Apariencia del Bloqueo]
• Código HTTP de respuesta: ○ 403  ○ 503  ○ Cerrar conexión
• Mensaje personalizado: [textarea]

[Retención de Datos]
• Días de retención de logs de tráfico: [30]
• Días de retención de eventos de seguridad: [90]
• Días de retención de intentos de login: [7]

[Rendimiento]
• Habilitar Capa 0 (auto_prepend_file): ☑
• Intervalo de sincronización Capa 0 (minutos): [5]
• Excluir recursos estáticos del log: ☑

[Notificaciones]
• Email de notificación: [admin@sitio.com]
• Notificar bloqueos automáticos: ☐ (puede generar mucho email)
• Notificar intentos de login exitosos desde IP nueva: ☑
• Notificar cambios en la configuración del plugin: ☑
• Resumen diario de seguridad: ☑
```

### 5.2 Reglas Predefinidas (On/Off)

| ID | Regla | Default |
|----|-------|---------|
| R01 | Bloquear IP en intento de login con usuario inexistente | ON |
| R02 | Bloquear todo acceso a XML-RPC | ON |
| R03 | Bloquear enumeración de usuarios vía REST API | ON |
| R04 | Bloquear acceso directo a wp-config.php | ON (no desactivable) |
| R05 | Desactivar REST API para visitantes no autenticados | OFF |
| R06 | Forzar HTTPS en login | ON |
| R07 | Ocultar versión de WordPress | ON |
| R08 | Bloquear acceso a archivos .sql, .bak, .old, .orig, .log | ON |
| R09 | Bloquear ejecución PHP en wp-content/uploads/ | ON |
| R10 | Verificar crawlers conocidos con reverse DNS | ON |
| R11 | Bloquear User-Agents vacíos | OFF |
| R12 | Bloquear peticiones sin header Host | ON |
| R13 | Bloquear métodos HTTP no estándar (TRACE, TRACK, DELETE sin REST) | ON |

---

## 6. Panel de Administración

### 6.1 Menú Principal

```
WP Seguro
├── Dashboard          # Resumen general, estadísticas del día
├── Tráfico en Vivo    # Visor en tiempo real
├── Bloqueos           # Gestión de bloqueos activos
│   ├── IPs Bloqueadas
│   ├── Países Bloqueados
│   └── ASN Bloqueados
├── Whitelist          # Gestión de listas blancas
├── Eventos            # Log de seguridad
├── Reglas             # Activar/desactivar reglas
├── Firewall           # Estado de capas 0/1, diagnóstico
├── Base de Datos IP   # Estado MMDB, actualización
└── Configuración      # Todos los ajustes
```

### 6.2 Dashboard

Widgets del dashboard:

1. **Estado del Firewall**
   - Capa 0: ✅ Activa / ❌ No instalada / ⚠️ Desactualizada
   - Capa 1: ✅ Activa / ❌ No instalada
   - Base de datos IP: ✅ Actualizada / ⚠️ Desactualizada (fecha)

2. **Resumen de las últimas 24 horas**
   - Total de peticiones
   - Peticiones bloqueadas
   - IPs únicas
   - Intentos de login (éxitos / fallos)
   - Ataques detectados por tipo

3. **Top 10 IPs bloqueadas** (tabla)

4. **Top 10 Países por tráfico** (gráfico de barras)

5. **Actividad de las últimas 24h** (gráfico de líneas: peticiones/hora, bloqueos/hora)

6. **Últimos eventos críticos** (lista de los 10 más recientes)

### 6.3 Estilos y UX

- Diseño limpio, minimalista, alineado con el estilo de WordPress admin
- Colores de estado claros: verde (OK/permitido), rojo (bloqueado/ataque), amarillo (sospechoso/advertencia), gris (informativo)
- Tablas con paginación, ordenamiento y búsqueda
- Responsive (el admin de WP se usa desde móvil)
- Sin dependencias CSS/JS externas pesadas (no Bootstrap, no jQuery UI completo)
- Charts con librería ligera: Chart.js embebido (solo si se necesita, cargado solo en páginas del plugin)
- Iconos con Dashicons (incluidos en WordPress) o un set SVG mínimo propio

---

## 7. Seguridad del Propio Plugin

El plugin mismo debe ser seguro:

| Medida | Aplicación |
|--------|-----------|
| Nonce verification | Toda acción de formulario y AJAX en admin |
| Capability checks | Solo `manage_options` puede acceder al panel y cambiar configuración |
| Sanitización de entrada | Todos los datos del usuario se sanitizan con funciones de WordPress |
| Escape de salida | Todo dato mostrado se escapa con `esc_html()`, `esc_attr()`, `wp_kses()` |
| Prepared statements | Toda consulta SQL usa `$wpdb->prepare()` o equivalente con tablas propias |
| Directo acceso PHP | `defined('ABSPATH') || exit;` en cada archivo PHP |
| Protección de datos | `.htaccess` deny en directorio `data/` |
| API Key almacenada cifrada | Cifrar con `wp_salt()` antes de guardar |
| Sin eval/exec | No usar funciones de ejecución de código dinámico |
| Logs sin datos sensibles | No registrar contraseñas, tokens, ni cuerpos de POST completos |

---

## 8. Compatibilidad y Requisitos

| Elemento | Requisito |
|----------|-----------|
| WordPress | 6.0+ |
| PHP | 7.4+ (recomendado 8.0+) |
| MySQL/MariaDB | 5.7+ / 10.3+ |
| Servidores web | Apache (con mod_rewrite), Nginx (documentación para configuración manual) |
| Multisite | Compatible (cada sitio con su configuración independiente) |
| Plugins de cache | Compatible (el firewall opera antes del cache de página) |
| CDN/Proxy | Soporte para Cloudflare, Sucuri, otros (detección correcta de IP real) |
| IPv6 | Soporte completo |
| SSL | Recomendado, no requerido |

---

## 9. Internacionalización

- Todo string visible al usuario pasa por `__()` o `_e()` con dominio `wp-secure`
- Archivos de traducción `.po`/`.mo` para al menos:
  - Español (es_ES) — idioma principal
  - Inglés (en_US)
- Nombres de países en el idioma del admin
- Dates y números formateados según locale

---

## 10. Ciclo de Vida del Plugin

### 10.1 Activación
1. Verificar requisitos mínimos (versiones PHP, MySQL, WordPress)
2. Crear tablas propias en la base de datos
3. Instalar MU-Plugin (Capa 1) copiando archivo a `wp-content/mu-plugins/`
4. Intentar instalar Capa 0 (auto_prepend_file en `.htaccess` o `.user.ini`)
5. Crear directorio `data/` con `.htaccess` de protección
6. Configurar valores por defecto
7. Agregar tareas de cron para mantenimiento
8. Registrar evento de activación
9. Redirigir al wizard de configuración inicial

### 10.2 Desactivación
1. Desactivar Capa 0 (remover auto_prepend_file)
2. Remover MU-Plugin
3. Remover tareas de cron
4. **No borrar tablas ni datos** (el usuario puede reactivar)

### 10.3 Desinstalación
1. Todo lo de desactivación
2. **Eliminar todas las tablas propias** (con confirmación previa si es posible)
3. Eliminar directorio `data/`
4. Limpiar cualquier dato residual

### 10.4 Actualización
1. Ejecutar migraciones de esquema si hay cambios de versión
2. Actualizar archivos de MU-Plugin y Capa 0 si cambiaron
3. Regenerar archivo de bloqueo (Capa 0)

---

## 11. Wizard de Configuración Inicial

Al activar el plugin por primera vez, guiar al administrador:

1. **Bienvenida:** explicación breve del plugin
2. **API Key:** solicitar API key de ipinfo.io (con link para obtener una gratuita)
3. **Modo de datos:** elegir API en línea o descarga de MMDB
4. **Protección básica:** activar/desactivar reglas principales
5. **Whitelist inicial:** agregar la IP actual del administrador
6. **Resumen:** mostrar el estado del firewall y las protecciones activadas

---

## 12. Fases de Desarrollo

### Fase 1 — Fundación (MVP) ✅
- [x] Estructura del plugin, activación/desactivación
- [x] Modelo de datos (crear tablas)
- [x] Objeto Request (captura de datos de la petición)
- [x] IP Utils (validación, CIDR, IPv4/IPv6)
- [x] Logger básico
- [x] Panel de administración: estructura, menú, dashboard básico
- [x] Configuración básica (guardar/leer settings)

### Fase 2 — Detección y Bloqueo Básico ✅
- [x] Detector de login: intentos fallidos, bloqueo automático
- [x] Detector de XML-RPC: bloqueo completo
- [x] Bloqueo manual de IPs
- [x] Whitelist de IPs
- [x] Log de eventos básico
- [x] Visor de eventos en panel

### Fase 3 — Geolocalización y Bloqueo Avanzado ✅
- [x] Integración ipinfo.io (API mode)
- [x] Integración MMDB (local mode)
- [x] Bloqueo por país
- [x] Bloqueo por ASN
- [x] Bloqueo por rango CIDR
- [x] Panel: selectores de país/ASN

### Fase 4 — Firewall Avanzado ✅
- [x] Detector de SQLi
- [x] Detector de XSS
- [x] Detector de path traversal
- [x] Detector de scanners
- [x] Rate limiter
- [x] Sistema de puntuación de riesgo
- [x] Capa 0 (auto_prepend_file)
- [x] Capa 1 (MU-Plugin)

### Fase 5 — Experiencia de Usuario
- [x] Visor de tráfico en vivo
- [x] Dashboard completo con gráficas
- [x] Vista de detalle de IP
- [x] Wizard de configuración inicial
- [x] Notificaciones por email
- [x] Exportación de logs
- [x] Internacionalización (es/en)

### Fase 6 — Optimización y Hardening ✅
- [x] Verificación de crawlers por rDNS
- [x] Protección de REST API
- [x] Reglas de seguridad adicionales (headers, métodos HTTP)
- [x] Optimización de rendimiento (benchmarks, profiling)
- [x] Compatibilidad con CDN/proxies
- [x] Tests unitarios y de integración
- [x] Documentación para el usuario

---

## 13. Convenciones de Código

| Aspecto | Convención |
|---------|-----------|
| Estándar | WordPress Coding Standards (WPCS) |
| Prefijo de funciones | `wps_` |
| Prefijo de clases | `WPS_` |
| Prefijo de hooks | `wps/` (usar `/` como separador) |
| Prefijo de opciones DB | `wps_` |
| Prefijo de transients | `wps_` |
| Prefijo de nonces | `wps_` |
| Nombres de tabla | `{$wpdb->prefix}wps_*` |
| Constantes globales | `WPS_` (ej: `WPS_VERSION`, `WPS_PLUGIN_DIR`) |
| Text domain | `wp-secure` |
| Namespace PHP | No usar (compatibilidad con PHP 7.4 y estándar de WordPress) |
| Autoloading | Propio, no Composer (minimizar dependencias externas) |
| Formato de fecha en BD | `DATETIME` en UTC |
| Formato de IP en BD | `VARCHAR(45)` para legibilidad, `VARBINARY(16)` para comparaciones de rango |

---

## 14. Métricas de Éxito

El plugin será considerado exitoso si:

1. **Rendimiento:** añade menos de 5ms al tiempo de carga de una página normal (sin detección de ataque)
2. **Bloqueo de Capa 0:** una IP bloqueada se rechaza en menos de 1ms sin cargar WordPress
3. **Falsos positivos:** tasa menor al 0.1% en tráfico legítimo
4. **Capacidad de log:** soporta más de 100,000 registros de tráfico por día sin degradar el sitio
5. **Claridad:** un administrador no técnico puede entender el estado de seguridad del sitio en menos de 30 segundos mirando el dashboard
6. **Autonomía de datos:** el plugin no escribe ni lee de `wp_options` para datos operativos (solo la versión del plugin y estado de activación mínimo)

---

## 15. Riesgos y Mitigaciones

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| auto_prepend_file no disponible (hosting compartido) | Capa 0 no funciona, solo Capa 1 | Degradación elegante, informar al admin, funcionar solo con Capa 1 |
| Base de datos MMDB demasiado grande | Espacio en disco, tiempo de descarga | Ofrecer solo country+ASN (~25MB), no la base completa |
| Tablas de tráfico crecen mucho | Rendimiento de BD | Purga automática agresiva, índices optimizados, archivado opcional |
| Falsos positivos bloquean usuarios | Pérdida de accesibilidad | Whitelist prioritaria, puntuación conservadora por defecto, modo "solo log" inicial |
| Conflicto con otros plugins de seguridad | Doble interceptación, bloqueos mutuos | Detectar y advertir sobre Wordfence/iThemes/etc., guía de convivencia |
| El plugin se bloquea a sí mismo | Administrador no puede acceder | Whitelist automática de IP de admin, opción de desactivar via WP-CLI o archivo de escape |
| MU-Plugin no se puede escribir | Permisos de archivo | Instrucciones manuales, alerta en admin, funcionar sin MU-Plugin |
| Hosting no permite tablas personalizadas | No se puede instalar | Verificación en activación, error claro con requisitos |

---

*Documento generado como plan de proyecto. Siguiente paso: revisión del plan y priorización de la Fase 1 para comenzar desarrollo.*
