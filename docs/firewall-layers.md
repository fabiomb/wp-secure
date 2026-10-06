# Capas del Firewall

WP Seguro utiliza una arquitectura de tres capas para interceptar tráfico malicioso lo más temprano posible, minimizando el impacto en rendimiento.

---

## Visión General

```
Petición HTTP entrante
    │
    ▼
┌─────────────────────────────┐
│  Capa 0: Firewall PHP       │  ← Antes de WordPress (< 1ms)
│  auto_prepend_file           │
├─────────────────────────────┤
│  ¿PHP en uploads?    → 403  │
│  ¿IP en whitelist?   → OK   │
│  ¿IP en lista negra? → 403  │
│  No decidido → continuar     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  Capa 1: MU-Plugin          │  ← Antes de plugins (< 5ms)
│  wps-firewall-muplugin.php   │
├─────────────────────────────┤
│  ¿IP bloqueada?      → 403  │
│  Rutas trampa                │
│  Rate limiting               │
│  ¿Bloquear? → 403           │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  Capa 2: Plugin Principal    │  ← Carga normal, en init
│  wp-secure.php               │
├─────────────────────────────┤
│  Detectores de ataques       │
│  Motor de riesgo             │
│  Headers y reglas de método  │
│  Registro de tráfico/eventos │
│  Panel de administración     │
└─────────────────────────────┘
```

---

## Capa 0 — Firewall PHP

### ¿Qué es?

La Capa 0 usa la directiva `auto_prepend_file` de PHP para ejecutar un script **antes** de que WordPress se cargue. Esto permite rechazar IPs bloqueadas en menos de 1 milisegundo, sin consumir recursos de WordPress ni de la base de datos.

### ¿Qué hace?

- Consulta un archivo de datos en disco con las IPs actualmente bloqueadas.
- Si «PHP en uploads» está activo y el script pedido está en la carpeta de subidas → HTTP 403, para cualquier IP.
- Si la IP está en whitelist → permite sin más verificaciones.
- Si la IP está bloqueada → responde con HTTP 403 inmediatamente.
- Si no hay decisión → pasa a la Capa 1.

### Limitaciones

- Solo trabaja con datos en archivo plano (no base de datos).
- No puede ejecutar reglas complejas ni detección de patrones.
- Requiere acceso a la configuración del servidor (`php.ini`, `.htaccess`, o pool de FPM).
- En hosting compartido puede no estar disponible.

### Activación

Ver [Instalación — Capa 0](installation.md#capa-0-firewall-php).

---

## Capa 1 — MU-Plugin

### ¿Qué es?

Un Must-Use Plugin (MU-Plugin) se carga antes que los plugins convencionales y los temas. WP Seguro instala un pequeño archivo en `wp-content/mu-plugins/` que corta lo que ya se sabe que hay que cortar antes de que carguen los plugins y el tema.

### ¿Qué hace?

- Exime al propio servidor (cron, loopbacks) y a la whitelist.
- Si la IP (o su red, en IPv6) está bloqueada → HTTP 403.
- Rutas trampa (`/.env`, copias de `wp-config.php`, `/.git/`…): bloquea a quien las pide. Sin sesión iniciada; con sesión lo decide la Capa 2 con los permisos reales.
- Rate limiting de peticiones totales y de páginas, también sin sesión iniciada.

Los detectores de patrones y el motor de riesgo **no** corren acá: necesitan WordPress completo (usuario actual, ajustes, `init`) y corren en la Capa 2.

### Ventajas

- Se ejecuta antes que otros plugins → no hay interferencia y el costo es mínimo.
- Un atacante ya bloqueado, o que pide una ruta trampa, se descarta antes de cargar plugins y tema.

### Activación

El asistente de configuración inicial ofrece instalar el MU-Plugin automáticamente. También se puede activar desde **WP Seguro → Configuración → General**.

---

## Capa 2 — Plugin Principal

### ¿Qué es?

El plugin convencional. Se carga en **todas** las peticiones que pasan por WordPress, públicas y del panel: ahí corre la detección y, en el panel, la administración.

### ¿Qué hace?

En cada petición (en `init`):

- Bloqueo por país o ASN, si hay geolocalización configurada.
- Detectores: inyección SQL, XSS, path traversal, escáneres, login (fuerza bruta, usuarios inexistentes, enumeración), XML-RPC y REST API.
- Reglas de métodos HTTP, User-Agent vacío y Host ausente; headers de seguridad, HSTS y CSP.
- Motor de puntuación de riesgo (si está en modo sombra o activo).
- Protección de formularios, límite de búsquedas y rutas trampa con los permisos reales del usuario.
- Registro de tráfico y de eventos.

En segundo plano y en el panel:

- Mantenimiento programado: purga de registros, monitor de integridad, PHP en uploads, resúmenes por mail.
- Dashboard, tráfico en vivo, bloqueos, whitelist, eventos, configuración, reglas y exportación.
- Geolocalización opcional (ipinfo.io o MaxMind GeoLite2) y descarga de sus bases MMDB.

### Nota sobre rendimiento

Lo que más pesa en cada petición es el registro de tráfico (una escritura) y, si está encendido, el motor de riesgo (dos consultas). En sitios con mucho tráfico, «Registro de tráfico» permite muestreo ([ver Configuración](configuration.md#registro-de-tráfico-en-sitios-con-mucho-tráfico)). Las IPs ya bloqueadas se descartan en las Capas 0 y 1, antes de llegar acá.

---

## Degradación Elegante

WP Seguro está diseñado para funcionar incluso si no todas las capas están activas:

| Capas activas | Nivel de protección | Nota |
|---------------|---------------------|------|
| 0 + 1 + 2 | Máximo | Configuración completa recomendada |
| 1 + 2 | Alto | Suficiente para la mayoría de sitios |
| Solo 2 | Básico | Detección completa, pero los bloqueados se descartan recién con WordPress y los plugins cargados |

El plugin detecta automáticamente qué capas están activas y muestra el estado en el dashboard.
