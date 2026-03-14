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
│  ¿IP en lista negra? → 403  │
│  ¿IP en whitelist?   → OK   │
│  No decidido → continuar     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  Capa 1: MU-Plugin          │  ← Antes de plugins (< 5ms)
│  mu-plugins/wps-firewall.php │
├─────────────────────────────┤
│  Análisis de petición        │
│  Detección de patrones       │
│  Rate limiting               │
│  Puntuación de riesgo        │
│  ¿Bloquear? → 403           │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  Capa 2: Plugin Principal    │  ← Carga normal de WordPress
│  wp-secure.php               │
├─────────────────────────────┤
│  Dashboard                   │
│  Configuración               │
│  Reportes y logs             │
│  Gestión de reglas           │
└─────────────────────────────┘
```

---

## Capa 0 — Firewall PHP

### ¿Qué es?

La Capa 0 usa la directiva `auto_prepend_file` de PHP para ejecutar un script **antes** de que WordPress se cargue. Esto permite rechazar IPs bloqueadas en menos de 1 milisegundo, sin consumir recursos de WordPress ni de la base de datos.

### ¿Qué hace?

- Consulta un archivo de datos en disco con las IPs actualmente bloqueadas.
- Si la IP está bloqueada → responde con HTTP 403 inmediatamente.
- Si la IP está en whitelist → permite sin más verificaciones.
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

Un Must-Use Plugin (MU-Plugin) se carga antes que los plugins convencionales y los temas. WP Seguro instala un pequeño archivo en `wp-content/mu-plugins/` que inicia el análisis de seguridad temprano en el ciclo de WordPress.

### ¿Qué hace?

- Clasifica el tipo de petición (login, XML-RPC, REST API, admin, página, recurso estático).
- Ejecuta todas las reglas de detección:
  - Inyección SQL (SQLi)
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Scanners y herramientas automatizadas
  - Fuerza bruta en login
  - Abuso de XML-RPC
- Evalúa el rate limiting.
- Calcula la puntuación de riesgo acumulada.
- Decide bloquear o permitir según umbrales configurados.
- Registra eventos y tráfico en la base de datos del plugin.

### Ventajas

- Se ejecuta antes que otros plugins → no hay interferencia.
- Tiene acceso completo a la base de datos → reglas complejas.
- La mayoría de atacantes son bloqueados aquí, antes de que WordPress procese la petición.

### Activación

El asistente de configuración inicial ofrece instalar el MU-Plugin automáticamente. También se puede activar desde **WP Seguro → Configuración → General**.

---

## Capa 2 — Plugin Principal

### ¿Qué es?

El plugin convencional que proporciona la interfaz de administración. Solo se carga en el contexto de `/wp-admin/`.

### ¿Qué hace?

- Dashboard con estadísticas y gráficas.
- Configuración de todas las reglas y ajustes.
- Visor de tráfico en tiempo real.
- Gestión de whitelist y bloqueos manuales.
- Detalle de IP con historial de eventos.
- Exportación de datos (CSV).
- Gestión de la base de datos MMDB (geolocalización).

### Nota sobre rendimiento

La Capa 2 solo se activa en el panel de administración. Las páginas públicas del sitio no cargan ningún código de esta capa, asegurando cero impacto en el rendimiento para los visitantes.

---

## Degradación Elegante

WP Seguro está diseñado para funcionar incluso si no todas las capas están activas:

| Capas activas | Nivel de protección | Nota |
|---------------|---------------------|------|
| 0 + 1 + 2 | Máximo | Configuración completa recomendada |
| 1 + 2 | Alto | Suficiente para la mayoría de sitios |
| Solo 2 | Básico | Sin interceptación temprana, pero dashboard y reglas funcionan |

El plugin detecta automáticamente qué capas están activas y muestra el estado en el dashboard.
