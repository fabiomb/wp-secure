# Registro de Cambios

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
