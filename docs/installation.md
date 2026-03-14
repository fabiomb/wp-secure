# Instalación

## Requisitos del Sistema

| Requisito | Mínimo | Recomendado |
|-----------|--------|-------------|
| PHP | 7.4 | 8.0+ |
| WordPress | 6.0 | Última versión |
| MySQL | 5.7 | 8.0 |
| MariaDB | 10.3 | 10.6+ |

### Extensiones PHP Requeridas

- `mbstring` — Manejo de cadenas multibyte para detección de patrones.
- `json` — Procesamiento de datos JSON.
- `mysqli` — Conexión a base de datos.

### Extensiones PHP Opcionales

- `gd` o `imagick` — Para generación de gráficas en el dashboard.
- `zip` — Para importación/exportación de configuraciones.

## Instalación Manual

1. Descarga el archivo `.zip` del plugin.
2. Ve a **Plugins → Añadir nuevo → Subir plugin**.
3. Selecciona el archivo `.zip` y pulsa **Instalar ahora**.
4. Activa el plugin.

### Instalación por FTP

1. Descomprime el archivo `.zip` en tu equipo.
2. Sube la carpeta `wp-secure/` a `wp-content/plugins/`.
3. Ve a **Plugins** en el panel de administración y activa **WP Seguro**.

## Configuración Inicial

Al activar el plugin por primera vez, se mostrará un **asistente de configuración** que te guiará por los ajustes básicos:

1. **Nivel de protección** — Elige entre Bajo, Medio o Alto.
2. **Whitelist de IP** — Tu IP actual se añade automáticamente.
3. **Notificaciones** — Configura el email para alertas de seguridad.
4. **REST API** — Decide si bloquear el acceso público a la API REST.
5. **CDN/Proxy** — Selecciona tu proveedor si usas uno (Cloudflare, Sucuri, etc.).

## Activación de Capas

### Capa 2 (Plugin Principal)

Se activa automáticamente al instalar el plugin. No requiere configuración adicional.

### Capa 1 (MU-Plugin)

WP Seguro puede instalar un micro-plugin en `wp-content/mu-plugins/` para interceptar tráfico antes de que se carguen los demás plugins. El asistente de configuración lo ofrece automáticamente.

Para instalación manual:
1. Copia `wp-secure/includes/firewall/wps-muplugin.php` a `wp-content/mu-plugins/wps-firewall.php`.
2. Verifica que los permisos del archivo sean correctos (644).

### Capa 0 (Firewall PHP)

Para máximo rendimiento, WP Seguro puede interceptar peticiones antes de que WordPress se cargue. Requiere acceso a la configuración de PHP:

**Apache (.htaccess):**
```
php_value auto_prepend_file "/ruta/a/wp-content/plugins/wp-secure/includes/firewall/wps-firewall-prepend.php"
```

**Nginx (php.ini o pool config):**
```ini
auto_prepend_file = /ruta/a/wp-content/plugins/wp-secure/includes/firewall/wps-firewall-prepend.php
```

**Nota:** En hosting compartido, esta opción puede no estar disponible. La Capa 1 proporciona protección suficiente para la mayoría de sitios.

## Desinstalación

Al desactivar el plugin, las tablas de datos se conservan por seguridad. Al **desinstalar** (eliminar) el plugin:

1. Se eliminan todas las tablas de la base de datos (`wps_*`).
2. Se elimina el MU-Plugin si fue instalado.
3. Se eliminan las directivas de auto_prepend_file si fueron añadidas.
4. Se eliminan los transients del cache.

Para conservar los datos antes de desinstalar, usa la función de **Exportación CSV** en el dashboard.
