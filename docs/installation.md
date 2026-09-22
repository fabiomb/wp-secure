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

1. **API y geolocalización** — Token de ipinfo.io y base de datos local de países/ASN.
2. **Login y XML-RPC** — Intentos máximos, duración de bloqueos y bloqueo de XML-RPC.
3. **Rate limiting** — Límites de peticiones por minuto.
4. **Whitelist** — Ofrece agregar tu IP actual (marcado por defecto).

## Activación de Capas

### Capa 2 (Plugin Principal)

Se activa automáticamente al instalar el plugin. No requiere configuración adicional.

### Capa 1 (MU-Plugin)

WP Seguro puede instalar un micro-plugin en `wp-content/mu-plugins/` para interceptar tráfico antes de que se carguen los demás plugins. El asistente de configuración lo ofrece automáticamente.

Para instalación manual:
1. Copia `wp-secure/includes/firewall/wps-firewall-muplugin.php` a `wp-content/mu-plugins/wps-firewall-muplugin.php`.
2. Verifica que los permisos del archivo sean correctos (644).

### Capa 0 (Firewall PHP)

Para máximo rendimiento, WP Seguro puede interceptar peticiones antes de que WordPress se cargue. Requiere acceso a la configuración de PHP y activar **Configuración → Firewall Avanzado → Capa 0**.

La directiva debe apuntar al **cargador** que el plugin genera en `wp-content/wps-data/`, nunca a un archivo dentro de la carpeta del plugin. Durante una actualización WordPress borra y vuelve a copiar esa carpeta; si la directiva apunta ahí, cada petición del sitio termina en error fatal mientras tanto, y también si el plugin se elimina o se renombra. El cargador no hace nada si el plugin no está. La ruta exacta se muestra en la descripción del ajuste.

**Apache con mod_php (.htaccess):**
```
php_value auto_prepend_file "/ruta/a/wp-content/wps-data/wps-firewall-loader.php"
```

**PHP-FPM / Nginx (.user.ini, php.ini o pool config):**
```ini
auto_prepend_file = /ruta/a/wp-content/wps-data/wps-firewall-loader.php
```

Si actualizás desde una versión anterior a 0.3.1 con la directiva apuntando a `plugins/wp-secure/includes/firewall/wps-firewall-prepend.php`, el panel muestra un aviso con la ruta nueva.

**Nota:** En hosting compartido, esta opción puede no estar disponible. La Capa 1 proporciona protección suficiente para la mayoría de sitios.

## Desinstalación

Al desactivar el plugin, las tablas de datos se conservan por seguridad. Al **desinstalar** (eliminar) el plugin:

1. Se eliminan todas las tablas de la base de datos (`wps_*`).
2. Se elimina el MU-Plugin si fue instalado.
3. Se eliminan las opciones y los transients del plugin (cache de geolocalización y de verificación de crawlers).
4. Se eliminan los datos de `wp-content/wps-data/`, **salvo el cargador de la Capa 0**. La directiva `auto_prepend_file` no se toca: la agregaste a mano y el plugin no puede modificarla con seguridad. Quitala primero y después borrá `wp-content/wps-data/wps-firewall-loader.php`. Si la dejás, el cargador no hace nada.

Para conservar los datos antes de desinstalar, usa la función de **Exportación CSV** en el dashboard.
