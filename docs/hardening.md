# Endurecimiento del sitio

**WP Seguro → Endurecimiento** verifica la configuración que el firewall no puede cubrir: constantes de `wp-config.php`, errores visibles, permisos, versión de PHP y comportamiento del servidor. Sólo informa y explica cómo corregir; no modifica `wp-config.php` ni la configuración del servidor.

También desde la consola: `wp wps hardening`.

## Estados

| Estado | Significado |
|--------|-------------|
| **Problema** | Expone información o permite un ataque directo. Corregir cuanto antes. |
| **Mejorable** | No es una falla, pero reduce la protección. |
| **Correcto** | Nada que hacer. |
| **Informativo** | No se pudo comprobar, no aplica al servidor o es una recomendación menor. |

## Verificaciones

| Verificación | Qué mira | Cómo corregirlo |
|--------------|----------|-----------------|
| Editor de archivos del panel | `DISALLOW_FILE_EDIT` (o `DISALLOW_FILE_MODS`). Con el editor activo, quien tome una cuenta de administrador inyecta código sin FTP. | `define( 'DISALLOW_FILE_EDIT', true );` en `wp-config.php`. |
| Errores de PHP visibles | El valor efectivo de `display_errors`. Con `WP_DEBUG` apagado, WordPress no lo toca y vale lo que diga `php.ini`, así que los errores pueden verse aunque `WP_DEBUG` esté en `false`. `WP_DEBUG` activo sin mostrar errores es «Mejorable». | `define( 'WP_DEBUG_DISPLAY', false );` y `@ini_set( 'display_errors', 0 );`, o `display_errors = Off` en `php.ini`. |
| debug.log público | Si existe `wp-content/debug.log` y si se puede descargar (petición del sitio a sí mismo). | Borrarlo y, si se necesita el log, llevarlo fuera de la carpeta pública: `define( 'WP_DEBUG_LOG', '/ruta/privada/debug.log' );`. |
| Listado de directorios | Crea una carpeta temporal sin índice en uploads, la pide y se fija si el servidor lista su contenido. La carpeta se borra enseguida. | Apache: `Options -Indexes` en el `.htaccess` de la raíz. nginx: `autoindex off;`. |
| Versión de PHP | Fin del soporte de seguridad de la rama instalada (fechas de php.net). Avisa seis meses antes. | Cambiar la versión desde el panel del hosting. |
| Permisos de wp-config.php | Que no lo puedan leer (ni menos modificar) otros usuarios del servidor. No aplica en Windows. | `chmod 640 wp-config.php` (o 600, 400). |
| Usuario «admin» | Si hay un administrador llamado `admin`, el primer nombre que prueban los ataques de contraseñas. | Crear otro administrador, entrar con él y eliminar `admin` atribuyendo su contenido al nuevo. |
| HTTPS | Que la dirección del sitio use `https://`. | Instalar un certificado y actualizar las direcciones en Ajustes → Generales. |
| PHP en la carpeta de subidas | El ajuste «PHP en uploads» ([ver Configuración](configuration.md#php-en-la-carpeta-de-subidas)). | Activarlo en Configuración → Firewall Avanzado. |
| Prefijo de tablas | Si se usa el prefijo por defecto `wp_`. Es informativo: sólo dificulta algunas inyecciones automatizadas y cambiarlo en un sitio existente es delicado. | En instalaciones nuevas, elegir otro prefijo. |

El listado de directorios y el debug.log se comprueban con peticiones del sitio a sí mismo (sin servicios externos) y el resultado se guarda 12 horas; «Volver a comprobar» las repite. Si el sitio no responde a peticiones desde el propio servidor, esas verificaciones quedan como «Informativo».
