# Solución de Problemas

## Problemas Comunes

### No puedo acceder al panel de administración

**Causa probable:** Tu IP fue bloqueada por el plugin.

**Solución:**

1. **Vía FTP/SSH:** Elimina el archivo `wp-content/mu-plugins/wps-firewall.php` para desactivar la Capa 1.
2. **Vía FTP/SSH:** Renombra la carpeta `wp-content/plugins/wp-secure/` a `wp-secure-disabled/` para desactivar la Capa 2.
3. Accede al panel de WordPress y reactiva el plugin.
4. Añade tu IP a la whitelist antes de reactivar las capas.

**Prevención:** Tu IP se añade automáticamente a la whitelist durante la configuración inicial. No la elimines.

---

### El plugin bloquea usuarios legítimos

**Causa probable:** Falso positivo en las reglas de detección.

**Solución:**

1. Revisa los **Eventos** en el dashboard para identificar qué regla se activó.
2. Si la IP es legítima, añádela a la **Whitelist**.
3. Considera bajar el **Nivel de protección** de Alto a Medio.
4. Si el problema persiste con un User-Agent específico, desactiva la regla correspondiente.

---

### Todas las IPs aparecen como la misma dirección

**Causa probable:** Tu sitio está detrás de un CDN/proxy y la configuración de proxy no está correcta.

**Solución:** Configura el modo de proxy adecuado en **Configuración → Proxy / CDN**. Consulta [Configuración de CDN/Proxy](cdn-proxy-setup.md).

---

### El dashboard muestra datos incorrectos o vacíos

**Causa probable:** Las tablas de la base de datos no se crearon correctamente.

**Solución:**

1. Desactiva y reactiva el plugin (esto ejecuta las migraciones).
2. Verifica que el usuario de la base de datos tiene permisos para crear tablas.
3. Revisa el error_log de PHP para mensajes de error de la base de datos.

---

### Conflicto con otros plugins de seguridad

**Causa probable:** Otro plugin de seguridad (Wordfence, iThemes Security, Sucuri plugin, etc.) interfiere con WP Seguro.

**Solución:**

1. **No se recomienda** usar múltiples plugins de seguridad simultáneamente.
2. Si necesitas mantener ambos, desactiva las funciones duplicadas en uno u otro:
   - Brute force protection
   - Firewall rules
   - Rate limiting
3. WP Seguro mostrará una advertencia si detecta plugins de seguridad conflictivos.

---

### El MU-Plugin no se instala automáticamente

**Causa probable:** El directorio `wp-content/mu-plugins/` no tiene permisos de escritura.

**Solución:**

1. Crea el directorio manualmente si no existe: `mkdir wp-content/mu-plugins/`
2. Establece permisos: `chmod 755 wp-content/mu-plugins/`
3. Copia manualmente el archivo: `cp wp-content/plugins/wp-secure/includes/firewall/wps-muplugin.php wp-content/mu-plugins/wps-firewall.php`
4. Reintenta la activación desde el panel.

---

### La Capa 0 no funciona

**Causa probable:** El hosting no permite `auto_prepend_file`.

**Solución:**

1. Contacta a tu proveedor de hosting para verificar si soportan `auto_prepend_file`.
2. En hosting compartido, prueba con `.user.ini`:
   ```ini
   auto_prepend_file = /ruta/completa/wp-content/plugins/wp-secure/includes/firewall/wps-prepend.php
   ```
3. Si no es posible, la Capa 1 (MU-Plugin) proporciona protección suficiente. La Capa 0 es una optimización, no un requisito.

---

### Las notificaciones por email no llegan

**Causa probable:** Problema con la función `wp_mail()` de WordPress.

**Solución:**

1. Verifica que la dirección de email configurada es correcta en **Configuración → Notificaciones**.
2. Prueba enviando un email de prueba desde **Herramientas → Salud del sitio**.
3. Instala un plugin SMTP (WP Mail SMTP, Post SMTP) si el servidor no envía correos correctamente.
4. Revisa la carpeta de spam del destinatario.

---

### Alto consumo de base de datos

**Causa probable:** Las tablas de tráfico crecen con cada petición registrada.

**Solución:**

1. Reduce el período de **Retención de datos** en **Configuración → Retención**.
2. Verifica que la **Limpieza automática** está activada.
3. Revisa el tamaño de las tablas `wps_*` en phpMyAdmin.
4. Ejecuta una purga manual desde **WP Seguro → Herramientas → Mantenimiento**.

---

## Diagnóstico Avanzado

### Activar modo debug de rendimiento

1. Ve a **Configuración → Rendimiento**.
2. Activa **Modo debug de rendimiento**.
3. Visita cualquier página del sitio como administrador.
4. En la barra de admin aparecerá el tiempo de overhead del plugin.
5. Detalles adicionales se escriben en el `error_log` de PHP.

### Verificar las capas activas

El dashboard de WP Seguro muestra el estado de cada capa:

- 🟢 Activa y funcionando
- 🟡 Disponible pero no configurada
- 🔴 No disponible (permisos, configuración del hosting, etc.)

### Logs de error

WP Seguro registra errores en el log estándar de PHP (`error_log`). Para activarlo:

```php
// En wp-config.php
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
```

Los mensajes del plugin se identifican con el prefijo `[WP Seguro]`.
