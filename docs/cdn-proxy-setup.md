# Configuración de CDN / Proxy

Cuando tu sitio está detrás de un CDN (Content Delivery Network) o un proxy inverso, la IP que WordPress ve como `REMOTE_ADDR` es la del servidor CDN, no la del visitante real. WP Seguro necesita resolver la IP real del visitante para funcionar correctamente.

---

## ¿Necesito configurar esto?

| Situación | Configuración necesaria |
|-----------|------------------------|
| Sin CDN ni proxy | Modo: **Ninguno** |
| Cloudflare (free/pro/business/enterprise) | Modo: **Cloudflare** o **Auto-detectar** |
| Sucuri Firewall | Modo: **Sucuri** o **Auto-detectar** |
| Otro CDN/proxy (Fastly, Akamai, AWS ALB, etc.) | Modo: **Personalizado** |
| Múltiples proxies en cadena | Modo: **Personalizado** |

---

## Auto-detectar (Recomendado)

El modo **Auto-detectar** identifica automáticamente si el tráfico proviene de Cloudflare o Sucuri verificando:

1. La presencia de cabeceras específicas del CDN (`CF-Connecting-IP`, `X-Sucuri-ClientIP`).
2. Que la IP del servidor (`REMOTE_ADDR`) pertenece a los rangos de IP conocidos del CDN.

Si ambas condiciones se cumplen, se usa la cabecera del CDN para obtener la IP real. Si no, se usa `REMOTE_ADDR`.

**Esta es la opción más segura** porque verifica que el proxy es legítimo antes de confiar en la cabecera.

---

## Cloudflare

### Configuración automática

1. Ve a **WP Seguro → Configuración → Proxy / CDN**.
2. Selecciona modo **Cloudflare**.
3. Guarda los cambios.

WP Seguro verificará que las peticiones provienen de los rangos de IP de Cloudflare antes de usar la cabecera `CF-Connecting-IP`.

### Rangos de IP de Cloudflare

WP Seguro incluye los rangos de IP actuales de Cloudflare. Estos se verifican contra la IP del servidor para prevenir spoofing de la cabecera `CF-Connecting-IP`.

Rangos IPv4 incluidos:
```
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
```

### Verificación

Para verificar que la configuración funciona:
1. Visita tu sitio desde una red externa.
2. Ve al **Visor de Tráfico en Vivo** en el dashboard de WP Seguro.
3. Comprueba que tu IP real aparece correctamente (no la IP de Cloudflare).

---

## Sucuri

### Configuración

1. Ve a **WP Seguro → Configuración → Proxy / CDN**.
2. Selecciona modo **Sucuri**.
3. Guarda los cambios.

WP Seguro usará la cabecera `X-Sucuri-ClientIP` verificando que la petición proviene de los rangos de IP de Sucuri.

### Rangos de IP de Sucuri

```
192.88.134.0/23
185.93.228.0/22
66.248.200.0/22
208.109.0.0/22
```

---

## Proxy Personalizado

Para CDNs o proxies no soportados nativamente (Fastly, Akamai, AWS ELB/ALB, nginx como proxy, Varnish, etc.):

### Configuración

1. Ve a **WP Seguro → Configuración → Proxy / CDN**.
2. Selecciona modo **Personalizado**.
3. En **IPs de proxy confiables**, introduce las IPs o rangos CIDR de tu proxy (uno por línea).
4. En **Cabecera de IP**, selecciona la cabecera que tu proxy usa para enviar la IP real del visitante.
5. Guarda los cambios.

### Cabeceras soportadas

| Cabecera | Uso típico |
|----------|-----------|
| `X-Forwarded-For` | Estándar, usado por la mayoría de proxies y load balancers |
| `X-Real-IP` | nginx, algunos proxies |
| `CF-Connecting-IP` | Cloudflare |
| `X-Sucuri-ClientIP` | Sucuri |

### Ejemplo: nginx como proxy inverso

Si usas nginx delante de Apache/PHP-FPM:

**IPs confiables:** `127.0.0.1` (o la IP del servidor nginx)

**Cabecera:** `X-Real-IP` o `X-Forwarded-For`

### Ejemplo: AWS Application Load Balancer

**IPs confiables:** Los rangos CIDR de tu VPC o subredes del ALB.

**Cabecera:** `X-Forwarded-For`

---

## Seguridad de la Resolución de IP

WP Seguro implementa varias protecciones contra spoofing de IP:

1. **Verificación de origen**: Solo confía en cabeceras de proxy cuando `REMOTE_ADDR` pertenece a los rangos de IP del proxy configurado.
2. **Primera IP pública**: Al procesar `X-Forwarded-For` (que puede contener múltiples IPs separadas por coma), extrae la primera IP pública de la lista.
3. **Validación de formato**: Verifica que la IP extraída es una dirección IPv4 o IPv6 válida.
4. **Fallback seguro**: Si la cabecera no contiene una IP válida o el proxy no es confiable, usa `REMOTE_ADDR`.

### ¿Por qué es importante?

Un atacante podría enviar una cabecera `X-Forwarded-For` o `CF-Connecting-IP` falsa para:
- Hacerse pasar por una IP diferente y evadir bloqueos.
- Inyectar una IP de la whitelist para saltarse las reglas.

WP Seguro previene esto verificando siempre que `REMOTE_ADDR` pertenece al proxy antes de confiar en la cabecera.

---

## Solución de Problemas

### Todas las IPs aparecen como la misma dirección

Tu sitio está detrás de un proxy/CDN y el modo de proxy no está configurado correctamente. Configura el modo apropiado en **Configuración → Proxy / CDN**.

### Las IPs aparecen como direcciones privadas (10.x.x.x, 172.x.x.x)

Esto suele indicar un proxy interno (Docker, Kubernetes, load balancer). Configura el modo **Personalizado** con las IPs del proxy interno.

### Bloqueo accidental de tu propia IP

Si el proxy no está configurado y bloqueas la IP del CDN, **todos** los visitantes serán bloqueados. Solución:

1. Accede al servidor por SSH o FTP.
2. Elimina el archivo `wp-content/mu-plugins/wps-firewall.php` si existe.
3. Desactiva el plugin renombrando la carpeta `wp-secure/`.
4. Reactiva y configura correctamente el modo de proxy.
