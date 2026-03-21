# Reglas Personalizadas

WP Seguro permite definir **reglas manuales personalizadas** para detectar patrones específicos en las peticiones HTTP y ejecutar acciones automáticas. Estas reglas complementan las reglas automáticas del motor de detección.

---

## Conceptos

Cada regla personalizada sigue la lógica:

```
IF (condición 1) AND/OR (condición 2) AND/OR (condición N) THEN (acción)
```

- **Condiciones**: criterios que se evalúan contra cada petición HTTP entrante.
- **Operadores lógicos**: las condiciones se encadenan con **AND** (todas deben cumplirse) u **OR** (basta con que una se cumpla).
- **Acción**: la consecuencia que se ejecuta cuando las condiciones se cumplen.

---

## Campos de Condición

Cada condición evalúa un campo de la petición HTTP:

| Campo | Descripción | Ejemplo |
|-------|-------------|---------|
| URI de la petición | La ruta completa de la URL solicitada. | `/wp-json/optimization-detective/v1/url-metrics:store` |
| User-Agent | La cadena de identificación del navegador o cliente HTTP. | `Mozilla/5.0`, `python-requests/2.28` |
| Dirección IP | La IP del visitante. | `192.168.1.100` |
| Método HTTP | El método de la petición. | `POST`, `GET`, `DELETE` |
| Query String | Los parámetros de la URL (después del `?`). | `action=edit&id=5` |
| Referer | La página de origen de la petición. | `https://ejemplo.com/pagina` |
| Host | El dominio solicitado. | `ejemplo.com` |
| País (código ISO) | El código de país de dos letras de la IP (requiere base de datos de geolocalización). | `US`, `CN`, `RU` |
| Tipo de visitante | La clasificación automática del visitante. | `login`, `restapi`, `page`, `static` |

---

## Operadores de Comparación

| Operador | Descripción | Ejemplo de uso |
|----------|-------------|----------------|
| Contiene | El campo contiene el texto especificado (sin distinguir mayúsculas). | URI *contiene* `/wp-json/` |
| No contiene | El campo NO contiene el texto especificado. | User-Agent *no contiene* `Mozilla` |
| Es igual a | El campo es exactamente igual al valor (sin distinguir mayúsculas). | Método HTTP *es igual a* `DELETE` |
| No es igual a | El campo NO es exactamente igual al valor. | País *no es igual a* `US` |
| Empieza con | El campo comienza con el texto especificado. | URI *empieza con* `/wp-json/` |
| Termina con | El campo termina con el texto especificado. | URI *termina con* `:store` |
| Coincide con regex | El campo coincide con una expresión regular. | User-Agent *coincide con regex* `python\|curl\|wget` |
| Está en rango CIDR | La IP del visitante pertenece al rango CIDR especificado. | IP *está en rango CIDR* `10.0.0.0/8` |

---

## Acciones Disponibles

| Acción | Descripción |
|--------|-------------|
| **Bloqueo permanente** | Bloquea la IP del visitante de forma permanente. La IP se agrega a la lista de IPs bloqueadas sin fecha de expiración. |
| **Bloqueo temporal** | Bloquea la IP del visitante por un período configurable (en minutos). Tras expirar, la IP puede volver a acceder. |
| **Agregar a whitelist** | Agrega la IP del visitante a la whitelist global. Las peticiones futuras de esta IP se excluyen de todas las reglas. |
| **Solo registrar (log)** | Registra un evento de seguridad sin bloquear ni modificar nada. Útil para monitoreo. |

---

## Ejemplos de Reglas

### Bloquear un endpoint específico

Bloquear todas las peticiones a un endpoint REST que genera tráfico no deseado:

```
IF   URI contiene "/wp-json/optimization-detective/v1/url-metrics:store"
THEN Bloqueo permanente
```

### Bloquear bots por User-Agent

Bloquear peticiones de bots con un User-Agent específico:

```
IF   User-Agent contiene "AhrefsBot"
AND  Método HTTP es igual a "GET"
THEN Bloqueo temporal (60 minutos)
```

### Bloquear POST sospechosos a la REST API

```
IF   URI empieza con "/wp-json/"
AND  Método HTTP es igual a "POST"
AND  User-Agent no contiene "Mozilla"
THEN Bloqueo temporal (30 minutos)
```

### Permitir un servicio de monitoreo

Agregar automáticamente a la whitelist un servicio conocido:

```
IF   User-Agent contiene "UptimeRobot"
THEN Agregar a whitelist
```

### Monitorear tráfico de un país sin bloquear

```
IF   País es igual a "CN"
AND  URI contiene "/wp-admin"
THEN Solo registrar (log)
```

### Bloquear acceso con regex

Bloquear acceso a archivos de configuración usando expresión regular:

```
IF   URI coincide con regex "\.(env|ini|conf|yml|yaml|bak)$"
THEN Bloqueo permanente
```

---

## Prioridad

Cada regla tiene un valor de **prioridad** (1-999). Las reglas con menor número se evalúan primero. La primera regla que coincida con la petición ejecuta su acción y las demás se omiten.

**Recomendaciones:**
- Whitelist: prioridad 1-5 (evaluar primero para evitar bloqueos incorrectos).
- Bloqueos específicos: prioridad 10-50.
- Reglas generales: prioridad 50-100.
- Solo log: prioridad 100+.

---

## Orden de Evaluación

Las reglas personalizadas se evalúan dentro del flujo del plugin en este orden:

1. Verificar si la IP está en la **whitelist** (si es así, no se evalúa nada más).
2. Verificar si la IP está **bloqueada** (bloqueos activos existentes).
3. **→ Evaluar reglas personalizadas** (la primera que coincida se ejecuta).
4. Detectores automáticos (SQLi, XSS, Path Traversal, etc.).
5. Motor de puntuación de riesgo.

---

## Gestión desde el Panel

Puedes crear, editar, activar/desactivar y eliminar reglas desde **WP Seguro → Reglas** en el panel de administración de WordPress.

La tabla de reglas muestra:
- **Prioridad**: orden de evaluación.
- **Nombre**: identificador descriptivo.
- **Condiciones**: resumen visual de las condiciones configuradas.
- **Acción**: tipo de acción a ejecutar.
- **Hits**: número de veces que la regla ha coincidido.
- **Estado**: activa o inactiva.

Las reglas inactivas no se evalúan pero se conservan para re-activación futura.

---

## Consideraciones de Seguridad

- Las reglas con acción **whitelist** deben usarse con precaución, ya que excluyen la IP de todos los controles de seguridad futuros.
- Las expresiones regulares se ejecutan con un límite de backtracking para prevenir ataques ReDoS (denegación de servicio por regex).
- Los administradores en la whitelist no se ven afectados por las reglas personalizadas.
- Las reglas usan campos de la petición a nivel HTTP; no se analizan contenidos cifrados.
