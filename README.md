<p align="center">
  <a href="https://wpsecure.fabio.com.ar"><strong>WP Seguro</strong></a><br>
  Firewall de tres capas para WordPress
</p>

<p align="center">
  <a href="https://github.com/fabiomb/wp-secure/releases/latest"><img alt="Última versión" src="https://img.shields.io/github/v/release/fabiomb/wp-secure?label=versi%C3%B3n&color=34d399"></a>
  <a href="LICENSE"><img alt="Licencia GPL-2.0" src="https://img.shields.io/badge/licencia-GPL--2.0--or--later-blue"></a>
  <img alt="WordPress 6.0+" src="https://img.shields.io/badge/WordPress-6.0%2B-21759b">
  <img alt="PHP 7.4+" src="https://img.shields.io/badge/PHP-7.4%2B-777bb4">
</p>

<p align="center">
  <a href="https://wpsecure.fabio.com.ar">Sitio oficial</a> ·
  <a href="https://github.com/fabiomb/wp-secure/releases/latest/download/wp-secure.zip">Descargar</a> ·
  <a href="docs/README.md">Documentación</a> ·
  <a href="docs/changelog.md">Cambios</a>
</p>

---

**WP Seguro** es un plugin de seguridad para WordPress, libre y de código abierto. Detecta y bloquea bots, fuerza bruta, inyección SQL, XSS, path traversal y escáneres de vulnerabilidades. Intercepta cada petición lo más temprano posible, en muchos casos antes de que WordPress llegue a cargar, para que la protección no se pague en rendimiento.

## Funciones

- **Firewall de tres capas**: bloqueo previo a PHP, análisis en un MU-plugin y panel de administración.
- **Detectores de ataques**: SQLi, XSS, path traversal, escáneres, abuso de XML-RPC y de la REST API, con patrones afinados para no bloquear texto legítimo.
- **Login blindado**: freno a la fuerza bruta y sin enumeración de usuarios.
- **Puntuación de riesgo**: cada petición suma puntos y la acción depende del umbral alcanzado.
- **Rate limiting** por IP.
- **IP real detrás de CDN**: Cloudflare (IPv4 e IPv6), Sucuri y proxies propios, sin que la IP pueda falsificarse con un header.
- **Crawlers verificados por rDNS**: Googlebot pasa, quien se hace pasar por Googlebot no.
- **Tráfico en vivo y geolocalización** con una base MMDB local.
- **Reglas personalizadas**, whitelist, exportación y notificaciones.

## Cómo funciona

| Capa | Mecanismo | Momento | Qué hace |
|------|-----------|---------|----------|
| **0** | `auto_prepend_file` | Antes de cualquier PHP del sitio | Descarta IPs y rangos bloqueados leyendo un archivo plano. Sin base de datos, sin WordPress. |
| **1** | MU-plugin | Después del núcleo, antes de plugins y temas | Detecta patrones, aplica rate limiting, calcula el riesgo y registra. |
| **2** | Plugin | Carga normal | Asistente, dashboard, eventos, reglas, whitelist y configuración. |

Cada petición recibe una puntuación de riesgo:

| Puntaje | Acción |
|---------|--------|
| 0–30 | Permitir |
| 31–50 | Registrar |
| 51–80 | Limitar |
| 81–99 | Bloqueo temporal |
| 100+ | Bloqueo inmediato |

El detalle está en [Capas del firewall](docs/firewall-layers.md) y en la [Referencia de reglas](docs/rules-reference.md).

## Instalación

1. Descargá [`wp-secure.zip`](https://github.com/fabiomb/wp-secure/releases/latest/download/wp-secure.zip) desde la última release.
2. En WordPress, andá a **Plugins → Añadir nuevo → Subir plugin**.
3. Subí el archivo, instalalo y activá **WP Seguro**.
4. Completá el asistente de configuración inicial y revisá **WP Seguro → Dashboard**.

> [!IMPORTANT]
> Si el sitio está detrás de Cloudflare u otro proxy, revisá la [configuración de CDN/Proxy](docs/cdn-proxy-setup.md) antes de activar el bloqueo en producción. Con el proxy mal configurado, todo el tráfico parece venir de pocas IPs y el rate limiter puede bloquearlas.

### Requisitos

| | Mínimo | Recomendado |
|---|---|---|
| WordPress | 6.0 | Última |
| PHP | 7.4 | 8.0+ |
| MySQL | 5.7 | 8.0 |
| MariaDB | 10.3 | 10.6+ |

Extensiones PHP: `mbstring`, `json`, `mysqli`.

## Documentación

- [Instalación](docs/installation.md)
- [Configuración](docs/configuration.md)
- [Capas del firewall](docs/firewall-layers.md)
- [Referencia de reglas](docs/rules-reference.md)
- [Reglas personalizadas](docs/custom-rules.md)
- [Configuración de CDN/Proxy](docs/cdn-proxy-setup.md)
- [Solución de problemas](docs/troubleshooting.md)
- [Preguntas frecuentes](docs/faq.md)
- [Registro de cambios](docs/changelog.md)

## Contribuir

Toda ayuda suma, y probar el plugin en tu sitio ya cuenta.

- **¿Encontraste un falso positivo o un error?** Abrí un [issue](https://github.com/fabiomb/wp-secure/issues/new) con los pasos para reproducirlo. Si es un bloqueo, incluí la URL y los parámetros que lo dispararon.
- **¿Querés aportar código?** Nuevos detectores, mejoras de rendimiento, traducciones o documentación son bienvenidos por [pull request](https://github.com/fabiomb/wp-secure/pulls).
- **¿Una vulnerabilidad de seguridad?** No la publiques en un issue. Escribí directamente al autor a través de su [perfil de GitHub](https://github.com/fabiomb).

### Desarrollo local

```bash
git clone https://github.com/fabiomb/wp-secure.git
cd wp-secure
composer install
vendor/bin/phpunit --testsuite unit
```

Los tests unitarios no necesitan una instalación de WordPress. Los de integración requieren el framework de tests de WordPress:

```bash
WP_TESTS_DIR=/ruta/a/wordpress-tests-lib vendor/bin/phpunit --testsuite integration
```

Las clases `WPS_Foo_Bar` viven en `class-wps-foo-bar.php`, dentro de `includes/` y sus subcarpetas.

## Licencia

[GPL-2.0-or-later](LICENSE). Creado por [Fabio Baccaglioni](https://github.com/fabiomb).
