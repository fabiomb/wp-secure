# Comandos WP-CLI

WP Seguro agrega el comando `wp wps` a [WP-CLI](https://wp-cli.org/). Sirve para recuperar el acceso sin pasar por el panel y para automatizar tareas.

| Comando | Qué hace |
|---------|----------|
| `wp wps status` | Versión, estado de las capas, Modo Inseguro, `WPS_DISABLE_BLOCKING`, bloqueos activos y entradas en la whitelist. |
| `wp wps block <ip\|cidr> [--minutes=<n>] [--reason=<texto>]` | Bloqueo manual. Sin `--minutes`, es permanente. |
| `wp wps unblock <ip\|cidr>` | Levanta los bloqueos de esa IP **y los de rango que la contienen** (en IPv6 los bloqueos automáticos son de red). Con un CIDR, levanta los bloqueos de ese rango. |
| `wp wps blocks [--format=table\|json\|csv\|yaml]` | Lista los bloqueos activos. |
| `wp wps whitelist add <ip\|cidr> [--label=<texto>] [--type=global\|login]` | Agrega a la whitelist. |
| `wp wps whitelist remove <ip\|cidr>` | Quita de la whitelist. |
| `wp wps whitelist list [--format=…]` | Lista la whitelist. |
| `wp wps sync-layer0` | Regenera el archivo de la Capa 0 desde la base de datos. |
| `wp wps integrity scan` | Escaneo completo de integridad, sin límite de tiempo. |
| `wp wps integrity status [--format=…]` | Resumen y lista de archivos con cambios sin revisar. |
| `wp wps integrity accept [<área>]` | Acepta los cambios de un área (p. ej. `core`, `plugin:akismet`) o de todas. |
| `wp wps activity [--user=<login>] [--group=users\|content\|plugins\|settings] [--limit=<n>] [--format=…]` | Registro de actividad, más recientes primero. |
| `wp wps hardening [--format=…]` | Chequeo de endurecimiento del sitio ([ver](hardening.md)). «Errores de PHP visibles» refleja el PHP de la consola, que puede diferir del de la web. |
| `wp wps unsafe-mode on\|off` | Activa o desactiva el Modo Inseguro: el firewall detecta y registra, pero no bloquea. Envía el aviso de cambio de configuración. |

## Recuperar el acceso

Si quedaste bloqueado y tenés acceso por SSH:

```bash
wp wps unblock 203.0.113.7
wp wps whitelist add 203.0.113.7 --label="Mi conexión"
```

Si no sabés qué te bloquea, suspendé el bloqueo, entrá al panel y revisá **Eventos**:

```bash
wp wps unsafe-mode on
```

Acordate de volver a activarlo con `wp wps unsafe-mode off`.
