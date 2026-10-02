# Publicar una versión

Desde la 0.7.0 los sitios se actualizan solos desde los releases de GitHub, y **sólo instalan un zip firmado** con una de las claves cuyas públicas están en `WPS_Updater::PUBLIC_KEYS`. Un release sin firma, o con una firma que no corresponde, se rechaza en cada sitio (evento «Actualización rechazada») y el plugin queda en la versión que tenía.

## Claves

- **Principal** (`~/.wp-secure/release-signing.pem`): firma cada release. Cifrada con contraseña; la contraseña vive en el gestor de contraseñas.
- **Emergencia** (`release-emergency.pem`): guardada fuera de línea. Sólo se usa si la principal se pierde o se compromete, para publicar una versión que deje de aceptarla.
- Las claves privadas nunca van al repositorio, a un servidor ni a GitHub.

## Pasos

1. Bump de versión en `wp-secure.php` (cabecera y `WPS_VERSION`), en el MU-plugin (cabecera y constante de respaldo) y fecha en el changelog.
2. Armar el zip desde el commit de la versión:

   ```bash
   git archive --format=zip --prefix=wp-secure/ -o wp-secure-X.Y.Z.zip HEAD LICENSE README.md assets data includes uninstall.php wp-secure.php
   ```

3. Firmarlo (pide la contraseña de la clave principal). En Windows, en Git Bash y con `/usr/bin/openssl`:

   ```bash
   /usr/bin/openssl pkeyutl -sign -rawin -inkey ~/.wp-secure/release-signing.pem -in wp-secure-X.Y.Z.zip -out wp-secure-X.Y.Z.zip.sig
   ```

4. Verificar la firma con la pública antes de publicar:

   ```bash
   /usr/bin/openssl pkeyutl -verify -rawin -pubin -inkey ~/.wp-secure/release-signing.pub.pem -in wp-secure-X.Y.Z.zip -sigfile wp-secure-X.Y.Z.zip.sig
   ```

5. Publicar el release con el tag `vX.Y.Z` y **los dos archivos**: `wp-secure-X.Y.Z.zip` y `wp-secure-X.Y.Z.zip.sig`. El zip firmado tiene que ser exactamente el que se sube: si se regenera, hay que volver a firmarlo.

Los sitios ven la versión nueva en las horas siguientes (o al instante con «Buscar actualizaciones» en Escritorio → Actualizaciones).
