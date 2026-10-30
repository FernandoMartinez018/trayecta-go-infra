# Trayecta Go · infraestructura — guía para Claude Code

Lee este archivo completo antes de cada tarea. Este repositorio despliega el producto del repositorio `trayecta-go`. **El código del producto es el mismo en los dos entornos; aquí solo cambia cómo y dónde se despliega.**

## Documentación (fuera del repositorio)

Toda la documentación del proyecto vive **solo** en la carpeta del PC de Fernando:

`C:\proyectosPersonales\contextoa\optimus routes`

Antes de cada tarea:

1. Lee `output/estado.md` de esa carpeta (qué está hecho, qué sigue, bloqueos). No releas todo.
2. Usa el índice de `README.md` de esa carpeta para abrir solo lo que la tarea necesita.

Al terminar cada tarea (aunque quede incompleta):

1. Agrega una entrada al inicio de `output/registro.md` con el formato de `output/README.md`.
2. Reescribe `output/estado.md`.
3. Actualiza los documentos afectados (`04-infraestructura/despliegues.md`, `04-infraestructura/secretos.md`, `05-costos/costos.md`, `00-contexto/decisiones.md`, etc.).
4. Si el código y la documentación no coinciden, no decidas tú: anótalo en `output/estado.md` → Inconsistencias y pregunta a Fernando.

**No crees documentación dentro del repositorio** (nada de `docs/`). En el repositorio solo van código, contratos, migraciones, configuración y este archivo. Si la carpeta no es accesible (por ejemplo, Claude Code corre en otro equipo), detente y avísale a Fernando.

## Entornos

| Entorno | Carpeta | Dónde | Estado |
|---|---|---|---|
| `pruebas` | `entornos/pruebas/` | Oracle Cloud **Always Free** (VM ARM + Docker Compose) | Activo: fase de pruebas de Fernando |
| `produccion` | `entornos/produccion/` | GCP `us-east1` (Cloud Run + VM e2-standard-4) + Cloudflare | Se construye después; no tocar sin aprobación |

### Pruebas (Oracle Cloud)

- **OpenTofu** (`entornos/pruebas/tofu/`) crea red, reglas de firewall y una VM `VM.Standard.A1.Flex` con Ubuntu.
- **cloud-init** instala Tailscale en el primer arranque para administrar la VM sin SSH público.
- **Ansible** (`entornos/pruebas/ansible/`) instala Docker y despliega `entornos/pruebas/compose/` con Caddy, backend, PostGIS, RabbitMQ, Keycloak, Valhalla, Photon y Uptime Kuma.
- **HTTPS** con Caddy y subdominios de DuckDNS (`api.<nombre>.duckdns.org`, `auth.<nombre>.duckdns.org`).
- **Archivos y respaldos** en Object Storage de Oracle por la API compatible con S3.
- **Estado de OpenTofu** en un bucket de Object Storage de Oracle (backend `s3`).

## Reglas obligatorias (costo y seguridad)

1. **Solo recursos Always Free.** Antes de crear o cambiar un recurso, confirma que es gratuito y que el total sigue dentro de los límites gratuitos vigentes (cómputo ARM, disco de arranque y bloques, Object Storage). Si no puedes confirmarlo, **pregunta**.
2. **Nunca** actualices la cuenta a Pay As You Go ni cambies nada de facturación.
3. **Nunca** crees recursos fuera del compartimento `trayecta-go-pruebas`.
4. **Plan antes de aplicar.** Todo cambio de infraestructura pasa por `tofu plan` en un pull request. `tofu apply` solo corre desde el workflow `desplegar-pruebas`, que requiere la aprobación de Fernando en el entorno `pruebas` de GitHub.
5. **Destruir recursos** (`tofu destroy`, borrar volúmenes o buckets) siempre requiere confirmación explícita de Fernando en el chat o en el PR.
6. **Sin SSH ni puertos de administración abiertos a internet.** Solo 80 y 443 son públicos. La administración va por Tailscale.
7. **Secretos** solo en GitHub Secrets o variables de entorno del runner. Nunca en archivos del repositorio, en logs ni en salidas de OpenTofu (marca las variables como `sensitive`).
8. **Etiquetas** en todos los recursos: `proyecto = trayecta-go`, `entorno = pruebas`, `gestionado-por = opentofu`.
9. **Inactividad.** Oracle puede reclamar instancias gratuitas con muy poco uso. Si pasa, se recrea todo con el workflow; los datos se restauran desde el respaldo diario en Object Storage.

## Cómo trabajar

1. Rama `infra/descripcion-corta`.
2. Cambios en OpenTofu: `tofu fmt`, `tofu validate` y el plan del PR deben estar en verde.
3. Cambios en Ansible o Compose: explica en el PR cómo verificarlos.
4. PR en español con qué cambia, el costo (debe ser 0) y cómo revertir.

## Secretos esperados

Ver `04-infraestructura/secretos.md` en la carpeta de documentación. Si falta uno, pídeselo a Fernando con el nombre exacto; nunca lo inventes ni lo pidas pegado en el chat si es una llave privada: debe cargarlo él en GitHub.
