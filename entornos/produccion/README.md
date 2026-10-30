# Producción (pendiente)

Despliegue en GCP `us-east1`, opción B1 aprobada:

- Cloud Run para el backend (escala a cero) y Cloud Run Jobs para procesos por lotes.
- VM e2-standard-4 con Docker Compose para Valhalla, VROOM, Photon, PostGIS, RabbitMQ, Keycloak y MLflow.
- Cloudflare: DNS del dominio propio, proxy con WAF básico y R2 para los mapas PMTiles.
- Estado de OpenTofu en GCS con versionado; GitHub Actions entra con Workload Identity Federation (sin llaves JSON).
- Respaldos de PostgreSQL con pgBackRest a GCS Coldline en otra región.

Ver `03-arquitectura/despliegue_produccion_b1.puml` y `04-infraestructura/despliegues.md` en la carpeta de documentación. **No construir sin aprobación de Fernando.**
