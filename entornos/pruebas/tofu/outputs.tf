output "ip_publica" {
  description = "IP pública de la VM; DuckDNS apunta aquí."
  value       = oci_core_instance.servidor.public_ip
}

output "nombre_tailscale" {
  description = "Nombre de la VM dentro de Tailscale, usado por Ansible."
  value       = "trayecta-go-pruebas"
}
