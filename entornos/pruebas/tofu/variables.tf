variable "tenancy_ocid" {
  type      = string
  sensitive = true
}

variable "user_ocid" {
  type      = string
  sensitive = true
}

variable "fingerprint" {
  type      = string
  sensitive = true
}

variable "private_key" {
  type      = string
  sensitive = true
}

variable "region" {
  type = string
}

variable "compartment_ocid" {
  type      = string
  sensitive = true
}

variable "tailscale_authkey" {
  description = "Auth key de Tailscale con la que la VM se une a la red privada en el primer arranque."
  type        = string
  sensitive   = true
}

# Límite Always Free vigente para cómputo ARM: 2 OCPU / 12 GB (Oracle lo redujo a mediados de 2026).
# El Compose de pruebas lleva mem_limit en cada servicio para caber en estos 12 GB. Verificar el límite antes de subirlo.
variable "ocpus" {
  type    = number
  default = 2

  validation {
    condition     = var.ocpus <= 2
    error_message = "Más de 2 OCPU de ARM sale del cupo gratuito de Oracle (Always Free) y genera cobro. Verifica el cupo vigente y pide aprobación a Fernando antes de subir este tope."
  }
}

variable "memoria_gb" {
  type    = number
  default = 12

  validation {
    condition     = var.memoria_gb <= 12
    error_message = "Más de 12 GB de memoria ARM sale del cupo gratuito de Oracle (Always Free) y genera cobro. Verifica el cupo vigente y pide aprobación a Fernando antes de subir este tope."
  }
}

# Dentro de la cuota gratuita de almacenamiento en bloques. Verificar antes de cambiarlo.
variable "disco_gb" {
  type    = number
  default = 100

  validation {
    condition     = var.disco_gb <= 100
    error_message = "Más de 100 GB de disco no está verificado dentro de la cuota gratuita de almacenamiento en bloques de Oracle. Verifica el cupo vigente y pide aprobación a Fernando antes de subir este tope."
  }
}
