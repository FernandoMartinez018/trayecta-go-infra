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

# Dentro del límite Always Free para cómputo ARM. Verificar el límite vigente antes de subirlo.
variable "ocpus" {
  type    = number
  default = 4
}

variable "memoria_gb" {
  type    = number
  default = 24
}

# Dentro de la cuota gratuita de almacenamiento en bloques. Verificar antes de cambiarlo.
variable "disco_gb" {
  type    = number
  default = 100
}
