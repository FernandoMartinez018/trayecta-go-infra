locals {
  etiquetas = {
    "proyecto"       = "trayecta-go"
    "entorno"        = "pruebas"
    "gestionado-por" = "opentofu"
  }
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

# Imagen más reciente de Ubuntu 24.04 compatible con la forma ARM.
data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

# Red ----------------------------------------------------------------------------

resource "oci_core_vcn" "principal" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.20.0.0/16"]
  display_name   = "trayecta-go-pruebas"
  dns_label      = "trayecta"
  freeform_tags  = local.etiquetas
}

resource "oci_core_internet_gateway" "salida" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.principal.id
  display_name   = "trayecta-go-pruebas-igw"
  freeform_tags  = local.etiquetas
}

resource "oci_core_route_table" "publica" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.principal.id
  display_name   = "trayecta-go-pruebas-rutas"
  freeform_tags  = local.etiquetas

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.salida.id
  }
}

# Solo HTTP y HTTPS abiertos. Sin SSH: la administración va por Tailscale.
resource "oci_core_security_list" "web" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.principal.id
  display_name   = "trayecta-go-pruebas-web"
  freeform_tags  = local.etiquetas

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "6"
    tcp_options {
      min = 80
      max = 80
    }
  }

  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "6"
    tcp_options {
      min = 443
      max = 443
    }
  }

  # Tailscale (WireGuard) para conexiones directas; funciona también sin esta regla vía relés.
  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "17"
    udp_options {
      min = 41641
      max = 41641
    }
  }
}

resource "oci_core_subnet" "publica" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.principal.id
  cidr_block        = "10.20.1.0/24"
  display_name      = "trayecta-go-pruebas-publica"
  dns_label         = "publica"
  route_table_id    = oci_core_route_table.publica.id
  security_list_ids = [oci_core_security_list.web.id]
  freeform_tags     = local.etiquetas
}

# Cómputo ------------------------------------------------------------------------

resource "oci_core_instance" "servidor" {
  compartment_id      = var.compartment_ocid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  display_name        = "trayecta-go-pruebas"
  shape               = "VM.Standard.A1.Flex"
  freeform_tags       = local.etiquetas

  shape_config {
    ocpus         = var.ocpus
    memory_in_gbs = var.memoria_gb
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu.images[0].id
    boot_volume_size_in_gbs = var.disco_gb
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.publica.id
    assign_public_ip = true
    hostname_label   = "servidor"
  }

  metadata = {
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
      tailscale_authkey = var.tailscale_authkey
    }))
  }

  preserve_boot_volume = false

  lifecycle {
    # La imagen se fija en la creación; actualizar Ubuntu se hace dentro de la VM, no recreándola.
    ignore_changes = [source_details[0].source_id, metadata]
  }
}
