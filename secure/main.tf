# =============================================================================
#  HARDENED VERSION of the customer portal
#  Each fix is labelled with the misconfiguration it resolves (M1-M8).
# =============================================================================

data "google_project" "this" {}

# ---------------------------------------------------------------- encryption --
# Customer-managed encryption key (CMEK) for the bucket, disk and database, rotated every 90 days.
resource "google_kms_key_ring" "portal" {
  name     = "portal-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "portal" {
  name            = "portal-key"
  key_ring        = google_kms_key_ring.portal.id
  rotation_period = "7776000s" # 90 days

  lifecycle {
    prevent_destroy = true
  }
}

# Google-managed service agents need permission to use the key
data "google_storage_project_service_account" "gcs" {}

resource "google_project_service_identity" "sql" {
  provider = google-beta
  project  = var.project_id
  service  = "sqladmin.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "agents" {
  for_each = toset([
    "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}",
    "serviceAccount:service-${data.google_project.this.number}@compute-system.iam.gserviceaccount.com",
    "serviceAccount:${google_project_service_identity.sql.email}",
  ])
  crypto_key_id = google_kms_crypto_key.portal.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value
}

# ------------------------------------------------------------------- network --
# M1 fix: custom-mode VPC, one private subnet with flow logs and Private Google Access
resource "google_compute_network" "vpc" {
  name                    = "portal-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "app" {
  name                     = "portal-app"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = "10.10.0.0/24"
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# M2 fix: SSH only through Identity-Aware Proxy (Google's IAP range), only to tagged VMs, with logging.
# No rule opens RDP; everything else is blocked by the VPC's implied deny-ingress rule.
resource "google_compute_firewall" "iap_ssh" {
  name          = "allow-ssh-from-iap"
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["portal-web"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Outbound internet for updates without public IPs on VMs
resource "google_compute_router" "nat" {
  name    = "portal-router"
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "portal-nat"
  router                             = google_compute_router.nat.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ---------------------------------------------------------------- identity --
# M3 fix: dedicated service account with only the roles the app needs
resource "google_service_account" "app" {
  account_id   = "portal-app"
  display_name = "Portal application (least privilege)"
}

resource "google_project_iam_member" "app_roles" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/cloudsql.client",
  ])
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.app.email}"
}

# Write access to the one bucket it uses - not to every bucket in the project
resource "google_storage_bucket_iam_member" "app_exports" {
  bucket = google_storage_bucket.exports.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.app.email}"
}

# M4 fix: no service account key - the VM uses its attached identity (short-lived tokens)

# --------------------------------------------------------------------- VM --
# M5 fix: no public IP, Shielded VM, OS Login, project SSH keys blocked, serial port off, CMEK disk
resource "google_compute_instance" "web" {
  name         = "portal-web"
  machine_type = "e2-small"
  zone         = var.zone
  tags         = ["portal-web"]

  boot_disk {
    kms_key_self_link = google_kms_crypto_key.portal.id
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app.id
    # no access_config block = no external IP
  }

  service_account {
    email  = google_service_account.app.email
    scopes = ["cloud-platform"] # access is limited by the IAM roles above, as Google recommends
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "true"
    serial-port-enable     = "false"
  }

  depends_on = [google_kms_crypto_key_iam_member.agents]
}

# ---------------------------------------------------------------- storage --
# M6 fix: public access blocked, uniform IAM, versioning, access logs, CMEK
resource "google_storage_bucket" "access_logs" {
  #checkov:skip=CKV_GCP_62:This IS the access-log bucket; logging it into itself would loop
  name                        = "${var.project_id}-portal-access-logs"
  location                    = "EU"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket" "exports" {
  name                        = "${var.project_id}-portal-exports"
  location                    = "EU"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  logging {
    log_bucket = google_storage_bucket.access_logs.name
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.portal.id
  }

  depends_on = [google_kms_crypto_key_iam_member.agents]
}

# --------------------------------------------------------------- database --
# M7 fix: private IP only, TLS with client certificates, backups + point-in-time recovery, CMEK,
# current major version, and logging flags from the CIS Google Cloud benchmark
resource "google_compute_global_address" "sql_range" {
  name          = "portal-sql-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.vpc.id
}

resource "google_service_networking_connection" "sql" {
  network                 = google_compute_network.vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql_range.name]
}

resource "google_sql_database_instance" "db" {
  name                = "portal-db"
  database_version    = "POSTGRES_18"
  region              = var.region
  deletion_protection = true
  encryption_key_name = google_kms_crypto_key.portal.id

  settings {
    edition = "ENTERPRISE" # Enterprise Plus is the default for new PostgreSQL versions; Enterprise is cheaper for a lab
    tier    = "db-custom-1-3840"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
      ssl_mode        = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED" # app connects through the Cloud SQL Auth Proxy
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }
    database_flags {
      name  = "log_min_duration_statement"
      value = "-1"
    }
    database_flags {
      name  = "log_duration"
      value = "on"
    }
    database_flags {
      name  = "log_hostname"
      value = "on"
    }
    database_flags {
      name  = "log_statement"
      value = "ddl"
    }
    database_flags {
      name  = "log_min_error_statement"
      value = "error"
    }
    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
  }

  depends_on = [google_service_networking_connection.sql, google_kms_crypto_key_iam_member.agents]
}

# ------------------------------------------------------------- audit logs --
# M8 fix: Data Access audit logs for all services (who read or changed data, not just config)
resource "google_project_iam_audit_config" "all" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
