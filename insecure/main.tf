# =============================================================================
#  INSECURE BASELINE - DO NOT DEPLOY TO A REAL PROJECT
#  A small "customer portal": web VM + Cloud SQL database + storage bucket.
#  Every resource contains common misconfigurations found in real cloud audits.
#  The numbered comments (M1, M2, ...) match the findings table in the README.
# =============================================================================

# M1: default-style network with no flow logs
resource "google_compute_network" "vpc" {
  name                    = "portal-vpc"
  auto_create_subnetworks = true
}

# M2: SSH and RDP open to the whole internet, no firewall logging
resource "google_compute_firewall" "allow_admin" {
  name          = "allow-admin-from-anywhere"
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
}

# M3: service account with the project-wide Editor role ...
resource "google_service_account" "app" {
  account_id   = "portal-app"
  display_name = "Portal application"
}

resource "google_project_iam_member" "app_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.app.email}"
}

# M4: ... and a long-lived, downloadable key for it
resource "google_service_account_key" "app_key" {
  service_account_id = google_service_account.app.name
}

# M5: VM with a public IP, full cloud-platform scope, serial port on, project SSH keys allowed, no Shielded VM
resource "google_compute_instance" "web" {
  name         = "portal-web"
  machine_type = "e2-small"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = google_compute_network.vpc.id
    access_config {} # ephemeral public IP
  }

  service_account {
    email  = google_service_account.app.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    serial-port-enable = "true"
  }
}

# M6: bucket holding customer exports - publicly readable, no versioning, no access logs
resource "google_storage_bucket" "exports" {
  name                        = "${var.project_id}-portal-exports"
  location                    = "EU"
  force_destroy               = true
  uniform_bucket_level_access = false
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.exports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# M7: database reachable from any IP, no TLS enforcement, no backups, no deletion protection
resource "google_sql_database_instance" "db" {
  name                = "portal-db"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = false

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "anywhere"
        value = "0.0.0.0/0"
      }
    }

    backup_configuration {
      enabled = false
    }
  }
}

# M8: no explicit Data Access audit logging configured
