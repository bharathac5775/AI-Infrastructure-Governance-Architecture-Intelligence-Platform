############################################################
# GCP PRODUCTION-GRADE INFRASTRUCTURE
# Targets all rule-based GCP checks across Security, Reliability,
# and Cost agents. Designed to score 98–100 / 100 on rule-only path.
#
# Highlights:
#   - Hardened VPC firewall (no 0.0.0.0/0 ingress; HTTPS-only from VPC)
#   - Private GKE cluster (private nodes, network policy, master
#     authorized networks, maintenance window, auto-repair + auto-upgrade)
#   - Cloud SQL: REGIONAL HA, SSL enforced (ssl_mode), private IP,
#     deletion protection, daily backups
#   - GCS bucket: uniform access, versioning, lifecycle to Nearline + delete
#   - Compute Engine: shielded VM, non-preemptible, modest machine type
#   - IAM bindings scoped to specific service accounts (no allUsers)
############################################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = "us-central1"
}

############################################################
# VPC NETWORK + PRIVATE SUBNET
############################################################

resource "google_compute_network" "main" {
  name                    = "prod-network"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "app" {
  name                     = "prod-app-subnet"
  region                   = "us-central1"
  network                  = google_compute_network.main.id
  ip_cidr_range            = "10.10.1.0/24"
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.20.0.0/16"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.30.0.0/20"
  }

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Private services connection for Cloud SQL private IP
resource "google_compute_global_address" "private_ip_alloc" {
  name          = "prod-private-ip-alloc"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc.name]
}

############################################################
# FIREWALL — restricted to internal VPC + IAP only
############################################################

# HTTPS from inside VPC
resource "google_compute_firewall" "allow_https_internal" {
  name    = "allow-https-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.10.0.0/16"]
  target_tags   = ["app-server"]
}

# SSH only from Google IAP CIDR (NOT 0.0.0.0/0)
resource "google_compute_firewall" "allow_ssh_iap" {
  name    = "allow-ssh-iap"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"] # IAP TCP forwarding range
  target_tags   = ["app-server"]
}

############################################################
# CLOUD SQL — REGIONAL HA, private IP, SSL enforced
############################################################

resource "google_sql_database_instance" "main" {
  name             = "prod-app-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  deletion_protection = true

  depends_on = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier              = "db-n1-standard-2"
    availability_type = "REGIONAL"
    disk_autoresize   = true
    disk_size         = 50
    disk_type         = "PD_SSD"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7

      backup_retention_settings {
        retained_backups = 14
        retention_unit   = "COUNT"
      }
    }

    maintenance_window {
      day          = 7
      hour         = 4
      update_track = "stable"
    }
  }
}

############################################################
# GCS BUCKET — uniform access, versioning, lifecycle, KMS
############################################################

resource "google_kms_key_ring" "main" {
  name     = "prod-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "bucket_key" {
  name            = "prod-bucket-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s" # 90 days
}

resource "google_storage_bucket" "data" {
  name                        = "prod-app-data-12345"
  location                    = "US"
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket_key.id
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
    condition {
      age = 30
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
    condition {
      age = 90
    }
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 2555 # ~7 years
    }
  }
}

############################################################
# PRIVATE GKE CLUSTER
############################################################

resource "google_container_cluster" "main" {
  name     = "prod-gke-cluster"
  location = "us-central1"
  project  = var.project_id

  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.app.id

  remove_default_node_pool = true
  initial_node_count       = 1

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.10.0.0/16"
      display_name = "internal-vpc"
    }
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  release_channel {
    channel = "REGULAR"
  }

  maintenance_policy {
    recurring_window {
      start_time = "2026-01-01T04:00:00Z"
      end_time   = "2026-01-01T08:00:00Z"
      recurrence = "FREQ=WEEKLY;BYDAY=SA"
    }
  }

  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
}

resource "google_container_node_pool" "primary" {
  name     = "prod-pool"
  location = "us-central1"
  cluster  = google_container_cluster.main.name

  node_count = 2

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = "e2-standard-2"
    disk_size_gb = 50
    disk_type    = "pd-standard"
    image_type   = "COS_CONTAINERD"

    service_account = google_service_account.gke_node.email
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }
}

############################################################
# COMPUTE INSTANCE — shielded VM, non-preemptible
############################################################

resource "google_compute_instance" "app" {
  name         = "prod-app-server"
  machine_type = "e2-standard-2"
  zone         = "us-central1-a"
  tags         = ["app-server"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 30
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app.id
    # No access_config block = no external IP (private only)
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    preemptible        = false
    automatic_restart  = true
    on_host_maintenance = "MIGRATE"
  }

  service_account {
    email  = google_service_account.app.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
    block-project-ssh-keys = "TRUE"
  }
}

############################################################
# IAM — least-privilege, scoped to specific service accounts
############################################################

resource "google_service_account" "app" {
  account_id   = "prod-app-sa"
  display_name = "Production App Service Account"
}

resource "google_service_account" "gke_node" {
  account_id   = "prod-gke-node-sa"
  display_name = "Production GKE Node Service Account"
}

# Scoped IAM binding — specific SA only, NOT allUsers / allAuthenticatedUsers
resource "google_project_iam_member" "app_storage_viewer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.app.email}"
}

resource "google_project_iam_member" "gke_node_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.gke_node.email}"
}

resource "google_project_iam_member" "gke_node_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.gke_node.email}"
}

############################################################
# VARIABLES
############################################################

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "db_password" {
  type        = string
  sensitive   = true
  description = "Database password (referenced via Secret Manager in production)"
}
