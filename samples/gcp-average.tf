############################################################
# GCP AVERAGE INFRASTRUCTURE — MIXED GAPS
############################################################

terraform {
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

# ---------------------------------------------------------
# VPC NETWORK
# ---------------------------------------------------------

resource "google_compute_network" "main" {
  name                    = "app-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "app" {
  name          = "app-subnet"
  region        = "us-central1"
  network       = google_compute_network.main.id
  ip_cidr_range = "10.0.1.0/24"
}

# ---------------------------------------------------------
# FIREWALL — SSH open to internet (gap)
# ---------------------------------------------------------

resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_https" {
  name    = "allow-https"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.0.0.0/8"]
}

# ---------------------------------------------------------
# GCS BUCKET — no lifecycle, no uniform access (gaps)
# ---------------------------------------------------------

resource "google_storage_bucket" "data" {
  name     = "app-data-bucket-12345"
  location = "US"

  versioning {
    enabled = true
  }
}

# ---------------------------------------------------------
# CLOUD SQL — public IP, no HA, no SSL (gaps)
# ---------------------------------------------------------

resource "google_sql_database_instance" "main" {
  name             = "app-db"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  deletion_protection = false

  settings {
    tier              = "db-custom-2-7680"
    availability_type = "ZONAL"

    ip_configuration {
      ipv4_enabled = true
      require_ssl  = false
    }

    backup_configuration {
      enabled = true
    }
  }
}

# ---------------------------------------------------------
# COMPUTE INSTANCE — no shielded VM (gap)
# ---------------------------------------------------------

resource "google_compute_instance" "app" {
  name         = "app-server"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app.id
  }

  metadata = {
    enable-oslogin = "true"
  }

  tags = ["app-server"]
}

# ---------------------------------------------------------
# VARIABLES
# ---------------------------------------------------------

variable "project_id" {
  type = string
}
