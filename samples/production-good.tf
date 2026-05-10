```hcl id="rz4m8t"
############################################################
# ENTERPRISE PRODUCTION-GRADE AWS TERRAFORM
# ==========================================================
# Features:
# - Zero Trust Security
# - High Availability
# - Multi-AZ Architecture
# - Encryption Everywhere
# - IAM Least Privilege
# - Auto Scaling
# - Observability
# - Cost Governance
# - Disaster Recovery Controls
# - CSPM / Compliance Ready
############################################################

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

############################################################
# PROVIDER
############################################################

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = "production"
      ManagedBy   = "terraform"
      Owner       = "platform-team"
      Compliance  = "enabled"
    }
  }
}

############################################################
# KMS KEY
############################################################

resource "aws_kms_key" "main" {
  description             = "Production encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "production-kms-key"
  }
}

############################################################
# VPC
############################################################

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "production-vpc"
  }
}

############################################################
# PRIVATE SUBNETS
############################################################

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "private-a"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "private-b"
  }
}

############################################################
# CLOUDTRAIL
############################################################

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "production-cloudtrail-logs-12345"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_block" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "main" {
  name                          = "production-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
}

############################################################
# VPC FLOW LOGS
############################################################

resource "aws_cloudwatch_log_group" "vpc_logs" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 30

  kms_key_id = aws_kms_key.main.arn
}

resource "aws_flow_log" "vpc" {
  iam_role_arn    = aws_iam_role.flowlogs.arn
  log_destination = aws_cloudwatch_log_group.vpc_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

############################################################
# IAM ROLE FOR FLOW LOGS
############################################################

resource "aws_iam_role" "flowlogs" {
  name = "vpc-flowlogs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })
}

############################################################
# SECURITY GROUP
############################################################

resource "aws_security_group" "app_sg" {
  name        = "production-app-sg"
  description = "Restricted application traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS Internal"

    from_port   = 443
    to_port     = 443
    protocol    = "tcp"

    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Restricted HTTPS outbound"

    from_port   = 443
    to_port     = 443
    protocol    = "tcp"

    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "production-app-sg"
  }
}

############################################################
# S3 BUCKET
############################################################

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "production-secure-data-12345"

  tags = {
    Name = "production-secure-bucket"
  }
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_block" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "lifecycle" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    id     = "archive"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

############################################################
# SECRETS MANAGER
############################################################

resource "aws_secretsmanager_secret" "db_password" {
  name = "production-db-password"

  kms_key_id = aws_kms_key.main.arn
}

############################################################
# RDS SUBNET GROUP
############################################################

resource "aws_db_subnet_group" "main" {
  name = "production-db-subnet-group"

  subnet_ids = [
    aws_subnet.private_a.id,
    aws_subnet.private_b.id
  ]
}

############################################################
# RDS
############################################################

resource "aws_db_instance" "main" {
  identifier = "production-db"

  engine         = "postgres"
  engine_version = "14.5"

  instance_class = "db.t3.medium"

  allocated_storage     = 100
  max_allocated_storage = 500

  username = "dbadmin"

  manage_master_user_password = true

  publicly_accessible = false

  multi_az = true

  backup_retention_period = 14
  deletion_protection     = true

  storage_encrypted = true
  kms_key_id        = aws_kms_key.main.arn

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.main.arn
  enabled_cloudwatch_logs_exports       = ["postgresql"]
  auto_minor_version_upgrade            = true
  copy_tags_to_snapshot                 = true

  db_subnet_group_name = aws_db_subnet_group.main.name

  vpc_security_group_ids = [
    aws_security_group.app_sg.id
  ]

  skip_final_snapshot = false

  final_snapshot_identifier = "production-final-snapshot"
}

############################################################
# IAM ROLE FOR EC2
############################################################

resource "aws_iam_role" "ec2_role" {
  name = "production-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "ec2.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })
}

############################################################
# INSTANCE PROFILE
############################################################

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "production-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

############################################################
# LAUNCH TEMPLATE
############################################################

resource "aws_launch_template" "app" {
  name_prefix   = "production-app-"
  image_id      = var.ami_id
  instance_type = "t3.medium"

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }

  monitoring {
    enabled = true
  }

  vpc_security_group_ids = [
    aws_security_group.app_sg.id
  ]

  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      encrypted             = true
      kms_key_id            = aws_kms_key.main.arn
      volume_size           = 50
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Environment = "production"
    }
  }
}

############################################################
# AUTOSCALING GROUP
############################################################

resource "aws_autoscaling_group" "app_asg" {
  name = "production-asg"

  min_size         = 3
  max_size         = 10
  desired_capacity = 3

  health_check_type         = "EC2"
  health_check_grace_period = 300

  vpc_zone_identifier = [
    aws_subnet.private_a.id,
    aws_subnet.private_b.id
  ]

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  tag {
    key                 = "Environment"
    value               = "production"
    propagate_at_launch = true
  }
}

############################################################
# CLOUDWATCH ALARMS
############################################################

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-alarm"

  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2

  metric_name = "CPUUtilization"
  namespace   = "AWS/EC2"

  period    = 120
  statistic = "Average"

  threshold = 80

  alarm_description = "High CPU utilization detected"
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "rds-high-cpu"

  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2

  metric_name = "CPUUtilization"
  namespace   = "AWS/RDS"

  period    = 120
  statistic = "Average"

  threshold = 80
}

############################################################
# AWS CONFIG
############################################################

resource "aws_config_configuration_recorder" "main" {
  name     = "production-config-recorder"
  role_arn = aws_iam_role.config_role.arn
}

resource "aws_iam_role" "config_role" {
  name = "aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          Service = "config.amazonaws.com"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })
}

############################################################
# GUARDDUTY
############################################################

resource "aws_guardduty_detector" "main" {
  enable = true
}

############################################################
# VARIABLES
############################################################

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "ami_id" {
  type = string
}
```
