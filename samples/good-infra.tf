provider "aws" {
  region = "us-east-1"
}

# ---------------------------------------------------------
# KMS KEY
# ---------------------------------------------------------

resource "aws_kms_key" "main" {
  description             = "Production encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# ---------------------------------------------------------
# SECURITY GROUP
# ---------------------------------------------------------

resource "aws_security_group" "app_sg" {
  name        = "production-app-sg"
  description = "Restricted application access"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "production"
  }
}

# ---------------------------------------------------------
# S3 BUCKET
# ---------------------------------------------------------

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-company-data-prod"
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.main.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
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
  }
}

# ---------------------------------------------------------
# RDS
# ---------------------------------------------------------

resource "aws_db_instance" "main_db" {
  identifier = "production-db"

  engine         = "postgres"
  engine_version = "14.5"

  instance_class    = "db.t3.medium"
  allocated_storage = 100

  username = var.db_username
  password = var.db_password

  publicly_accessible = false

  storage_encrypted = true
  kms_key_id        = aws_kms_key.main.arn

  multi_az                = true
  backup_retention_period = 14
  deletion_protection     = true

  performance_insights_enabled = true

  vpc_security_group_ids = [
    aws_security_group.app_sg.id
  ]
}

# ---------------------------------------------------------
# LAUNCH TEMPLATE
# ---------------------------------------------------------

resource "aws_launch_template" "app" {
  name_prefix   = "prod-app-"
  image_id      = var.ami_id
  instance_type = "t3.medium"

  vpc_security_group_ids = [
    aws_security_group.app_sg.id
  ]

  monitoring {
    enabled = true
  }

  metadata_options {
    http_tokens = "required"
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      encrypted   = true
      kms_key_id  = aws_kms_key.main.arn
      volume_size = 50
    }
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      Environment = "production"
    }
  }
}

# ---------------------------------------------------------
# AUTOSCALING GROUP
# ---------------------------------------------------------

resource "aws_autoscaling_group" "app_asg" {
  name = "production-asg"

  min_size         = 3
  max_size         = 10
  desired_capacity = 3

  health_check_type         = "EC2"
  health_check_grace_period = 300

  vpc_zone_identifier = var.private_subnet_ids

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

# ---------------------------------------------------------
# CLOUDWATCH ALARM
# ---------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 80
}