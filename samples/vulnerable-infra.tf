# Intentionally insecure Terraform configuration for testing
# Contains: public database, open security groups, no encryption, hardcoded secrets

provider "aws" {
  region = "us-east-1"
}

# --- INSECURE: Security group open to the world ---
resource "aws_security_group" "db_sg" {
  name        = "database-sg"
  description = "Allow database access"
  vpc_id      = "vpc-12345"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # DANGER: Open to entire internet
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # DANGER: SSH open to entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- INSECURE: Public RDS instance with hardcoded password ---
resource "aws_db_instance" "main_db" {
  identifier        = "production-db"
  engine            = "postgres"
  engine_version    = "14.5"
  instance_class    = "db.r6g.2xlarge"
  allocated_storage = 1000

  username = "admin"
  password = "SuperSecret123!" # DANGER: Hardcoded password

  publicly_accessible     = true  # DANGER: Database on public internet
  storage_encrypted       = false # DANGER: No encryption at rest
  multi_az                = false # DANGER: No high availability
  backup_retention_period = 0     # DANGER: No backups

  vpc_security_group_ids = [aws_security_group.db_sg.id]

  skip_final_snapshot = true
}

# --- INSECURE: Public S3 bucket without encryption ---
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-sensitive-data"
  acl    = "public-read" # DANGER: Public access

  versioning {
    enabled = false # DANGER: No versioning
  }
}

# --- INSECURE: Standalone EC2 without IMDSv2 ---
resource "aws_instance" "app_server" {
  ami           = "ami-12345678"
  instance_type = "p4d.24xlarge" # Very expensive GPU instance

  # No metadata_options - vulnerable to SSRF/IMDSv1 attacks
  # No auto-scaling group
}

# --- INSECURE: Overly permissive IAM policy ---
resource "aws_iam_policy" "admin_policy" {
  name        = "full-admin-access"
  description = "Admin access policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# --- COST WASTE: Unattached EIP ---
resource "aws_eip" "unused_ip" {
  domain = "vpc"
}

# --- COST WASTE: NAT Gateway ---
resource "aws_nat_gateway" "main_nat" {
  allocation_id = aws_eip.unused_ip.id
  subnet_id     = "subnet-12345"
}

# --- INSECURE: Unencrypted EBS volume ---
resource "aws_ebs_volume" "data_vol" {
  availability_zone = "us-east-1a"
  size              = 1000
  type              = "io2"
  iops              = 5000
  encrypted         = false # DANGER: No encryption
}

# --- INSECURE: CloudTrail with logging disabled ---
resource "aws_cloudtrail" "main_trail" {
  name                       = "main-audit-trail"
  s3_bucket_name             = aws_s3_bucket.data_bucket.id
  enable_logging             = false # DANGER: Logging disabled
  is_multi_region_trail      = false # DANGER: Single region only
  enable_log_file_validation = false # DANGER: No log integrity
}

# --- INSECURE: HTTP listener on ALB ---
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/my-alb/abc123"
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/my-tg/abc123"
  }
}

# --- INSECURE: VPC without flow logs ---
resource "aws_vpc" "main_vpc" {
  cidr_block = "10.0.0.0/16"
}

# --- INSECURE: KMS key without rotation ---
resource "aws_kms_key" "data_key" {
  description         = "Data encryption key"
  enable_key_rotation = false # DANGER: No rotation
}

# --- RELIABILITY: DynamoDB without PITR ---
resource "aws_dynamodb_table" "sessions" {
  name           = "user-sessions"
  billing_mode   = "PROVISIONED"
  read_capacity  = 200
  write_capacity = 200
  hash_key       = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  # No point_in_time_recovery - DANGER
}

# --- RELIABILITY: Lambda without DLQ ---
resource "aws_lambda_function" "processor" {
  function_name = "event-processor"
  role          = aws_iam_policy.admin_policy.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  filename      = "lambda.zip"

  # No dead_letter_config - DANGER
  # No vpc_config - runs in public internet
}

# --- RELIABILITY: SQS without dead letter queue ---
resource "aws_sqs_queue" "events_queue" {
  name = "events-processing"
  # No redrive_policy - DANGER
}

# --- COST: CloudWatch logs with no retention ---
resource "aws_cloudwatch_log_group" "app_logs" {
  name = "/app/production"
  # No retention_in_days - unlimited retention
}
