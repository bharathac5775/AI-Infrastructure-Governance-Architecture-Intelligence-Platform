provider "aws" {
  region = "us-east-1"
}

# ---------------------------------------------------------
# SECURITY GROUP
# ---------------------------------------------------------

resource "aws_security_group" "app_sg" {
  name = "app-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------
# EC2
# ---------------------------------------------------------

resource "aws_instance" "app" {
  ami           = "ami-123456"
  instance_type = "t3.medium"

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  tags = {
    Name = "app-server"
  }
}

# ---------------------------------------------------------
# S3
# ---------------------------------------------------------

resource "aws_s3_bucket" "data" {
  bucket = "company-data"

  versioning {
    enabled = true
  }
}

# ---------------------------------------------------------
# RDS
# ---------------------------------------------------------

resource "aws_db_instance" "main" {
  identifier        = "main-db"
  engine            = "postgres"
  instance_class    = "db.t3.small"
  allocated_storage = 50

  username = var.db_user
  password = var.db_password

  publicly_accessible = false
  storage_encrypted   = true

  backup_retention_period = 7
}
