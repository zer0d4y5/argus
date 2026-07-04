# PLANTED-VULNERABLE FIXTURE — DO NOT FIX. Deliberate misconfigurations for
# scanner coverage tests. See testdata/iac/labels.json.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "test-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name        = "open_ssh_sg"
  description = "Allow SSH from anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted_vol" {
  availability_zone = "us-east-1a"
  size              = 10
}
