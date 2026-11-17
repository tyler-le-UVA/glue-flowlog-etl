# -----------------------------------------------------------------------------
# Lab network: one VPC, one public subnet, internet gateway.
# No NAT gateway on purpose (they cost ~$30+/month even when idle).
# -----------------------------------------------------------------------------

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project}-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true # instances need outbound internet for SSM + package installs

  tags = { Name = "${var.project}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Lock down the VPC's default security group so nothing accidentally uses it.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.lab.id
  # No ingress/egress blocks = all rules removed.
}

# -----------------------------------------------------------------------------
# Security groups — designed so the flow logs contain BOTH outcomes:
#   ACCEPT  : scanner -> app on TCP/80 (allowed)
#   REJECT  : scanner -> app on every other port (nmap scan), plus internet noise
# -----------------------------------------------------------------------------

resource "aws_security_group" "scanner" {
  name        = "${var.project}-scanner-sg"
  description = "Traffic generator. No inbound at all; manage via SSM."
  vpc_id      = aws_vpc.lab.id

  egress {
    description = "All outbound (SSM, dnf, curl, nmap)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-scanner-sg" }
}

resource "aws_security_group" "app" {
  name        = "${var.project}-app-sg"
  description = "Web server. Only HTTP from the scanner SG is allowed."
  vpc_id      = aws_vpc.lab.id

  ingress {
    description     = "HTTP from scanner only"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.scanner.id]
  }

  egress {
    description = "All outbound (SSM, dnf)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-app-sg" }
}
