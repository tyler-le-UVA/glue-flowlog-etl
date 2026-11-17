# -----------------------------------------------------------------------------
# Terraform + provider setup
# -----------------------------------------------------------------------------
terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # Remote state. Values come from backend.hcl (see backend.hcl.example) so the
  # state bucket name never has to be committed to Git.
  #   terraform init -backend-config=backend.hcl
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  # Every resource gets these tags automatically, so you can find (and cost-track)
  # everything this project created.
  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Milestone = "1-foundation"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}
