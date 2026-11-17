variable "aws_region" {
  description = "Region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Short name used in resource names and tags."
  type        = string
  default     = "glue-flowlog-etl"
}

variable "vpc_cidr" {
  description = "CIDR for the lab VPC. Chosen to avoid overlapping the auditor project's lab VPC."
  type        = string
  default     = "10.50.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR for the single public subnet."
  type        = string
  default     = "10.50.1.0/24"
}

variable "instance_type" {
  description = "EC2 size for the two traffic-generating instances."
  type        = string
  default     = "t3.micro"
}

variable "alert_email" {
  description = "Email address that receives AWS Budgets alerts."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget (USD) for the alert."
  type        = number
  default     = 25
}

variable "raw_log_retention_days" {
  description = "Days to keep raw flow logs before S3 deletes them."
  type        = number
  default     = 30
}

variable "force_destroy_bucket" {
  description = "Let `terraform destroy` delete the bucket even if it still holds logs. Fine for a lab; never do this in production."
  type        = bool
  default     = true
}
