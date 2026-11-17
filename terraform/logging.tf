# -----------------------------------------------------------------------------
# Raw flow-log storage: KMS-encrypted, private, versioned S3 bucket.
# This is the "Extract" source that Glue will crawl in milestone 2.
# -----------------------------------------------------------------------------

# --- Customer-managed KMS key ------------------------------------------------
data "aws_iam_policy_document" "flowlogs_kms" {
  # Let IAM policies in this account grant use of the key (e.g., the Glue role later).
  statement {
    sid       = "EnableIAMPolicies"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # Let the VPC Flow Logs delivery service encrypt objects it writes —
  # but only on behalf of THIS account (confused-deputy protection).
  statement {
    sid       = "AllowFlowLogsDelivery"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.aws_region}:${local.account_id}:*"]
    }
  }
}

resource "aws_kms_key" "flowlogs" {
  description             = "${var.project} flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.flowlogs_kms.json
}

resource "aws_kms_alias" "flowlogs" {
  name          = "alias/${var.project}-flowlogs"
  target_key_id = aws_kms_key.flowlogs.key_id
}

# --- Bucket ------------------------------------------------------------------
resource "aws_s3_bucket" "raw" {
  bucket        = "${var.project}-raw-${local.account_id}-${var.aws_region}"
  force_destroy = var.force_destroy_bucket
}

resource "aws_s3_bucket_public_access_block" "raw" {
  bucket                  = aws_s3_bucket.raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "raw" {
  bucket = aws_s3_bucket.raw.id
  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs disabled; the account owns every object
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.flowlogs.arn
    }
    bucket_key_enabled = true # cuts KMS request costs dramatically
  }
}

resource "aws_s3_bucket_versioning" "raw" {
  bucket = aws_s3_bucket.raw.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id

  rule {
    id     = "expire-raw-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = var.raw_log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.raw]
}

# --- Bucket policy -----------------------------------------------------------
data "aws_iam_policy_document" "raw_bucket" {
  # 1) Flow Logs delivery may write objects under raw/AWSLogs/ only.
  statement {
    sid       = "AWSLogDeliveryWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.raw.arn}/raw/AWSLogs/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.aws_region}:${local.account_id}:*"]
    }
  }

  # 2) Delivery service checks the bucket ACL before writing.
  statement {
    sid       = "AWSLogDeliveryAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.raw.arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${var.aws_region}:${local.account_id}:*"]
    }
  }

  # 3) Refuse any request that isn't over HTTPS.
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.raw.arn, "${aws_s3_bucket.raw.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "raw" {
  bucket     = aws_s3_bucket.raw.id
  policy     = data.aws_iam_policy_document.raw_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.raw]
}

# --- The flow log itself -----------------------------------------------------
resource "aws_flow_log" "lab" {
  vpc_id                   = aws_vpc.lab.id
  traffic_type             = "ALL" # ACCEPT + REJECT
  log_destination_type     = "s3"
  log_destination          = "${aws_s3_bucket.raw.arn}/raw/"
  max_aggregation_interval = 60 # 1-minute windows instead of the 10-minute default

  # Custom format: the default v2 fields plus extras the ETL job will use.
  # ($${...} is Terraform escaping for a literal ${...})
  log_format = join(" ", [
    "$${version}", "$${account-id}", "$${interface-id}",
    "$${srcaddr}", "$${dstaddr}", "$${srcport}", "$${dstport}",
    "$${protocol}", "$${packets}", "$${bytes}", "$${start}", "$${end}",
    "$${action}", "$${log-status}",
    "$${vpc-id}", "$${subnet-id}", "$${instance-id}",
    "$${tcp-flags}", "$${flow-direction}",
    "$${pkt-srcaddr}", "$${pkt-dstaddr}",
  ])

  # Deliberately plain-text (gzipped), NOT Parquet: converting to Parquet is
  # Glue's job in this project. Hive-style folders (year=/month=/day=/hour=)
  # let the Glue crawler detect partitions automatically.
  destination_options {
    file_format                = "plain-text"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }

  tags = { Name = "${var.project}-flowlog" }

  depends_on = [aws_s3_bucket_policy.raw]
}
