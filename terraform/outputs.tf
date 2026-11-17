output "vpc_id" {
  value = aws_vpc.lab.id
}

output "raw_bucket_name" {
  description = "Where flow logs land. Milestone 2's Glue crawler points here."
  value       = aws_s3_bucket.raw.bucket
}

output "raw_logs_prefix" {
  value = "s3://${aws_s3_bucket.raw.bucket}/raw/AWSLogs/"
}

output "kms_key_arn" {
  description = "The Glue job role will need kms:Decrypt on this key."
  value       = aws_kms_key.flowlogs.arn
}

output "flow_log_id" {
  value = aws_flow_log.lab.id
}

output "app_instance_id" {
  value = aws_instance.app.id
}

output "app_private_ip" {
  value = aws_instance.app.private_ip
}

output "scanner_instance_id" {
  value = aws_instance.scanner.id
}

output "scanner_private_ip" {
  value = aws_instance.scanner.private_ip
}
