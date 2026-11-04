# These are the values this module shows after an apply.

output "association_id" {
  description = "The ID of the SSM association that runs the installer on the instances."
  value       = aws_ssm_association.install.association_id
}

output "document_name" {
  description = "The name of the SSM document that holds the install steps."
  value       = aws_ssm_document.install.name
}

output "script_sha256" {
  description = "A fingerprint of the script text. Changes when the script changes."
  value       = module.script.script_sha256
}

output "instance_read_policy_json" {
  description = "An IAM policy (JSON) that lets an instance role read only the connector files. Attach it to the instance role if you do not set instance_role_name."
  value       = local.instance_read_policy_json
}

output "how_to_view_output" {
  description = "An AWS CLI command that shows the results of the SSM runs on the instances."
  value       = "aws ssm list-command-invocations --details --filters key=DocumentName,value=${aws_ssm_document.install.name}"
}
