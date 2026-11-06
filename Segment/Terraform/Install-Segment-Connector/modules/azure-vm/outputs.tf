# Values this module hands back after an apply.

output "extension_ids" {
  description = "Map from VM resource ID to the ID of its CustomScript extension."
  value       = { for vm_id, ext in azurerm_virtual_machine_extension.script : vm_id => ext.id }
}

output "how_to_view_output" {
  description = "Azure CLI commands that show what the script printed on each VM. Run one per VM."
  value = [
    for vm_id in var.virtual_machine_ids : format(
      "az vm extension show --resource-group %s --vm-name %s --name %s --instance-view",
      split("/", vm_id)[4],
      split("/", vm_id)[8],
      var.extension_name,
    )
  ]
}

output "settings_timestamp" {
  description = "The re-run number that goes into the extension settings. It changes when a re-run is needed. Marked sensitive because it is computed from the install script, which the core module marks sensitive."
  value       = local.rerun_timestamp
  sensitive   = true
}
