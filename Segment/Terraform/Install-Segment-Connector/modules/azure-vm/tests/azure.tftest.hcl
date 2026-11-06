# Tests for the Azure VM module.
#
# These tests use mock providers, so no Azure account is needed and nothing
# real is created. Run them from modules/azure-vm with:
#   terraform init -backend=false
#   terraform test
#
# Needs Terraform 1.7 or newer.

# Fake results for the Azure calls the plan makes.
mock_provider "azurerm" {
  mock_data "azurerm_storage_account" {
    defaults = {
      primary_connection_string = "DefaultEndpointsProtocol=https;AccountName=fakeacct;AccountKey=ZmFrZQ==;EndpointSuffix=core.windows.net"
    }
  }

  mock_data "azurerm_storage_account_blob_container_sas" {
    defaults = {
      sas = "?sv=2023-01-03&sr=c&sp=r&sig=fake"
    }
  }

  mock_resource "azurerm_storage_blob" {
    defaults = {
      url = "https://fakeacct.blob.core.windows.net/zn-installer/fake.blob"
    }
  }
}

# Fake fixed time, so the SAS window is the same on every run.
mock_provider "time" {
  mock_resource "time_static" {
    defaults = {
      rfc3339 = "2026-11-04T12:00:00Z"
    }
  }
}

variables {
  # Two VMs, so we can check there is one extension per VM.
  virtual_machine_ids = [
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-one",
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-two",
  ]
  storage_account_name        = "fakeacct"
  storage_resource_group_name = "rg-test"
  storage_container_name      = "zn-installer"

  # The file only needs to exist, because the plan reads its checksum.
  # versions.tf is always present in this module.
  installer_zip_local_path = "versions.tf"

  token = "test-token-value-123"
}

# Run with the default settings: protected settings delivery, SAS links.
# This uses "apply" rather than "plan", because the protected settings
# include blob URLs and a SAS value that are only known after apply. The
# mock providers create nothing real.
run "install_uses_protected_settings" {
  command = apply

  assert {
    condition     = length(azurerm_virtual_machine_extension.script) == length(var.virtual_machine_ids)
    error_message = "There must be exactly one extension per VM ID."
  }

  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : ext.publisher == "Microsoft.Azure.Extensions"])
    error_message = "Every extension must use publisher Microsoft.Azure.Extensions."
  }

  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : ext.type == "CustomScript"])
    error_message = "Every extension must use type CustomScript."
  }

  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : ext.type_handler_version == "2.1"])
    error_message = "Every extension must use type handler version 2.1."
  }

  # The token must be inside the encrypted protected settings, as the
  # base64-encoded value in the command.
  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : jsondecode(ext.protected_settings).commandToExecute == "ZN_SEGMENT_CONNECTOR_TOKEN_B64=${base64encode("test-token-value-123")} /bin/bash segment-connector.sh"])
    error_message = "commandToExecute must carry the base64 token and run the script."
  }

  # The plain token must not show up in the public settings.
  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : length(regexall("test-token-value-123", ext.settings)) == 0])
    error_message = "The plain token must not appear in the public settings."
  }

  # Public settings must hold only the timestamp.
  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : length(keys(jsondecode(ext.settings))) == 1])
    error_message = "Public settings must hold only the re-run timestamp."
  }

  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : length(jsondecode(ext.protected_settings).fileUris) == 2])
    error_message = "Protected settings must list the script and the installer zip."
  }
}

# Changing reinstall_trigger must change the timestamp in the settings.
run "reinstall_trigger_changes_timestamp" {
  command = apply

  variables {
    reinstall_trigger = "rotation-2"
  }

  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : jsondecode(ext.settings).timestamp != run.install_uses_protected_settings.settings_timestamp])
    error_message = "A new reinstall_trigger must change the settings timestamp."
  }

  assert {
    condition     = alltrue([for ext in values(azurerm_virtual_machine_extension.script) : jsondecode(ext.settings).timestamp == output.settings_timestamp])
    error_message = "The settings timestamp must match the module's timestamp output."
  }
}
