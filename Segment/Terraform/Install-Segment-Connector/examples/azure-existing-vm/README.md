# Example: install on an existing Azure VM

Installs the Segment Connector on a Linux VM that already exists in Azure. It looks up the VM by name and adds the install extension. It does not create or change the VM.

Read the [project README](../../README.md) first. It explains Terraform basics, the token handling and the security notes.

## What it creates

- One `CustomScript` VM extension on the existing VM (named `zn-segment-connector`).
- In the storage container you name: the installer zip and the script, as blobs.

## Steps

1. Put the installer zip in the project's `installer/` folder.
2. Copy the settings file and fill it in:

   ```sh
   cp terraform.tfvars.example terraform.tfvars
   ```

3. Set the token in your shell. Do not put it in `terraform.tfvars`:

   ```sh
   export TF_VAR_token='<paste token from the portal>'
   ```

4. Run the commands:

   ```sh
   terraform init
   terraform plan
   terraform apply
   ```

5. Check the output. The `how_to_view_output` value shows the command to run. Or run:

   ```sh
   az vm extension show --resource-group <vm-resource-group> --vm-name <vm-name> --name zn-segment-connector --instance-view
   ```

## Notes

- Azure allows only one `CustomScript` extension per VM. If the VM already has one, remove it or pick another VM.
- The storage account and container must already exist. This example does not create them.
- Your identity needs permission to read the VM and to write the extension, and to list keys on the storage account.
- Nothing in this example has been run against a real Azure account yet. See the [caveats](../../README.md#caveats-and-testing-status).
