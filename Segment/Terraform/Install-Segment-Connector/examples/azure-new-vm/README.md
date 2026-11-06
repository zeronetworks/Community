# Example: create a test Azure VM and install the Segment Connector

Creates a small Ubuntu 22.04 VM in a new resource group, with a network, a storage account and a container. Then it installs the Segment Connector on that VM. Use it to try the Azure path on a test subscription.

Read the [project README](../../README.md) first. It explains Terraform basics, the token handling and the security notes.

## What it creates

- A resource group, a virtual network, a subnet and a network card.
- A Linux VM (`Standard_B1s` by default, with SSH key login only). It has a private IP only.
- A storage account and a private container for the installer zip and the script.
- The Segment Connector install on the VM, through a `CustomScript` extension.

## Steps

1. Put the installer zip in the project's `installer/` folder.
2. Copy the settings file and fill it in. Pick a storage account name that is unique in Azure:

   ```sh
   cp terraform.tfvars.example terraform.tfvars
   ```

3. Set the token in your shell. Do not put it in `terraform.tfvars`:

   ```sh
   export TF_VAR_token='<paste token from the portal>'
   ```

4. Run the commands. The install waits for the VM and the container to exist (`depends_on`):

   ```sh
   terraform init
   terraform plan
   terraform apply
   ```

5. Check the output with the `how_to_view_output` command, or:

   ```sh
   az vm extension show --resource-group <resource-group> --vm-name <vm-name> --name zn-segment-connector --instance-view
   ```

## Notes

- The VM has a private IP only. To reach it for checks, use your own VPN, bastion or jump host.
- The test VM needs outbound access to the segment server (TCP 443) and to public DNS. Check that your network allows it.
- Remove the test resources when you finish: `terraform destroy` removes the VM, but it does **not** uninstall the agent first. Run the uninstall action before you destroy, if you want a clean removal from the portal too.
- Nothing in this example has been run against a real Azure account yet. See the [caveats](../../README.md#caveats-and-testing-status).
