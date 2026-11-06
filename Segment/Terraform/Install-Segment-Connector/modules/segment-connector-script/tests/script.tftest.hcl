# Tests for the install script module.
# Each run is a "plan" only. No cloud account, no provider and no real token are needed.
# A sample token string is used to prove that the token only appears where it should.

variables {
  token = "SAMPLE-TOKEN-123"
}

# ---------------------------------------------------------------------------
# Default settings
# ---------------------------------------------------------------------------

run "default_args" {
  command = plan

  # The install run only gets -run-as zn-user by default.
  assert {
    condition     = output.install_args == ["-run-as", "zn-user"]
    error_message = "Default install_args should be [-run-as, zn-user]."
  }

  # user_data is the same text as the install script.
  assert {
    condition     = output.user_data == output.install_script
    error_message = "user_data should be the same text as install_script."
  }

  assert {
    condition     = strcontains(output.install_script, "'-run-as' 'zn-user'")
    error_message = "The install script should pass the quoted -run-as argument."
  }

  assert {
    condition     = strcontains(output.install_script, "/opt/zn-segment-connector-setup") && strcontains(output.install_script, "/var/zeronetworks/.zn-internal/identity.json")
    error_message = "The install script should use the default staging folder and identity file."
  }

  assert {
    condition     = length(output.script_sha256) == 64
    error_message = "script_sha256 should be a 64 character SHA-256 value."
  }

  # The default token source is "env", so the sample token must not be in the script.
  assert {
    condition     = !strcontains(output.install_script, "SAMPLE-TOKEN-123")
    error_message = "The default install script must not contain the sample token."
  }

  assert {
    condition     = !strcontains(output.install_script, "{{")
    error_message = "The install script must not contain a double opening brace."
  }
}

run "default_uninstall_script" {
  command = plan

  # The uninstall script runs in uninstall mode and calls -uninstall.
  # The template also holds the install branch, but it only runs when the action is install.
  assert {
    condition     = strcontains(output.uninstall_script, "ACTION='uninstall'") && strcontains(output.uninstall_script, "-uninstall")
    error_message = "The uninstall script should be set to uninstall mode and call -uninstall."
  }

  # By default it gets no -force flag.
  assert {
    condition     = !strcontains(output.uninstall_script, "'-force'")
    error_message = "By default the uninstall script should not pass -force."
  }

  assert {
    condition     = !strcontains(output.uninstall_script, "SAMPLE-TOKEN-123") && !strcontains(output.uninstall_script, "{{")
    error_message = "The uninstall script must not contain the token or a double opening brace."
  }
}

# ---------------------------------------------------------------------------
# Enrollment combinations (each one is valid)
# ---------------------------------------------------------------------------

run "enroll_allow_create_only" {
  command = plan

  variables {
    allow_create = true
  }

  assert {
    condition     = output.install_args == ["-run-as", "zn-user", "-allow-create"]
    error_message = "allow_create alone should add -allow-create."
  }
}

run "enroll_fqdn" {
  command = plan

  variables {
    allow_create = true
    asset_fqdn   = "connector01.example.com"
  }

  assert {
    condition     = output.install_args == ["-run-as", "zn-user", "-allow-create", "-asset-fqdn", "connector01.example.com"]
    error_message = "allow_create with asset_fqdn should add -asset-fqdn with the name."
  }
}

run "enroll_name" {
  command = plan

  variables {
    allow_create = true
    asset_name   = "connector-01"
  }

  assert {
    condition     = output.install_args == ["-run-as", "zn-user", "-allow-create", "-name", "connector-01"]
    error_message = "allow_create with asset_name should add -name."
  }
}

run "enroll_static_ip" {
  command = plan

  variables {
    allow_create   = true
    with_static_ip = true
    asset_name     = "connector-02"
  }

  assert {
    condition     = output.install_args == ["-run-as", "zn-user", "-allow-create", "-with-static-ip", "-name", "connector-02"]
    error_message = "with_static_ip should add -with-static-ip (and -name), not -asset-fqdn."
  }
}

run "enroll_fqdn_and_name" {
  command = plan

  variables {
    allow_create = true
    asset_fqdn   = "connector03.example.com"
    asset_name   = "connector-03"
  }

  assert {
    condition     = output.install_args == ["-run-as", "zn-user", "-allow-create", "-asset-fqdn", "connector03.example.com", "-name", "connector-03"]
    error_message = "asset_fqdn and asset_name should both be passed, in that order."
  }
}

run "asset_id_force_root" {
  command = plan

  variables {
    asset_id = "asset-123"
    force    = true
    run_as   = "root"
  }

  assert {
    condition     = output.install_args == ["-run-as", "root", "-force", "-assetId", "asset-123"]
    error_message = "asset_id, force and run_as root should give the expected install flags."
  }

  # force also adds -force to the uninstall script.
  assert {
    condition     = strcontains(output.uninstall_script, "'-force'")
    error_message = "force should also add -force to the uninstall script."
  }
}

run "uninstall_action_has_no_token" {
  command = plan

  variables {
    action       = "uninstall"
    token_source = "embedded"
    token        = "SAMPLE-TOKEN-123"
  }

  assert {
    condition     = strcontains(output.uninstall_script, "-uninstall") && !strcontains(output.uninstall_script, base64encode("SAMPLE-TOKEN-123"))
    error_message = "The uninstall script must not contain the encoded token, even with token_source embedded."
  }
}

# ---------------------------------------------------------------------------
# Download timeout and environment variables
# ---------------------------------------------------------------------------

run "download_timeout_number_is_seconds" {
  command = plan

  variables {
    download_timeout = "600"
  }

  assert {
    condition     = strcontains(output.install_script, "export ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT='600s'")
    error_message = "download_timeout 600 should be exported as 600s."
  }
}

run "download_timeout_go_duration" {
  command = plan

  variables {
    download_timeout = "10m"
  }

  assert {
    condition     = strcontains(output.install_script, "export ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT='10m'")
    error_message = "A Go duration download_timeout should be exported unchanged."
  }
}

run "named_settings_override_installer_env" {
  command = plan

  variables {
    trace            = true
    download_timeout = "90s"
    installer_env = {
      ZN_AGENT_INSTALLER_TRACE_ENABLED             = "false"
      ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT = "5m"
      KEEP_ME                                      = "yes"
    }
  }

  # trace = true wins over the installer_env value.
  assert {
    condition     = strcontains(output.install_script, "export ZN_AGENT_INSTALLER_TRACE_ENABLED='true'") && !strcontains(output.install_script, "ZN_AGENT_INSTALLER_TRACE_ENABLED='false'")
    error_message = "trace = true should override ZN_AGENT_INSTALLER_TRACE_ENABLED from installer_env."
  }

  # download_timeout wins over the installer_env value.
  assert {
    condition     = strcontains(output.install_script, "export ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT='90s'") && !strcontains(output.install_script, "ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT='5m'")
    error_message = "download_timeout should override ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT from installer_env."
  }

  # Other installer_env values still pass through.
  assert {
    condition     = strcontains(output.install_script, "export KEEP_ME='yes'")
    error_message = "Other installer_env values should still be exported."
  }
}

run "installer_env_passes_through_when_named_setting_off" {
  command = plan

  variables {
    trace          = false
    log_to_console = false
    installer_env = {
      ZN_AGENT_INSTALLER_TRACE_ENABLED        = "false"
      ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE = "false"
    }
  }

  assert {
    condition     = strcontains(output.install_script, "export ZN_AGENT_INSTALLER_TRACE_ENABLED='false'") && strcontains(output.install_script, "export ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE='false'")
    error_message = "When trace and log_to_console are off, installer_env values should be used as they are."
  }
}

run "log_to_console_sets_variable" {
  command = plan

  variables {
    log_to_console = true
  }

  assert {
    condition     = strcontains(output.install_script, "export ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE='true'")
    error_message = "log_to_console = true should export ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE='true'."
  }
}

run "empty_and_null_env_values_dropped" {
  command = plan

  variables {
    installer_env = {
      EMPTY_ONE = ""
      NULL_ONE  = null
      KEEP_ME   = "yes"
    }
  }

  assert {
    condition     = !strcontains(output.install_script, "EMPTY_ONE=") && !strcontains(output.install_script, "NULL_ONE=") && strcontains(output.install_script, "export KEEP_ME='yes'")
    error_message = "Empty and null installer_env values should be dropped."
  }
}

# ---------------------------------------------------------------------------
# Shell quoting
# ---------------------------------------------------------------------------

run "single_quote_in_env_value_is_escaped" {
  command = plan

  variables {
    installer_env = {
      GREETING = "it's"
    }
  }

  assert {
    condition     = strcontains(output.install_script, "export GREETING='it'\\''s'")
    error_message = "A single quote in an environment value should be written as '\\''."
  }
}

run "single_quote_in_argument_is_escaped" {
  command = plan

  variables {
    allow_create = true
    asset_name   = "O'Brien"
  }

  assert {
    condition     = strcontains(output.install_script, "'O'\\''Brien'")
    error_message = "A single quote in an installer argument should be written as '\\''."
  }
}

# ---------------------------------------------------------------------------
# Token handling
# ---------------------------------------------------------------------------

run "token_not_in_script_for_file_source" {
  command = plan

  variables {
    token_source = "file"
  }

  assert {
    condition     = !strcontains(output.install_script, "SAMPLE-TOKEN-123") && !strcontains(output.install_script, base64encode("SAMPLE-TOKEN-123")) && !strcontains(output.install_script, "{{")
    error_message = "With token_source file, the token must not be in the script."
  }
}

run "token_not_in_script_for_key_vault_source" {
  command = plan

  variables {
    token_source                = "azure_key_vault"
    azure_key_vault_name        = "example-vault"
    azure_key_vault_secret_name = "zn-token"
  }

  assert {
    condition     = !strcontains(output.install_script, "SAMPLE-TOKEN-123") && !strcontains(output.install_script, base64encode("SAMPLE-TOKEN-123")) && !strcontains(output.install_script, "{{")
    error_message = "With token_source azure_key_vault, the token must not be in the script."
  }

  assert {
    condition     = strcontains(output.install_script, "example-vault") && strcontains(output.install_script, "zn-token")
    error_message = "The Key Vault name and secret name should be in the script."
  }
}

run "token_embedded_is_base64_in_script" {
  command = plan

  variables {
    token_source = "embedded"
  }

  # The token is written in base64 form, never as plain text.
  assert {
    condition     = strcontains(output.install_script, base64encode("SAMPLE-TOKEN-123"))
    error_message = "With token_source embedded, the base64 form of the token should be in the script."
  }

  assert {
    condition     = !strcontains(output.install_script, "SAMPLE-TOKEN-123") && !strcontains(output.install_script, "{{")
    error_message = "With token_source embedded, the plain token must not appear as text in the script."
  }
}

run "token_env_source_valid_without_token" {
  command = plan

  variables {
    token = ""
  }

  assert {
    condition     = !strcontains(output.install_script, "{{")
    error_message = "The env token source should work without a token value."
  }
}

# ---------------------------------------------------------------------------
# Failures that are expected (each must be rejected)
# ---------------------------------------------------------------------------

# Single-variable checks: the variable's own validation rejects the value.

run "rejects_bad_action" {
  command = plan

  variables {
    action = "remove"
  }

  expect_failures = [var.action]
}

run "rejects_bad_token_source" {
  command = plan

  variables {
    token_source = "vault"
  }

  expect_failures = [var.token_source]
}

run "rejects_http_installer_url" {
  command = plan

  variables {
    installer_url = "http://example.com/segment-connector-linux-installer.zip"
  }

  expect_failures = [var.installer_url]
}

run "rejects_bad_env_name" {
  command = plan

  variables {
    installer_env = {
      "1BAD" = "x"
    }
  }

  expect_failures = [var.installer_env]
}

run "rejects_bad_download_timeout" {
  command = plan

  variables {
    download_timeout = "10x"
  }

  expect_failures = [var.download_timeout]
}

run "rejects_verify_timeout_below_10" {
  command = plan

  variables {
    verify_timeout = 5
  }

  expect_failures = [var.verify_timeout]
}

run "rejects_verify_timeout_fraction" {
  command = plan

  variables {
    verify_timeout = 10.5
  }

  expect_failures = [var.verify_timeout]
}

run "rejects_bad_run_as" {
  command = plan

  variables {
    run_as = "admin"
  }

  expect_failures = [var.run_as]
}

run "rejects_fqdn_that_is_an_ip" {
  command = plan

  variables {
    allow_create = true
    asset_fqdn   = "10.0.0.5"
  }

  expect_failures = [var.asset_fqdn]
}

run "rejects_fqdn_without_dot" {
  command = plan

  variables {
    allow_create = true
    asset_fqdn   = "connector01"
  }

  expect_failures = [var.asset_fqdn]
}

# Combination checks: the output precondition rejects the set of values.

run "rejects_fqdn_without_allow_create" {
  command = plan

  variables {
    asset_fqdn = "connector01.example.com"
  }

  expect_failures = [output.install_script]
}

run "rejects_name_without_allow_create" {
  command = plan

  variables {
    asset_name = "connector-01"
  }

  expect_failures = [output.install_script]
}

run "rejects_static_ip_without_allow_create" {
  command = plan

  variables {
    with_static_ip = true
    asset_name     = "connector-02"
  }

  expect_failures = [output.install_script]
}

run "rejects_static_ip_with_fqdn" {
  command = plan

  variables {
    allow_create   = true
    with_static_ip = true
    asset_name     = "connector-02"
    asset_fqdn     = "connector02.example.com"
  }

  expect_failures = [output.install_script]
}

run "rejects_static_ip_without_name" {
  command = plan

  variables {
    allow_create   = true
    with_static_ip = true
  }

  expect_failures = [output.install_script]
}

run "rejects_key_vault_without_names" {
  command = plan

  variables {
    token_source = "azure_key_vault"
  }

  expect_failures = [output.install_script]
}

run "rejects_embedded_without_token" {
  command = plan

  variables {
    token_source = "embedded"
    token        = ""
  }

  expect_failures = [output.install_script]
}

# ---------------------------------------------------------------------------
# Other settings
# ---------------------------------------------------------------------------
