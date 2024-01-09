# Define an array of URLs and Ports to test
$connections = @(
    @{ "Url" = "monitor.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "portal.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "download.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "access.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "2fa.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "cloud-prod-v2.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "register-prod.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "cloud-connector.zeronetworks.com"; "Port" = 443 },
    @{ "Url" = "connect-backend.zeronetworks.com"; "Port" = 443},
    @{ "Url" = "connect-auth.zeronetworks.com"; "Port" = 443},
    @{ "Url" = "connect.zeronetworks.com"; "Port" = 443},
    @{ "Url" = "34.74.201.149"; "Port" = 443},
    @{ "Url" = "35.201.109.138"; "Port" = 443}
)

# Loop through each URL and Port to run Test-NetConnection
$failedConnections = @()
foreach ($conn in $connections) {
    $url = $conn.Url
    $port = $conn.Port
    $result = Test-NetConnection -ComputerName $url -Port $port

    # Check the result and print out failures
    if (-not $result.TcpTestSucceeded) {
        Write-Host "Failed to connect to $url on port $port"
        $failedConnections += [PSCustomObject]@{ "Url" = $url; "Port" = $port }
    }
}

# Output the list of failed connections, if any
if ($failedConnections.Count -gt 0) {
    Write-Host "The following connections failed:"
    $failedConnections | Format-Table -AutoSize
} else {
    Write-Host "All connections succeeded."
}
