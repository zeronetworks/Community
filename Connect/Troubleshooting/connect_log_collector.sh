#!/bin/bash

# Synopsis:
# This script is designed to collect and compress support information for Zero Networks Connect Server.
# It provides the following functionalities:
# 1. Collect Connect Server information including host details, network interfaces, Wireguard information, and server logs.
# 2. Perform TCPDump for a specific Wireguard interface and source IP, capturing network traffic for a chosen duration.
# 3. Compress the collected information into a zip or tar.gz file for easy transfer to the Zero Networks Support team.

# Check if the script is being run with sudo
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (using sudo)" 
   exit 1
fi

# Function to collect Connect Server information
collect_connect_server_info() {
    echo "Collecting Connect Server information..."
    mkdir -p "$output_dir/connect_server_info" || { echo "Failed to create directory $output_dir/connect_server_info"; exit 1; }

    # Collect host information
    {
        echo "Hostname: $(hostname)"
        echo "Distro and version: $(lsb_release -ds)"
        echo "Network Interfaces:"
        ip addr show
        echo "Routing information:"
        ip route
    } > "$output_dir/connect_server_info/host_info.txt" || { echo "Failed to collect host information"; exit 1; }

    # Collect Wireguard information
    {
        echo "WG Interfaces:"
        wg show interfaces
        echo "WG Status:"
        wg
        echo "WG Connections:"
        wg show
    } > "$output_dir/connect_server_info/wg_info.txt" || { echo "Failed to collect Wireguard information"; exit 1; }

    # Collect Zero Networks Connect Server logs
    cp -r /var/log/zero-networks/connect-server/*.log "$output_dir/connect_server_info/" || { echo "Failed to copy logs"; exit 1; }

    echo "Connect Server information collected successfully."
}

# Function to perform TCPDump for a specific WG interface and source IP
perform_tcpdump() {
    echo "Performing TCPDump..."
    mkdir -p "$output_dir/tcpdump" || { echo "Failed to create directory $output_dir/tcpdump"; exit 1; }

    # List WG interfaces and prompt for selection
    wg_interfaces=($(wg show interfaces))
    if [ ${#wg_interfaces[@]} -eq 0 ]; then
        echo "No Wireguard interfaces found."
        exit 1
    elif [ ${#wg_interfaces[@]} -eq 1 ]; then
        selected_interface=${wg_interfaces[0]}
        echo "Only one WG interface found: $selected_interface. Using it by default."
    else
        echo "Available WG interfaces:"
        for i in "${!wg_interfaces[@]}"; do
            echo "$((i+1)). ${wg_interfaces[$i]}"
        done
        while :; do
            read -p "Select the WG interface (1-${#wg_interfaces[@]}): " interface_choice
            if [[ $interface_choice =~ ^[1-9][0-9]*$ ]] && [ $interface_choice -le ${#wg_interfaces[@]} ]; then
                selected_interface=${wg_interfaces[$((interface_choice-1))]}
                break
            else
                echo "Invalid choice. Please enter a number between 1 and ${#wg_interfaces[@]}."
            fi
        done
    fi

    # Prompt for source IP and validate it
    while :; do
        read -p "Enter the source IP to filter: " source_ip
        if [[ $source_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            break
        else
            echo "Invalid IP address format. Please try again."
        fi
    done

    # Prompt for duration
    echo "Select the duration for TCPDump:"
    echo "1. 1 minute"
    echo "2. 5 minutes"
    echo "3. 10 minutes"
    while :; do
        read -p "Enter your choice (1-3): " duration_choice
        case $duration_choice in
            1) duration=60; break ;;
            2) duration=300; break ;;
            3) duration=600; break ;;
            *) echo "Invalid choice. Please enter 1, 2, or 3." ;;
        esac
    done

    # Perform TCPDump
    tcpdump -i "$selected_interface" -n src host "$source_ip" -w "$output_dir/tcpdump/capture.pcap" -G "$duration" -W 1
    if [ $? -ne 0 ]; then
        echo "TCPDump failed."
        exit 1
    fi
    
    echo "TCPDump completed successfully."
}

# Function to compress the output directory
compress_output() {
    echo "Compressing the output directory..."
    
    if command -v zip &> /dev/null; then
        zip -r "${output_dir}.zip" "$output_dir"
    elif command -v tar &> /dev/null && command -v gzip &> /dev/null; then
        tar -czf "${output_dir}.tar.gz" "$output_dir"
    else
        echo "Neither zip nor tar and gzip commands found. Unable to compress the output directory."
        exit 1
    fi
    
    echo "Output directory compressed successfully."
}

# Main script

# Set the output directory name with the current timestamp
timestamp=$(date +"%d-%m-%Y-%H:%M")
output_dir="ZeroNetworks-$timestamp"
mkdir -p "$output_dir" || { echo "Failed to create directory $output_dir"; exit 1; }

# Display menu options
while true; do
    echo "Zero Networks Support Information Collection"
    echo "1. Collect Connect Server information"
    echo "2. Perform TCPDump for a specific WG interface and source IP"
    echo "3. Exit"
    read -p "Enter your choice (1-3): " choice
    
    case $choice in
        1) collect_connect_server_info ;;
        2) perform_tcpdump ;;
        3) break ;;
        *) echo "Invalid choice. Please try again." ;;
    esac
    
    echo
done

# Compress the output directory
compress_output

echo "Information collection completed. Please send the compressed file to Zero Networks Support team."
