#!/bin/bash

# Debian setup script
# This script installs and configures Tailscale and OpenSSH
# Created for Aidan Leuenberger

# Exit immediately if a command fails
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[!] $1${NC}"
}

# Must run as root
if [ "$(id -u)" -ne 0 ]; then
    print_error "This script must be run as root"
    exit 1
fi

# Update package lists
print_status "Updating package lists..."
apt-get update

# Install required packages
print_status "Installing required packages..."
apt-get install -y curl gnupg apt-transport-https sudo

# Install Tailscale
print_status "Installing Tailscale..."
curl -fsSL https://pkgs.tailscale.com/stable/debian/bullseye.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/debian/bullseye.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list

# Update package list again to include Tailscale repository
apt-get update
apt-get install -y tailscale

# Enable and start Tailscale service
print_status "Enabling Tailscale service..."
systemctl enable --now tailscaled

# Configure Tailscale with auth key from base64
print_status "Decoding Tailscale auth key..."
TAILSCALE_AUTH_KEY=$(echo "dHNrZXktYXV0aC1rZndKYnZLVWYyMTFDTlRSTC1FV1piRFoxaGJZRVp3SEZGYkdZTFlFRUdjN3lMalA3VDU=" | base64 -d)
print_status "Starting Tailscale..."
tailscale up --authkey "$TAILSCALE_AUTH_KEY" --hostname "$(hostname)-debian"

# Install and configure OpenSSH
print_status "Installing and configuring OpenSSH..."
apt-get install -y openssh-server

# Configure OpenSSH for password authentication
print_status "Enabling password authentication for SSH..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Ensure SSH starts on boot - handle different service names across Debian versions
print_status "Ensuring SSH starts on boot..."
# Try ssh service name first (Debian 11+)
if systemctl list-unit-files | grep -q ssh.service; then
    print_status "Enabling ssh service..."
    systemctl enable ssh
    systemctl restart ssh
# If that fails, try sshd service name (older Debian)
elif systemctl list-unit-files | grep -q sshd.service; then
    print_status "Enabling sshd service..."
    systemctl enable sshd
    systemctl restart sshd
# Last resort - try both
else
    print_status "Trying both service names..."
    systemctl enable ssh || systemctl enable sshd || true
    systemctl restart ssh || systemctl restart sshd || true
    # Verify SSH is running
    if ! pgrep sshd > /dev/null; then
        print_error "WARNING: Could not confirm SSH is running. You may need to start it manually."
    else
        print_status "SSH service is running!"
    fi
fi

# Add new user with password
print_status "Creating new user: wub333..."
useradd -m -s /bin/bash wub333

# Set password for the new user
print_status "Setting password for wub333..."
echo "wub333:Aidan@1197" | chpasswd

# Add user to sudo group
print_status "Adding wub333 to sudo group..."
usermod -aG sudo wub333

# Verify the user was added to sudoers
if groups wub333 | grep -q sudo; then
    print_status "User wub333 successfully added to sudoers!"
else
    print_error "Failed to add user wub333 to sudoers!"
fi

# Final status
print_status "Setup complete!"
print_status "Tailscale is running and configured to start on boot"
print_status "SSH is configured for password authentication and set to run on startup"
print_status "User wub333 is created with sudo privileges"

exit 0
