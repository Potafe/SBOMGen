#!/bin/bash

# Install Trivy
echo "Installing Trivy..."

apt-get update
apt-get install -y wget gnupg   # ensure prerequisites

# Download and store the GPG key (de-armored) in /usr/share/keyrings
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null

# Add the Trivy repository, referencing the signed-by keyring
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
  https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | tee /etc/apt/sources.list.d/trivy.list

# Update and install
apt-get update
apt-get install -y trivy

# Install Syft
echo "Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install CDXGen
echo "Installing CDXGen..."
npm install -g @cyclonedx/cdxgen

echo "All scanners installed."
