#!/bin/bash

# Install Trivy
echo "Installing Trivy..."

apt-get update
apt-get install -y wget gnupg software-properties-common

# Download and store the GPG key (de-armored) in /usr/share/keyrings
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null

# Add the Trivy repository, referencing the signed-by keyring
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] \
  https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | tee /etc/apt/sources.list.d/trivy.list

# Update and install
apt-get update
apt-get install -y trivy || {
  echo "Failed to install Trivy from repo, trying direct download..."
  wget https://github.com/aquasecurity/trivy/releases/download/v0.67.2/trivy_0.67.2_Linux-64bit.deb
  dpkg -i trivy_0.67.2_Linux-64bit.deb
  rm trivy_0.67.2_Linux-64bit.deb
}

# Install Syft
echo "Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install CDXGen
echo "Installing CDXGen..."
npm install -g @cyclonedx/cdxgen

# Create symlink for cdxgen if it doesn't exist in /usr/local/bin
if [ ! -f /usr/local/bin/cdxgen ]; then
  ln -sf /usr/local/lib/node_modules/@cyclonedx/cdxgen/bin/cdxgen.js /usr/local/bin/cdxgen
  chmod +x /usr/local/bin/cdxgen
fi

# Install CycloneDX CLI for merging SBOMs
echo "Installing CycloneDX CLI..."
npm install -g @cyclonedx/cyclonedx-cli

echo "All scanners installed."
