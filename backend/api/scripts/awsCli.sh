#!/bin/bash

# aws-cli.sh - AWS CLI installation script
# This script installs AWS CLI v2 on various Linux distributions using sudo

# Function to detect OS
detect_os() {
  if [ -f /etc/os-release ]; then
    # freedesktop.org and systemd
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
  elif type lsb_release >/dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    VERSION=$(lsb_release -sr)
  elif [ -f /etc/lsb-release ]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    . /etc/lsb-release
    OS=$DISTRIB_ID
    VERSION=$DISTRIB_RELEASE
  elif [ -f /etc/debian_version ]; then
    # Older Debian/Ubuntu/etc.
    OS=debian
    VERSION=$(cat /etc/debian_version)
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    VERSION=$(uname -r)
  fi

  OS=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
  echo "$OS"
}

# Detect architecture
detect_arch() {
  ARCH=$(uname -m)
  if [ "$ARCH" = "x86_64" ]; then
    echo "x86_64"
  elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    echo "aarch64"
  else
    echo "Unsupported architecture: $ARCH"
    exit 1
  fi
}

# Install AWS CLI using the official installer
install_awscli_official() {
  echo "Installing AWS CLI using the official installer..."
  
  ARCH=$(detect_arch)
  TMPDIR=$(mktemp -d)
  
  # Install required packages
  if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ] || [ "$OS" = "raspbian" ]; then
    sudo apt-get update
    sudo apt-get install -y unzip curl
  elif [ "$OS" = "centos" ] || [ "$OS" = "fedora" ] || [ "$OS" = "rhel" ] || [ "$OS" = "amzn" ]; then
    if [ "$OS" = "fedora" ]; then
      sudo dnf install -y unzip curl
    else
      sudo yum install -y unzip curl
    fi
  elif [ "$OS" = "alpine" ]; then
    sudo apk update
    sudo apk add unzip curl
  elif [ "$OS" = "arch" ] || [ "$OS" = "manjaro" ]; then
    sudo pacman -Sy --noconfirm unzip curl
  fi
  
  # Download the appropriate AWS CLI package
  echo "Downloading AWS CLI v2 installer..."
  curl -s "https://awscli.amazonaws.com/awscli-exe-linux-$ARCH.zip" -o "$TMPDIR/awscliv2.zip"
  
  # Unzip and install
  echo "Extracting and installing AWS CLI..."
  unzip -q "$TMPDIR/awscliv2.zip" -d "$TMPDIR"
  sudo "$TMPDIR/aws/install"
  
  # Cleanup
  rm -rf "$TMPDIR"
  
  echo "AWS CLI has been installed to /usr/local/bin/aws"
}

# Install AWS CLI on Alpine (uses special method)
install_awscli_alpine() {
  echo "Installing AWS CLI on Alpine Linux..."
  
  # Update package index
  sudo apk update
  
  # Install Python and pip
  sudo apk add python3 py3-pip
  
  # Install AWS CLI using pip
  sudo pip3 install awscli
  
  echo "AWS CLI has been installed using pip"
}

# Main installation process
main() {
  echo "Starting AWS CLI installation with sudo..."
  
  # Detect OS
  OS=$(detect_os)
  echo "Detected OS: $OS"

  # Install AWS CLI based on the detected OS
  if [ "$OS" = "alpine" ]; then
    install_awscli_alpine
  else
    install_awscli_official
  fi

  # Verify installation
  echo "Verifying AWS CLI installation..."
  aws --version
  
  echo "AWS CLI has been successfully installed!"
  echo "You can configure your AWS credentials by running 'aws configure'"
}

# Run the main function
main