#!/bin/bash

# docker.sh - Docker installation script
# This script installs Docker on various Linux distributions using sudo

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

# Install Docker on Ubuntu/Debian
install_docker_debian_ubuntu() {
  echo "Installing Docker on Debian/Ubuntu-based system..."
  
  # Update package index
  sudo apt-get update

  # Install dependencies
  sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

  # Add Docker's official GPG key
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

  # Set up the repository
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  # Update package index again
  sudo apt-get update

  # Install Docker Engine
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  # Add current user to docker group
  sudo usermod -aG docker "$USER"
  echo "Added $USER to docker group. You'll need to log out and back in for this to take effect."
  
  # Start and enable Docker service
  sudo systemctl enable docker
  sudo systemctl start docker
}

# Install Docker on CentOS/RHEL/Fedora
install_docker_redhat() {
  echo "Installing Docker on Red Hat-based system..."
  
  # Install required packages
  sudo yum install -y yum-utils

  # Add Docker repository
  sudo yum-config-manager --add-repo https://download.docker.com/linux/$OS/docker-ce.repo

  # Install Docker
  sudo yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  # Start and enable Docker service
  sudo systemctl start docker
  sudo systemctl enable docker

  # Add current user to docker group
  sudo usermod -aG docker "$USER"
  echo "Added $USER to docker group. You'll need to log out and back in for this to take effect."
}

# Install Docker on Alpine
install_docker_alpine() {
  echo "Installing Docker on Alpine Linux..."
  
  # Update the package index
  sudo apk update

  # Install Docker
  sudo apk add docker docker-compose

  # Enable and start Docker service
  sudo rc-update add docker boot
  sudo service docker start

  # Add current user to docker group
  sudo addgroup "$USER" docker
  echo "Added $USER to docker group. You'll need to log out and back in for this to take effect."
}

# Install Docker on Arch Linux
install_docker_arch() {
  echo "Installing Docker on Arch Linux..."
  
  # Update the package index
  sudo pacman -Sy

  # Install Docker
  sudo pacman -S --noconfirm docker docker-compose

  # Enable and start Docker service
  sudo systemctl start docker
  sudo systemctl enable docker

  # Add current user to docker group
  sudo usermod -aG docker "$USER"
  echo "Added $USER to docker group. You'll need to log out and back in for this to take effect."
}

# Main installation process
main() {
  echo "Starting Docker installation with sudo..."
  
  # Detect OS
  OS=$(detect_os)
  echo "Detected OS: $OS"

  # Install Docker based on the detected OS
  case "$OS" in
    ubuntu|debian|raspbian)
      install_docker_debian_ubuntu
      ;;
    centos|fedora|rhel|amzn)
      install_docker_redhat
      ;;
    alpine)
      install_docker_alpine
      ;;
    arch|manjaro)
      install_docker_arch
      ;;
    *)
      echo "Unsupported OS: $OS"
      exit 1
      ;;
  esac

  # Verify installation
  echo "Verifying Docker installation..."
  docker --version
  
  echo "Docker has been successfully installed!"
  echo "You can run 'docker run hello-world' to verify that Docker is working correctly."
}

# Run the main function
main