#!/bin/bash

# caddy.sh - Caddy installation script
# This script installs Caddy on various Linux distributions using sudo

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

# Install Caddy on Ubuntu/Debian
install_caddy_debian_ubuntu() {
  echo "Installing Caddy on Debian/Ubuntu-based system..."
  
  # Install required packages
  sudo apt-get update
  sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg

  # Add the Caddy official repository
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list

  # Update and install Caddy
  sudo apt-get update
  sudo apt-get install -y caddy

  # Start and enable Caddy service
  sudo systemctl start caddy
  sudo systemctl enable caddy

  # Allow Caddy through firewall if ufw is active
  if command -v ufw > /dev/null; then
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
  fi

  # Create a basic Caddyfile
  echo "Creating a basic Caddyfile..."
  echo ":80 {
  respond \"Caddy is successfully installed!\"
}" | sudo tee /etc/caddy/Caddyfile > /dev/null

  # Reload Caddy to apply changes
  sudo systemctl reload caddy

  echo "Caddy installation complete!"
}

# Install Caddy on CentOS/RHEL/Fedora
install_caddy_redhat() {
  echo "Installing Caddy on Red Hat-based system..."
  
  # Use dnf for Fedora, yum for others
  if [ "$OS" == "fedora" ]; then
    PKG_MGR="dnf"
  else
    PKG_MGR="yum"
  fi

  # Add EPEL repository if it's not Fedora
  if [ "$OS" != "fedora" ]; then
    sudo $PKG_MGR install -y epel-release
  fi

  # Install required packages
  sudo $PKG_MGR install -y yum-utils

  # Add official Caddy repository
  sudo $PKG_MGR-config-manager --add-repo https://copr.fedorainfracloud.org/coprs/g/caddy/caddy/repo/epel-9/caddy-caddy-epel-9.repo

  # Install Caddy
  sudo $PKG_MGR install -y caddy

  # Start and enable Caddy service
  sudo systemctl start caddy
  sudo systemctl enable caddy

  # Configure firewall if firewalld is running
  if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --reload
  fi

  # Create a basic Caddyfile
  echo "Creating a basic Caddyfile..."
  echo ":80 {
  respond \"Caddy is successfully installed!\"
}" | sudo tee /etc/caddy/Caddyfile > /dev/null

  # Reload Caddy to apply changes
  sudo systemctl reload caddy

  echo "Caddy installation complete!"
}

# Install Caddy on Alpine
install_caddy_alpine() {
  echo "Installing Caddy on Alpine Linux..."
  
  # Update package index
  sudo apk update

  # Install Caddy
  sudo apk add caddy

  # Create necessary directories
  sudo mkdir -p /etc/caddy

  # Configure Caddy to start on boot
  sudo rc-update add caddy default

  # Create a basic Caddyfile
  echo "Creating a basic Caddyfile..."
  echo ":80 {
  respond \"Caddy is successfully installed!\"
}" | sudo tee /etc/caddy/Caddyfile > /dev/null

  # Start Caddy service
  sudo service caddy start

  echo "Caddy installation complete!"
}

# Install Caddy on Arch Linux
install_caddy_arch() {
  echo "Installing Caddy on Arch Linux..."
  
  # Update package index
  sudo pacman -Sy

  # Install Caddy
  sudo pacman -S --noconfirm caddy

  # Start and enable Caddy service
  sudo systemctl start caddy
  sudo systemctl enable caddy

  # Create a basic Caddyfile
  echo "Creating a basic Caddyfile..."
  echo ":80 {
  respond \"Caddy is successfully installed!\"
}" | sudo tee /etc/caddy/Caddyfile > /dev/null

  # Reload Caddy to apply changes
  sudo systemctl reload caddy

  echo "Caddy installation complete!"
}

# For other systems - direct download from official site
install_caddy_direct() {
  echo "Installing Caddy directly from official source..."
  
  # Download the Caddy binary
  sudo curl -o /usr/local/bin/caddy -L "https://github.com/caddyserver/caddy/releases/latest/download/caddy_linux_amd64"
  
  # Make it executable
  sudo chmod +x /usr/local/bin/caddy
  
  # Allow binding to privileged ports
  sudo setcap cap_net_bind_service=+ep /usr/local/bin/caddy
  
  # Create user for Caddy
  sudo useradd -r -d /var/lib/caddy -m caddy
  
  # Create necessary directories
  sudo mkdir -p /etc/caddy /var/log/caddy
  sudo chown -R caddy:caddy /etc/caddy /var/log/caddy
  
  # Create systemd service file
  echo "[Unit]
Description=Caddy Web Server
Documentation=https://caddyserver.com/docs/
After=network.target

[Service]
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target" | sudo tee /etc/systemd/system/caddy.service > /dev/null

  # Create a basic Caddyfile
  echo "Creating a basic Caddyfile..."
  echo ":80 {
  respond \"Caddy is successfully installed!\"
}" | sudo tee /etc/caddy/Caddyfile > /dev/null
  
  # Reload systemd, enable and start Caddy
  sudo systemctl daemon-reload
  sudo systemctl enable caddy
  sudo systemctl start caddy
  
  echo "Caddy installation complete!"
}

# Main installation process
main() {
  echo "Starting Caddy installation with sudo..."
  
  # Detect OS
  OS=$(detect_os)
  echo "Detected OS: $OS"

  # Install Caddy based on the detected OS
  case "$OS" in
    ubuntu|debian|raspbian)
      install_caddy_debian_ubuntu
      ;;
    centos|fedora|rhel|amzn)
      install_caddy_redhat
      ;;
    alpine)
      install_caddy_alpine
      ;;
    arch|manjaro)
      install_caddy_arch
      ;;
    *)
      echo "Unsupported OS detected: $OS"
      echo "Attempting direct installation method..."
      install_caddy_direct
      ;;
  esac

  # Verify installation
  echo "Verifying Caddy installation..."
  caddy version
  
  echo "Caddy has been successfully installed!"
  echo "You can now access your web server at http://your-server-ip"
  echo "Caddy automatically obtains and renews TLS certificates for your domains."
}

# Run the main function
main