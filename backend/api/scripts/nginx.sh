#!/bin/bash

# nginx.sh - Nginx installation script
# This script installs Nginx on various Linux distributions using sudo

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

# Install Nginx on Ubuntu/Debian
install_nginx_debian_ubuntu() {
  echo "Installing Nginx on Debian/Ubuntu-based system..."
  
  # Update package index
  sudo apt-get update

  # Install Nginx
  sudo apt-get install -y nginx

  # Start and enable Nginx service
  sudo systemctl start nginx
  sudo systemctl enable nginx

  # Allow Nginx through firewall if ufw is active
  if command -v ufw > /dev/null; then
    sudo ufw allow 'Nginx HTTP'
    sudo ufw allow 'Nginx HTTPS'
  fi

  # Create basic status page for checking installation
  echo "Creating a basic status page..."
  echo "<html><body><h1>Nginx is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /var/www/html/nginx-status.html > /dev/null

  echo "Nginx installation complete!"
}

# Install Nginx on CentOS/RHEL/Fedora
install_nginx_redhat() {
  echo "Installing Nginx on Red Hat-based system..."
  
  # Add Nginx repository
  if [ "$OS" == "fedora" ]; then
    sudo dnf install -y nginx
  else
    # For CentOS/RHEL
    sudo yum install -y epel-release
    sudo yum install -y nginx
  fi

  # Start and enable Nginx service
  sudo systemctl start nginx
  sudo systemctl enable nginx

  # Configure firewall if firewalld is running
  if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --permanent --zone=public --add-service=http
    sudo firewall-cmd --permanent --zone=public --add-service=https
    sudo firewall-cmd --reload
  fi

  # Create basic status page for checking installation
  echo "Creating a basic status page..."
  echo "<html><body><h1>Nginx is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /usr/share/nginx/html/nginx-status.html > /dev/null

  echo "Nginx installation complete!"
}

# Install Nginx on Alpine
install_nginx_alpine() {
  echo "Installing Nginx on Alpine Linux..."
  
  # Update package index
  sudo apk update

  # Install Nginx
  sudo apk add nginx

  # Create necessary directories if they don't exist
  sudo mkdir -p /run/nginx

  # Configure Nginx to start on boot
  sudo rc-update add nginx default

  # Start Nginx service
  sudo service nginx start

  # Create basic status page for checking installation
  echo "Creating a basic status page..."
  sudo mkdir -p /var/www/localhost/htdocs
  echo "<html><body><h1>Nginx is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /var/www/localhost/htdocs/nginx-status.html > /dev/null

  echo "Nginx installation complete!"
}

# Install Nginx on Arch Linux
install_nginx_arch() {
  echo "Installing Nginx on Arch Linux..."
  
  # Update package index
  sudo pacman -Sy

  # Install Nginx
  sudo pacman -S --noconfirm nginx

  # Start and enable Nginx service
  sudo systemctl start nginx
  sudo systemctl enable nginx

  # Create basic status page for checking installation
  echo "Creating a basic status page..."
  echo "<html><body><h1>Nginx is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /usr/share/nginx/html/nginx-status.html > /dev/null

  echo "Nginx installation complete!"
}

# Main installation process
main() {
  echo "Starting Nginx installation with sudo..."
  
  # Detect OS
  OS=$(detect_os)
  echo "Detected OS: $OS"

  # Install Nginx based on the detected OS
  case "$OS" in
    ubuntu|debian|raspbian)
      install_nginx_debian_ubuntu
      ;;
    centos|fedora|rhel|amzn)
      install_nginx_redhat
      ;;
    alpine)
      install_nginx_alpine
      ;;
    arch|manjaro)
      install_nginx_arch
      ;;
    *)
      echo "Unsupported OS: $OS"
      exit 1
      ;;
  esac

  # Verify installation
  echo "Verifying Nginx installation..."
  nginx -v
  
  echo "Nginx has been successfully installed!"
  echo "You can now access your web server at http://your-server-ip"
  echo "A status page is available at http://your-server-ip/nginx-status.html"
}

# Run the main function
main