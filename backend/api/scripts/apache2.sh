#!/bin/bash

# apache2.sh - Apache2 installation script
# This script installs Apache2 on various Linux distributions using sudo

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

# Install Apache2 on Ubuntu/Debian
install_apache2_debian_ubuntu() {
  echo "Installing Apache2 on Debian/Ubuntu-based system..."
  
  # Update package index
  sudo apt-get update

  # Install Apache2
  sudo apt-get install -y apache2

  # Start and enable Apache2 service
  sudo systemctl start apache2
  sudo systemctl enable apache2

  # Allow Apache through firewall if ufw is active
  if command -v ufw > /dev/null; then
    sudo ufw allow 'Apache Full'
  fi

  # Create a test page
  echo "<html><body><h1>Apache2 is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /var/www/html/apache2-test.html > /dev/null

  echo "Apache2 installation complete!"
}

# Install Apache (httpd) on CentOS/RHEL/Fedora
install_apache2_redhat() {
  echo "Installing Apache (httpd) on Red Hat-based system..."
  
  # Install Apache
  if [ "$OS" == "fedora" ]; then
    sudo dnf install -y httpd
  else
    sudo yum install -y httpd
  fi

  # Start and enable Apache service
  sudo systemctl start httpd
  sudo systemctl enable httpd

  # Configure firewall if firewalld is running
  if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --permanent --add-service=http
    sudo firewall-cmd --permanent --add-service=https
    sudo firewall-cmd --reload
  fi

  # Create a test page
  echo "<html><body><h1>Apache (httpd) is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /var/www/html/apache2-test.html > /dev/null

  echo "Apache (httpd) installation complete!"
}

# Install Apache2 on Alpine
install_apache2_alpine() {
  echo "Installing Apache2 on Alpine Linux..."
  
  # Update package index
  sudo apk update

  # Install Apache2
  sudo apk add apache2

  # Create necessary directories
  sudo mkdir -p /run/apache2

  # Configure Apache2 to start on boot
  sudo rc-update add apache2 default

  # Start Apache2 service
  sudo service apache2 start

  # Create a test page
  sudo mkdir -p /var/www/localhost/htdocs
  echo "<html><body><h1>Apache2 is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /var/www/localhost/htdocs/apache2-test.html > /dev/null

  echo "Apache2 installation complete!"
}

# Install Apache2 on Arch Linux
install_apache2_arch() {
  echo "Installing Apache2 on Arch Linux..."
  
  # Update package index
  sudo pacman -Sy

  # Install Apache
  sudo pacman -S --noconfirm apache

  # Start and enable Apache service
  sudo systemctl start httpd
  sudo systemctl enable httpd

  # Create a test page
  echo "<html><body><h1>Apache is successfully installed!</h1><p>Server is running.</p></body></html>" | sudo tee /srv/http/apache2-test.html > /dev/null

  echo "Apache installation complete!"
}

# Main installation process
main() {
  echo "Starting Apache2 installation with sudo..."
  
  # Detect OS
  OS=$(detect_os)
  echo "Detected OS: $OS"

  # Install Apache2 based on the detected OS
  case "$OS" in
    ubuntu|debian|raspbian)
      install_apache2_debian_ubuntu
      ;;
    centos|fedora|rhel|amzn)
      install_apache2_redhat
      ;;
    alpine)
      install_apache2_alpine
      ;;
    arch|manjaro)
      install_apache2_arch
      ;;
    *)
      echo "Unsupported OS: $OS"
      exit 1
      ;;
  esac

  # Verify installation
  echo "Verifying Apache2 installation..."
  if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ] || [ "$OS" == "raspbian" ]; then
    apache2 -v
  elif [ "$OS" == "alpine" ]; then
    httpd -v
  else
    httpd -v
  fi
  
  echo "Apache2 has been successfully installed!"
  echo "You can now access your web server at http://your-server-ip"
  echo "A test page is available at http://your-server-ip/apache2-test.html"
}

# Run the main function
main