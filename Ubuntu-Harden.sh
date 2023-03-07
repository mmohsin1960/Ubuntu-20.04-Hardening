#!/bin/bash

# Update and upgrade packages
sudo apt-get update -y
sudo apt-get upgrade -y

# Install and configure firewall
sudo apt-get install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable

# Disable root login and password authentication
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sudo systemctl reload sshd

# Install fail2ban to prevent brute-force attacks
sudo apt-get install fail2ban -y
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

# Disable unnecessary services
sudo systemctl disable bluetooth.service
sudo systemctl disable cups.service
sudo systemctl disable cups-browsed.service
sudo systemctl disable isc-dhcp-server.service
sudo systemctl disable isc-dhcp-server6.service
sudo systemctl disable keyboard-setup.service
sudo systemctl disable wpa_supplicant.service

# Remove unnecessary packages
sudo apt-get remove gnome-orca gnome-sudoku gnome-mines gnome-mahjongg firefox rhythmbox -y

# Enable automatic security updates
sudo apt-get install unattended-upgrades -y
sudo dpkg-reconfigure unattended-upgrades

# Configure file permissions
sudo chmod 700 /root
sudo chmod 600 /etc/shadow
sudo chmod 600 /etc/gshadow

# Use a separate partition for /tmp
sudo mkdir /tmp_tmp
sudo mount -t tmpfs -o nosuid,noexec,nodev tmpfs /tmp_tmp
sudo cp -Rpf /tmp/* /tmp_tmp/
sudo rm -rf /tmp/*
sudo chmod 1777 /tmp
sudo mount --bind /tmp_tmp /tmp

# Disable unused file systems
echo "install cramfs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install freevxfs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install jffs2 /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install hfs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install hfsplus /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install squashfs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
echo "install udf /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf


# Configure file system integrity checking
sudo apt-get install aide -y
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
sudo chmod 600 /var/lib/aide/aide.db
sudo sed -i 's/^.*\/boot.*$/#&/g' /etc/aide/aide.conf
sudo aide -c /etc/aide/aide.conf --init
sudo cp /var/lib/aide/aide.db /var/lib/aide/aide.db.bak
sudo aide -c /etc/aide/aide.conf
