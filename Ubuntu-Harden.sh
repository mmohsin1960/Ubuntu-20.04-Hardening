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


# Check AppArmor status
sudo aa-status

# Create backup of AppArmor configuration files
sudo cp /etc/apparmor.d/* /etc/apparmor.d.bak/

# Download and apply the CIS benchmark profile
sudo wget -O /etc/apparmor.d/usr.bin.firefox https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%204%20-%20Logging%2C%20Auditing%20and%20AppArmor/usr.bin.firefox
sudo wget -O /etc/apparmor.d/usr.sbin.sshd https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%204%20-%20Logging%2C%20Auditing%20and%20AppArmor/usr.sbin.sshd
sudo wget -O /etc/apparmor.d/usr.bin.libreoffice https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%204%20-%20Logging%2C%20Auditing%20and%20AppArmor/usr.bin.libreoffice

# Reload AppArmor profiles
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.firefox
sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.sshd
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.libreoffice

# Check AppArmor status again
sudo aa-status

sudo wget -O /etc/sysctl.d/99-cis.conf https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%203%20-%20Network%20Configuration/sysctl.conf
sudo sysctl -p

# Disable IPv6
sudo wget -O /etc/modprobe.d/ipv6.conf https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%203%20-%20Network%20Configuration/ipv6.conf
sudo modprobe -r ipv6

# Configure firewall
sudo apt-get update -y
sudo apt-get install -y ufw
sudo ufw reset
sudo wget -O /etc/ufw/ufw.conf https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%203%20-%20Network%20Configuration/ufw.conf
sudo wget -O /etc/ufw/sysctl.conf https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%203%20-%20Network%20Configuration/ufw_sysctl.conf
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable

# Configure SSH
sudo wget -O /etc/ssh/sshd_config https://raw.githubusercontent.com/a7vinx/CIS-Ubuntu20.04/main/Section%203%20-%20Network%20Configuration/sshd_config
sudo systemctl restart sshd.service
This script does the following:

Configures network parameters according to CIS benchmark.
Disables IPv6 according to CIS benchmark.
Installs and configures ufw firewall according to CIS benchmark.
Allows incoming SSH traffic and enables the firewall.
Configures SSH settings according to CIS benchmark.


#!/bin/bash

# Flush existing rules
sudo iptables -F

# Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback traffic
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related traffic
sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow SSH traffic
sudo iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -j ACCEPT

# Deny traffic from reserved ports
sudo iptables -A INPUT -p tcp --match multiport --dports 0:1023 -j DROP
sudo iptables -A INPUT -p udp --match multiport --dports 0:1023 -j DROP

# Deny ICMP redirects
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

# Deny source routed packets
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

# Log all dropped packets
sudo iptables -N LOGGING
sudo iptables -A INPUT -j LOGGING
sudo iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
sudo iptables -A LOGGING -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6




# Configure system auditing
sudo apt-get install -y auditd
sudo systemctl enable auditd
sudo sed -i 's/^space_left_action\s*=.*/space_left_action = email/g' /etc/audit/auditd.conf
sudo sed -i 's/^action_mail_acct\s*=.*/action_mail_acct = root/g' /etc/audit/auditd.conf
sudo sed -i 's/^admin_space_left_action\s*=.*/admin_space_left_action = halt/g' /etc/audit/auditd.conf
sudo sed -i 's/^max_log_file_action\s*=.*/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf
sudo systemctl restart auditd

# Configure system logging
sudo sed -i 's/#\s*ForwardToSyslog\s*=\s*yes/ForwardToSyslog = no/g' /etc/systemd/journald.conf
sudo sed -i 's/#\s*MaxRetentionSec\s*=\s*1week/MaxRetentionSec = 30days/g' /etc/systemd/journald.conf
sudo sed -i 's/#\s*SystemMaxUse\s*=\s*10%\s*$/SystemMaxUse = 50M/g' /etc/systemd/journald.conf
sudo systemctl restart systemd-journald


# Configure logrotate
sudo cat << EOF > /etc/logrotate.d/ubuntu-cis
/var/log/wtmp {
    monthly
    create 0664 root utmp
    rotate 12
    compress
    delaycompress
    missingok
}

/var/log/btmp {
    monthly
    create 0600 root utmp
    rotate 4
    compress
    delaycompress
    missingok
}

/var/log/messages {
    weekly
    rotate 4
    create 0640 root adm
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        invoke-rc.d rsyslog rotate > /dev/null
    endscript
}

/var/log/auth.log {
    weekly
    rotate 4
    create 0640 root adm
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        invoke-rc.d rsyslog rotate > /dev/null
    endscript
}
EOF


# Install SSH server if not already installed
apt-get update
apt-get -y install openssh-server

# Backup the original SSH configuration file
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configure SSH server according to CIS benchmark

# 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
chmod 600 /etc/ssh/sshd_config

# 5.2.2 - Ensure SSH Protocol is set to 2
sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config

# 5.2.3 - Ensure SSH LogLevel is set to INFO
sed -i 's/#LogLevel INFO/LogLevel INFO/' /etc/ssh/sshd_config

# 5.2.4 - Ensure SSH X11 forwarding is disabled
sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config

# 5.2.5 - Ensure SSH MaxAuthTries is set to 4 or less
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config

# 5.2.6 - Ensure SSH IgnoreRhosts is enabled
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config

# 5.2.7 - Ensure SSH HostbasedAuthentication is disabled
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config

# 5.2.8 - Ensure SSH root login is disabled
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# 5.2.9 - Ensure SSH PermitEmptyPasswords is disabled
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# 5.2.10 - Ensure SSH PermitUserEnvironment is disabled
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config

# 5.2.11 - Ensure only approved MAC algorithms are used
sed -i 's/#MACs .*/MACs hmac-sha2-512,hmac-sha2-256/' /etc/ssh/sshd_config

# 5.2.12 - Ensure SSH Idle Timeout Interval is configured
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

# 5.2.13 - Ensure SSH LoginGraceTime is set to one minute or less
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 1m/' /etc/ssh/sshd_config

# 5.2.14 - Ensure SSH access is limited
echo "AllowGroups sudo" >> /etc/ssh/sshd_config

# Restart SSH server
systemctl restart sshd
Note: This script assumes that the user executing the script has sudo privileges.







