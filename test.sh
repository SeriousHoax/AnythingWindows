#!/bin/bash

#https://github.com/systemd/zram-generator

# Install zram-generator
sudo zypper --non-interactive in zram-generator

# Create configuration file for zram
echo '[zram0]
zram-size = ram
compression-algorithm = zstd' | sudo tee /etc/systemd/zram-generator.conf

# Create sysctl configuration for zram
echo 'vm.swappiness = 180
vm.watermark_boost_factor = 0
vm.watermark_scale_factor = 125
vm.page-cluster = 0' | sudo tee /etc/sysctl.d/99-vm-zram-parameters.conf

# Reload systemd daemon and start zram
sudo systemctl daemon-reload

# Start the correct zram service
sudo systemctl start systemd-zram-setup@zram0.service

# Check if the zram device is working
echo "check with"
echo "swapon or zramctl"
echo "or systemctl status systemd-zram-setup@zram0.service"
