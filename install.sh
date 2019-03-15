#!/bin/bash
#
# About: Install NRPE automatically
# Author: liberodark
# License: GNU GPLv3

#=================================================
# CHECK UPDATE
#=================================================

  update_source="https://raw.githubusercontent.com/liberodark/nrpe-installer/master/install.sh"
  version="1.0.0"

  echo "Welcome on NRPE Install Script $version"

  # make update if asked
  if [ "$1" = "noupdate" ]; then
    update_status="false"
  else
    update_status="true"
  fi ;

  # update updater
  if [ "$update_status" = "true" ]; then
    wget -O $0 $update_source
    $0 noupdate
    exit 0
fi ;

#=================================================
# CHECK ROOT
#=================================================

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST
#=================================================

rhel_plugin=/usr/lib64/nagios/plugins/
rhel_nrpe=/etc/nrpe.d/
test ! -e "$rhel_plugin" || echo "This path already contains a folder" exit
test ! -e "$rhel_nrpe" || echo "This path already contains a folder" exit

deb_plugin=/usr/lib/nagios/plugins/
deb_nrpe=/etc/nagios/nrpe.d/
test ! -e "$deb_plugin" || echo "This path already contains a folder" exit
test ! -e "$deb_nrpe" || echo "This path already contains a folder" exit

#==============================================
# FIREWALL
#==============================================
echo Install Nagios NRPE Server

iptables -A INPUT -p tcp -m tcp --dport 5666 -j ACCEPT &> /dev/null

#==============================================
# INSTALL NRPE Debian
#==============================================
echo Install Nagios NRPE Server

  # Check OS & nrpe

  which nrpe &> /dev/null

  if [ $? != 0 ]; then
    echo "nrpe is not Installed"
     distribution=$(cat /etc/issue | head -n +1 | awk '{print $1}')

    if [ "$distribution" = "Ubuntu" ]; then
      apt install -y nagios-nrpe-server nagios-plugins-basic # Ubuntu / Debian
      wget -o check_service https://raw.githubusercontent.com/liberodark/nagios-plugins/master/check_service.sh
      mv check_service $deb_plugin
      chmod+x $deb_plugin/check_service
    
    elif [ "$distribution" = "Fedora" ]; then
      dnf install -y nrpe nagios-plugins-users nagios-plugins-load nagios-plugins-swap nagios-plugins-disk nagios-plugins-procs # Fedora
      wget -o check_service https://raw.githubusercontent.com/liberodark/nagios-plugins/master/check_service.sh
      mv check_service $rhel_plugin
      chmod+x $rhel_plugin/check_service
    
    elif [ "$distribution" = "CentOS" ]; then
      yum install -y nrpe nagios-plugins-users nagios-plugins-load nagios-plugins-swap nagios-plugins-disk nagios-plugins-procs # OpenSuse / CentOS
      wget -o check_service https://raw.githubusercontent.com/liberodark/nagios-plugins/master/check_service.sh
      mv check_service $rhel_plugin
      chmod+x $rhel_plugin/check_service
    
    elif [ "$distribution" = "Debian" ]; then
      apt install -y nagios-nrpe-server nagios-plugins-basic # Ubuntu / Debian
      wget -o check_service https://raw.githubusercontent.com/liberodark/nagios-plugins/master/check_service.sh
      mv check_service $deb_plugin
      chmod+x $deb_plugin/check_service
      
    fi
    else
  echo "nrpe is Installed"
fi

#==============================================
# SystemD
#==============================================
echo Stop Nagios NRPE Server Service

# Check OS & nrpe

  if [ $? != 1 ]; then
     distribution=$(cat /etc/issue | head -n +1 | awk '{print $1}')

    if [ "$distribution" = "Ubuntu" ]; then
      systemctl stop nagios-nrpe-server # Ubuntu / Debian
    
    elif [ "$distribution" = "Fedora" ]; then
      systemctl stop nrpe # Fedora
    
    elif [ "$distribution" = "CentOS" ]; then
      systemctl stop nrpe # OpenSuse / CentOS
    
    elif [ "$distribution" = "Debian" ]; then
      systemctl stop nagios-nrpe-server # Ubuntu / Debian
      
    fi
    else
fi

#==============================================
# Install Configuration Debian
#==============================================
echo Install Nagios NRPE Configurations

echo
'################################################################################
#
# nrpe command configuration file
#
# COMMAND DEFINITIONS
# Syntax:
#       command[<command_name>]=<command_line>
#
command[service]=/usr/lib/nagios/plugins/check_service -o linux -t "systemctl list-units --state=failed"
command[users]=/usr/lib/nagios/plugins/check_users -w 5 -c 10
command[load]=/usr/lib/nagios/plugins/check_load -w 15,10,5 -c 30,25,20
command[check_load]=/usr/lib/nagios/plugins/check_load -w 15,10,5 -c 30,25,20
command[swap]=/usr/lib/nagios/plugins/check_swap -w 20% -c 10%
command[root_disk]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p / -m
command[usr_disk]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /usr -m
command[var_disk]=/usr/lib/nagios/plugins/check_disk -w 20% -c 10% -p /var -m
command[zombie_procs]=/usr/lib/nagios/plugins/check_procs -w 5 -c 10 -s Z
command[total_procs]=/usr/lib/nagios/plugins/check_procs -w 190 -c 200
command[proc_named]=/usr/lib/nagios/plugins/check_procs -w 1: -c 1:2 -C named
command[proc_crond]=/usr/lib/nagios/plugins/check_procs -w 1: -c 1:5 -C cron
command[proc_syslogd]=/usr/lib/nagios/plugins/check_procs -w 1: -c 1:2 -C syslog-ng
command[proc_rsyslogd]=/usr/lib/nagios/plugins/check_procs -w 1: -c 1:2 -C rsyslogd' > $deb_nrpe/commands.cfg

#==============================================
# Install Configuration Centos
#==============================================
echo Install Nagios NRPE Configurations

echo
'################################################################################
#
# nrpe command configuration file
#
# COMMAND DEFINITIONS
# Syntax:
#       command[<command_name>]=<command_line>
#
command[service]=/usr/lib/nagios/plugins/check_service -o linux -t "systemctl list-units --state=failed"
command[users]=/usr/lib64/nagios/plugins/check_users -w 5 -c 10
command[load]=/usr/lib64/nagios/plugins/check_load -w 15,10,5 -c 30,25,20
command[check_load]=/usr/lib64/nagios/plugins/check_load -w 15,10,5 -c 30,25,20
command[swap]=/usr/lib64/nagios/plugins/check_swap -w 20% -c 10%
command[root_disk]=/usr/lib64/nagios/plugins/check_disk -w 20% -c 10% -p / -m
command[usr_disk]=/usr/lib64/nagios/plugins/check_disk -w 20% -c 10% -p /usr -m
command[var_disk]=/usr/lib64/nagios/plugins/check_disk -w 20% -c 10% -p /var -m
command[zombie_procs]=/usr/lib64/nagios/plugins/check_procs -w 5 -c 10 -s Z
command[total_procs]=/usr/lib64/nagios/plugins/check_procs -w 190 -c 200
command[proc_named]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:2 -C named
command[proc_crond]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:5 -C crond
command[proc_syslogd]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:2 -C syslog-ng
command[proc_rsyslogd]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:2 -C rsyslogd' > $rhel_nrpe/commands.cfg

#==============================================
# SystemD
#==============================================
echo Start & Enable Nagios NRPE Server Service

# Check OS & nrpe

  if [ $? != 1 ]; then
     distribution=$(cat /etc/issue | head -n +1 | awk '{print $1}')

    if [ "$distribution" = "Ubuntu" ]; then
      systemctl enable nagios-nrpe-server # Ubuntu / Debian
      systemctl start nagios-nrpe-server # Ubuntu / Debian
    
    elif [ "$distribution" = "Fedora" ]; then
      systemctl start nrpe # Fedora
      systemctl enable nrpe # Fedora
    
    elif [ "$distribution" = "CentOS" ]; then
      systemctl start nrpe # Fedora
      systemctl enable nrpe # Fedora
    
    elif [ "$distribution" = "Debian" ]; then
      systemctl enable nagios-nrpe-server # Ubuntu / Debian
      systemctl start nagios-nrpe-server # Ubuntu / Debian
      
    fi
    else
fi
