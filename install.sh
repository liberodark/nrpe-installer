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

app=nrpe
final_path=/etc/nagios/nrpe.d/
test ! -e "$final_path" || echo "This path already contains a folder" exit


#==============================================
# FIREWALL
#==============================================
echo Install Nagios NRPE Server

iptables -A INPUT -p tcp -m tcp --dport 5666 -j ACCEPT &> /dev/null

#==============================================
# INSTALL DEPS
#==============================================
echo Install Nagios NRPE Server

apt install -y nagios-nrpe-server nagios-plugins-basic &> /dev/null
yum install -y nrpe nagios-plugins-users nagios-plugins-load nagios-plugins-swap nagios-plugins-disk nagios-plugins-procs &> /dev/null

#==============================================
# SystemD
#==============================================
echo Stop Nagios NRPE Server Service

systemctl stop nagios-nrpe-server &> /dev/null

#==============================================
# Install Configuration
#==============================================
echo Install Nagios NRPE Configurations

echo
"################################################################################
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
command[proc_rsyslogd]=/usr/lib/nagios/plugins/check_procs -w 1: -c 1:2 -C rsyslogd" > $final_path/commands.cfg

systemctl enable nagios-nrpe-server &> /dev/null
systemctl start nagios-nrpe-server &> /dev/null
