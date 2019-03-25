#!/bin/bash
#
# About: Install NRPE automatically
# Author: liberodark
# Thanks : frju365
# License: GNU GPLv3

#=================================================
# CHECK UPDATE
#=================================================

  update_source="https://raw.githubusercontent.com/liberodark/nrpe-installer/master/install.sh"
  version="0.5.6"

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
# IP
#=================================================

echo "What is your server ip ?"
read ip

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

distribution=$(cat /etc/*release | head -n +1 | awk '{print $1}')

nagios_path=/etc/nagios/nrpe.cfg

plugin1=https://raw.githubusercontent.com/jonschipp/nagios-plugins/master/check_service.sh
plugin2=https://raw.githubusercontent.com/June-Wang/NagiosPlugins/master/check_mem.sh
plugin3=https://raw.githubusercontent.com/June-Wang/NagiosPlugins/master/check_cpu_utilization.sh

port=5666

rhel_plugin=/usr/lib64/nagios/plugins
rhel_nrpe=/etc/nrpe.d
test ! -e "$rhel_plugin" || echo "This path already contains a folder" | exit
test ! -e "$rhel_nrpe" || echo "This path already contains a folder" | exit

deb_plugin=/usr/lib/nagios/plugins
deb_nrpe=/etc/nagios/nrpe.d
test ! -e "$deb_plugin" || echo "This path already contains a folder" | exit
test ! -e "$deb_nrpe" || echo "This path already contains a folder" | exit

deb_conf='################################################################################\n 
#\n
# nrpe command configuration file\n
#\n
# COMMAND DEFINITIONS\n
# Syntax:\n
#       command[<command_name>]=<command_line>\n
#\n
command[service]=/usr/lib/nagios/plugins/check_service.sh -o linux -t "systemctl list-units --state=failed"\n
command[memory]=/usr/lib/nagios/plugins/check_mem.sh -w $ARG1$ -c $ARG2$\n
command[cpu]=/usr/lib/nagios/plugins/check_cpu_utilization.sh -w $ARG1$ -c $ARG2$\n
command[users]=/usr/lib/nagios/plugins/check_users -w $ARG1$ -c $ARG2$\n
command[load]=/usr/lib/nagios/plugins/check_load -w $ARG1$ -c $ARG2$\n
command[check_load]=/usr/lib/nagios/plugins/check_load -w $ARG1$ -c $ARG2$\n
command[swap]=/usr/lib/nagios/plugins/check_swap -w $ARG1$ -c $ARG2$\n
command[root_disk]=/usr/lib/nagios/plugins/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[usr_disk]=/usr/lib/nagios/plugins/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[var_disk]=/usr/lib/nagios/plugins/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[zombie_procs]=/usr/lib/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -s Z\n
command[total_procs]=/usr/lib/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$\n
command[proc_named]=/usr/lib/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_crond]=/usr/lib/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_syslogd]=/usr/lib/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_rsyslogd]=/usr/lib/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$'

rhel_conf='################################################################################\n
#\n
# nrpe command configuration file\n
#\n
# COMMAND DEFINITIONS\n
# Syntax:\n
#       command[<command_name>]=<command_line>\n
#\n
command[service]=/usr/lib64/nagios/plugins/check_service.sh -o linux -t "systemctl list-units --state=failed"\n
command[memory]=/usr/lib64/nagios/plugins/check_mem.sh -w $ARG1$ -c $ARG2$\n
command[cpu]=/usr/lib64/nagios/plugins/check_cpu_utilization.sh -w $ARG1$ -c $ARG2$\n
command[users]=/usr/lib64/nagios/plugins/check_users -w $ARG1$ -c $ARG2$\n
command[load]=/usr/lib64/nagios/plugins/check_load -w $ARG1$ -c $ARG2$\n
command[check_load]=/usr/lib64/nagios/plugins/check_load -w $ARG1$ -c $ARG2$\n
command[swap]=/usr/lib64/nagios/plugins/check_swap -w $ARG1$ -c $ARG2$\n
command[root_disk]=/usr/lib64/nagios/plugins/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[usr_disk]=/usr/lib64/nagios/plugins/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[var_disk]=/usr/lib64/nagios/plugins/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[zombie_procs]=/usr/lib64/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -s Z\n
command[total_procs]=/usr/lib64/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$\n
command[proc_named]=/usr/lib64/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_crond]=/usr/lib64/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_syslogd]=/usr/lib64/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_rsyslogd]=/usr/lib64/nagios/plugins/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$'


#==============================================
# INSTALL NRPE Debian
#==============================================
echo "Install Nagios NRPE Server"

  # Check OS & nrpe

  which nrpe &> /dev/null

  if [ $? != 0 ]; then

    if [[ "$distribution" =~ .Ubuntu || "$distribution" = Ubuntu ]]; then
      apt install -y nagios-nrpe-server nagios-plugins-basic ufw bc &> /dev/null
      cd $deb_plugin
      wget $plugin1 &> /dev/null && wget $plugin2 &> /dev/null && wget $plugin3 &> /dev/null
      chmod +x check_service.sh && chmod +x check_mem.sh && chmod +x check_cpu_utilization.sh 
      echo -e $deb_conf > $deb_nrpe/commands.cfg
    
    elif [[ "$distribution" =~ .Fedora || "$distribution" = Fedora ]]; then
      dnf install -y nrpe nagios-plugins-users nagios-plugins-load nagios-plugins-swap nagios-plugins-disk nagios-plugins-procs firewalld bc &> /dev/null
      cd $rhel_plugin
      wget $plugin1 &> /dev/null && wget $plugin2 &> /dev/null && wget $plugin3 &> /dev/null
      chmod +x check_service.sh && chmod +x check_mem.sh && chmod +x check_cpu_utilization.sh 
      echo -e $rhel_conf > $rhel_nrpe/commands.cfg
    
    elif [[ "$distribution" =~ .CentOS || "$distribution" = CentOS ]]; then
      yum install -y epel-release nrpe nagios-plugins-users nagios-plugins-load nagios-plugins-swap nagios-plugins-disk nagios-plugins-procs firewalld bc &> /dev/null
      cd $rhel_plugin
      wget $plugin1 &> /dev/null && wget $plugin2 &> /dev/null && wget $plugin3 &> /dev/null
      chmod +x check_service.sh && chmod +x check_mem.sh && chmod +x check_cpu_utilization.sh 
      echo -e $rhel_conf > $rhel_nrpe/commands.cfg
    
    elif [[ "$distribution" =~ .Debian || "$distribution" = Debian ]]; then
      apt install -y nagios-nrpe-server nagios-plugins-basic ufw bc &> /dev/null
      cd $deb_plugin
      wget $plugin1 &> /dev/null && wget $plugin2 &> /dev/null && wget $plugin3 &> /dev/null
      chmod +x check_service.sh && chmod +x check_mem.sh && chmod +x check_cpu_utilization.sh 
      echo -e $deb_conf > $deb_nrpe/commands.cfg
      
    fi
fi

#==============================================
# ADD IP IN NAGIOS_PATH
#==============================================

rp=$(grep "allowed_hosts=127.0.0.1" $nagios_path)
sed -i "s@${rp}*@allowed_hosts=127.0.0.1,${ip}@g" $nagios_path
sed -i "s@dont_blame_nrpe=0@dont_blame_nrpe=1@g" $nagios_path

#==============================================
# FIREWALL
#==============================================
echo "Open Port NRPE Server"

# Check OS & nrpe

  if [ $? != 1 ]; then

    if [[ "$distribution" =~ .Ubuntu || "$distribution" = Ubuntu ]]; then
      ufw enable
      ufw allow $port/tcp
    
    elif [[ "$distribution" =~ .Fedora || "$distribution" = Fedora ]]; then
      systemctl enable firewalld
      systemctl start firewalld
      firewall-cmd --zone=public --add-port=$port/tcp --permanent &> /dev/nul
      firewall-cmd --reload &> /dev/null
    
    elif [[ "$distribution" =~ .CentOS || "$distribution" = CentOS ]]; then
      systemctl enable firewalld
      systemctl start firewalld
      firewall-cmd --zone=public --add-port=$port/tcp --permanent &> /dev/nul
      firewall-cmd --reload &> /dev/null
    
    elif [[ "$distribution" =~ .Debian || "$distribution" = Debian ]]; then
      ufw enable
      ufw allow $port/tcp
      
    fi
fi

#==============================================
# SystemD
#==============================================
echo "Start & Enable Nagios NRPE Server Service"

# Check OS & nrpe

  if [ $? != 1 ]; then

    if [[ "$distribution" =~ .Ubuntu || "$distribution" = Ubuntu ]]; then
      systemctl enable nagios-nrpe-server &> /dev/null
      systemctl restart nagios-nrpe-server &> /dev/null
    
    elif [[ "$distribution" =~ .Fedora || "$distribution" = Fedora ]]; then
      systemctl enable nrpe &> /dev/null
      systemctl restart nrpe &> /dev/null
    
    elif [[ "$distribution" =~ .CentOS || "$distribution" = CentOS ]]; then
      systemctl enable nrpe &> /dev/null
      systemctl restart nrpe &> /dev/null
    
    elif [[ "$distribution" =~ .Debian || "$distribution" = Debian ]]; then
      systemctl enable nagios-nrpe-server &> /dev/null
      systemctl restart nagios-nrpe-server &> /dev/null
      
    fi
fi
