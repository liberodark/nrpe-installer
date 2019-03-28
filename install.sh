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
  version="0.7.3"

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
distribution_old=$(cat /etc/issue | head -n +1 | awk '{print $1}')

nrpe_conf=/usr/local/nagios/etc/nrpe.cfg
port=5666
nrpe_plugin=/usr/local/nagios/libexec/

test ! -e "$nrpe_conf" || echo "This path already contains a folder" | exit
test ! -e "$nrpe_plugin" || echo "This path already contains a folder" | exit

plugins_conf='################################################################################\n 
#\n
# nrpe command configuration file\n
#\n
# COMMAND DEFINITIONS\n
# Syntax:\n
#       command[<command_name>]=<command_line>\n
#\n
command[service]=/usr/local/nagios/libexec/check_service.sh -o linux -t "systemctl list-units --state=failed"\n
command[memory]=/usr/local/nagios/libexec/check_mem.sh -w $ARG1$ -c $ARG2$\n
command[cpu]=/usr/local/nagios/libexec/check_cpu_utilization.sh -w $ARG1$ -c $ARG2$\n
command[users]=/usr/local/nagios/libexec/check_users -w $ARG1$ -c $ARG2$\n
command[load]=/usr/local/nagios/libexec/check_load -w $ARG1$ -c $ARG2$\n
command[check_load]=/usr/local/nagios/libexec/check_load -w $ARG1$ -c $ARG2$\n
command[swap]=/usr/local/nagios/libexec/check_swap -w $ARG1$ -c $ARG2$\n
command[disk]=/usr/local/nagios/libexec/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[usr_disk]=/usr/local/nagios/libexec/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[var_disk]=/usr/local/nagios/libexec/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m\n
command[zombie_procs]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -s Z\n
command[total_procs]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$\n
command[proc_named]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_crond]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_syslogd]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$\n
command[proc_rsyslogd]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$'


#==============================================
# INSTALL NRPE Debian
#==============================================
echo "Install Nagios NRPE Server"

  # Check OS & nrpe

  which nrpe &> /dev/null

  if [ $? != 0 ]; then

    if [[ "$distribution" =~ .CentOS || "$distribution" = CentOS || "$distribution" = Fedora ]]; then
      yum install -y gcc glibc glibc-common openssl openssl-devel perl wget &> /dev/null
      curl -L https://github.com/liberodark/nrpe-installer/releases/download/0.7.1/nrpe-offline.tar.gz| tar --strip-components=1 -xzv
      tar xzf nrpe.tar.gz &> /dev/null

      pushd nrpe-nrpe-3.2.1/
      ./configure --enable-command-args &> /dev/null
      make all &> /dev/null
      make install-groups-users &> /dev/null
      make install &> /dev/null
      make install-config &> /dev/null
      make install-init &> /dev/null
      update-rc.d nrpe defaults &> /dev/null # 5.x / 6.x
      systemctl enable nrpe.service &> /dev/null # 7.x
      popd

      pushd plugins/
      mv * $nrpe_plugin &> /dev/null
      popd

      pushd $nrpe_plugin
      chmod +x * && chown nagios:nagios *
      popd
      echo -e $plugins_conf >> $nrpe_conf 
    
    elif [[ "$distribution" =~ .Debian || "$distribution" = Debian || "$distribution" = Ubuntu ]]; then
      apt-get update &> /dev/null
      apt-get install -y autoconf automake gcc libc6 libmcrypt-dev make libssl-dev wget bc --force-yes &> /dev/null
      curl -L https://github.com/liberodark/nrpe-installer/releases/download/0.7.1/nrpe-offline.tar.gz| tar --strip-components=1 -xzv
      tar xzf nrpe.tar.gz &> /dev/null

      pushd nrpe-nrpe-3.2.1/
      ./configure --enable-command-args &> /dev/null
      make all &> /dev/null
      make install-groups-users &> /dev/null
      make install &> /dev/null
      make install-config &> /dev/null
      make install-init &> /dev/null
      update-rc.d nrpe defaults &> /dev/null # 7.x
      systemctl enable nrpe.service &> /dev/null # 8.x / 9.x
      popd

      pushd plugins/
      mv * $nrpe_plugin &> /dev/null
      popd

      pushd $nrpe_plugin
      chmod +x * && chown nagios:nagios *
      popd
      echo -e $plugins_conf >> $nrpe_conf
      
    fi
fi

#==============================================
# ADD IP IN NAGIOS_PATH
#==============================================

rp=$(grep "allowed_hosts=127.0.0.1" $nrpe_conf)
sed -i "s@${rp}*@allowed_hosts=127.0.0.1,${ip}@g" $nrpe_conf
sed -i "s@dont_blame_nrpe=0@dont_blame_nrpe=1@g" $nrpe_conf


#include=<somefile.cfg>

#==============================================
# FIREWALL
#==============================================
echo "Open Port NRPE Server"

# Check OS & nrpe

  if [ $? != 1 ]; then

    if [[ "$distribution" =~ .Ubuntu || "$distribution" = Ubuntu ]]; then
      apt-get install iptables-persistent
      iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      iptables-save > /etc/iptables/rules.v4
    
    elif [[ "$distribution" =~ .Fedora || "$distribution" = Fedora ]]; then
      iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      iptables-save > /etc/sysconfig/iptables
    
    elif [[ "$distribution" =~ .CentOS || "$distribution" = CentOS ]]; then
      iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      iptables-save > /etc/sysconfig/iptables
    
    elif [[ "$distribution" =~ .Debian || "$distribution" = Debian ]]; then
      apt-get install iptables-persistent
      iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      iptables-save > /etc/iptables/rules.v4
      
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
      service nrpe start &> /dev/null
      systemctl enable nagios-nrpe-server &> /dev/null
      systemctl restart nagios-nrpe-server &> /dev/null
      
    fi
fi
