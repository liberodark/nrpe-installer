#!/bin/bash
#
# About: Install NRPE automatically
# Author: liberodark
# Thanks : frju365, Booti386, erdnaxeli
# License: GNU GPLv3

version="0.9.4"

echo "Welcome on NRPE Install Script $version"

#=================================================
# CHECK ROOT
#=================================================

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

distribution=$(cat /etc/*release | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//g' | sed 's/["]//g' | awk '{print $1}')
#distribution_old=$(cat /etc/issue | head -n +1 | awk '{print $1}')

nrpe_conf=/usr/local/nagios/etc/nrpe.cfg
port=5666
nrpe_plugin=/usr/local/nagios/libexec/


if [ -e "$nrpe_conf" ]; then
echo "Error NRPE configuration already is installed"
exit
fi

if [ -e "$nrpe_plugin" ]; then
echo "Error NRPE plugin already is installed"
exit
fi

plugins_conf='
################################################################################ 
#
# nrpe command configuration file
#
# COMMAND DEFINITIONS
# Syntax:
#       command[<command_name>]=<command_line>
#
command[service]=/usr/local/nagios/libexec/check_service.sh -o linux -t "systemctl list-units --state=failed"
command[memory]=/usr/local/nagios/libexec/check_mem -w $ARG1$ -c $ARG2$
command[cpu]=/usr/local/nagios/libexec/check_cpu -w $ARG1$ -c $ARG2$
command[update]=sudo /usr/local/nagios/libexec/check_updates -lock /tmp/check_updates.lock -w $ARG1$ -c $ARG2$
command[users]=/usr/local/nagios/libexec/check_users -w $ARG1$ -c $ARG2$
command[load]=/usr/local/nagios/libexec/check_load -w $ARG1$ -c $ARG2$
command[check_load]=/usr/local/nagios/libexec/check_load -w $ARG1$ -c $ARG2$
command[swap]=/usr/local/nagios/libexec/check_swap -w $ARG1$ -c $ARG2$
command[disk]=/usr/local/nagios/libexec/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m
command[usr_disk]=/usr/local/nagios/libexec/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m
command[var_disk]=/usr/local/nagios/libexec/check_disk -w $ARG1$ -c $ARG2$ -p $ARG3$ -m
command[zombie_procs]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -s Z
command[total_procs]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$
command[proc_named]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$
command[proc_crond]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$
command[proc_syslogd]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$
command[proc_rsyslogd]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$'

compile_nrpe_ssl(){
      tar xzf nrpe.tar.gz > /dev/null 2>&1
      pushd nrpe-nrpe-3.2.1/ || exit
      ./configure --enable-command-args > /dev/null 2>&1
      make all > /dev/null 2>&1
      make install-groups-users > /dev/null 2>&1
      make install > /dev/null 2>&1
      make install-config > /dev/null 2>&1
      #echo >> /etc/services
      echo '# Nagios services' >> /etc/services
      echo 'nrpe    5666/tcp' >> /etc/services
      make install-init > /dev/null 2>&1
      popd || exit

      mv ./plugins/check* "$nrpe_plugin"

      pushd $nrpe_plugin || exit
      chmod +x ./check* && chown nagios:nagios ./check*
      echo -e "$plugins_conf" >> "$nrpe_conf"
      }

compile_nrpe_nossl(){
      tar xzf nrpe.tar.gz > /dev/null 2>&1
      pushd nrpe-nrpe-3.2.1/ || exit
      ./configure --enable-command-args --disable-ssl > /dev/null 2>&1
      make all > /dev/null 2>&1
      make install-groups-users > /dev/null 2>&1
      make install > /dev/null 2>&1
      make install-config > /dev/null 2>&1
      #echo >> /etc/services
      echo '# Nagios services' >> /etc/services
      echo 'nrpe    5666/tcp' >> /etc/services
      make install-init > /dev/null 2>&1
      popd || exit

      mv ./plugins/check* "$nrpe_plugin"

      pushd $nrpe_plugin || exit
      chmod +x ./check* && chown nagios:nagios ./check*
      echo -e "$plugins_conf" >> "$nrpe_conf"
      }

nrpe_ssl(){
echo "Install Nagios NRPE Server with SSL ($distribution)"

  # Check OS & nrpe

  if ! command -v nrpe > /dev/null 2>&1; then

    if [ "$distribution" = "CentOS" ] || [ "$distribution" = "Red\ Hat" ] || [ "$distribution" = "Oracle" ]; then
      yum install -y make gcc glibc glibc-common openssl openssl-devel PackageKit > /dev/null 2>&1

      compile_nrpe_ssl || exit
      
    elif [ "$distribution" = "Fedora" ]; then
      dnf install -y make gcc glibc glibc-common openssl openssl-devel PackageKit > /dev/null 2>&1
    
      compile_nrpe_ssl || exit
    
    elif [ "$distribution" = "Debian" ] || [ "$distribution" = "Ubuntu" ] || [ "$distribution" = "Deepin" ]; then
      apt-get update > /dev/null 2>&1
      apt-get install -y make autoconf automake gcc libc6 libmcrypt-dev libssl-dev openssl packagekit --force-yes > /dev/null 2>&1
    
      compile_nrpe_ssl || exit
      
    elif [ "$distribution" = "Clear" ]; then
      swupd bundle-add make c-basic-legacy openssl devpkg-openssl ansible packagekit > /dev/null 2>&1
    
      compile_nrpe_ssl || exit
      
    elif [ "$distribution" = "Manjaro" ] || [ "$distribution" = "Arch\ Linux" ]; then
      pacman -S make autoconf automake gcc glibc libmcrypt  openssl packagekit --noconfirm > /dev/null 2>&1
    
      compile_nrpe_ssl || exit
      
    elif [ "$distribution" = "openSUSE" ] || [ "$distribution" = "SUSE" ]; then
      zypper install -y make autoconf automake gcc glibc openssl openssl-devel PackageKit > /dev/null 2>&1
    
      compile_nrpe_ssl || exit

    fi
fi
}

nrpe_nossl(){
echo "Install Nagios NRPE Server without SSL ($distribution)"

  # Check OS & nrpe

  if ! command -v nrpe > /dev/null 2>&1; then

    if [ "$distribution" = "CentOS" ] || [ "$distribution" = "Red\ Hat" ] || [ "$distribution" = "Suse" ] || [ "$distribution" = "Oracle" ]; then
      yum install -y make gcc glibc glibc-common PackageKit > /dev/null 2>&1

      compile_nrpe_nossl || exit
      
    elif [ "$distribution" = "Fedora" ]; then
      dnf install -y make gcc glibc glibc-common openssl openssl-devel PackageKit > /dev/null 2>&1
    
      compile_nrpe_nossl || exit
    
    elif [ "$distribution" = "Debian" ] || [ "$distribution" = "Ubuntu" ] || [ "$distribution" = "Deepin" ]; then
      apt-get update > /dev/null 2>&1
      apt-get install -y make autoconf automake gcc libc6 libmcrypt-dev make packagekit --force-yes > /dev/null 2>&1
    
      compile_nrpe_nossl || exit
      
    elif [ "$distribution" = "Clear" ]; then
      swupd bundle-add make c-basic-legacy openssl ansible packagekit > /dev/null 2>&1
    
      compile_nrpe_nossl || exit
      
    elif [ "$distribution" = "Manjaro" ] || [ "$distribution" = "Arch\ Linux" ]; then
      pacman -S make autoconf automake gcc glibc libmcrypt packagekit --noconfirm > /dev/null 2>&1
    
      compile_nrpe_nossl || exit
      
    elif [ "$distribution" = "openSUSE" ] || [ "$distribution" = "SUSE" ]; then
       zypper install -y make autoconf automake gcc glibc PackageKit > /dev/null 2>&1
    
      compile_nrpe_nossl || exit

    fi
fi
}

#=================================================
# ASK
#=================================================

echo "What is your server ip ?"
read -r ip

#==============================================
# INSTALL NRPE
#==============================================

while true; do
    read -r -p "Compile with ssl ?" yn
    case $yn in
        [Yy]* ) nrpe_ssl; break;;
        [Nn]* ) nrpe_nossl; break;;
        * ) echo "Please answer yes or no.";;
    esac
done

#==============================================
# ADD IP IN NAGIOS_PATH
#==============================================
echo "Configure NRPE"

rp=$(grep "allowed_hosts=127.0.0.1" $nrpe_conf)
sed -i "s@${rp}*@allowed_hosts=127.0.0.1,${ip}@g" $nrpe_conf
sed -i "s@dont_blame_nrpe=0@dont_blame_nrpe=1@g" $nrpe_conf

#==============================================
# FIREWALL
#==============================================
echo "Open Port NRPE Server"

# Check OS & nrpe
    
    if [ "$distribution" = "CentOS" ] || [ "$distribution" = "Red\ Hat" ] || [ "$distribution" = "Suse" ] || [ "$distribution" = "Oracle" ]; then
      #firewall-cmd --permanent --zone=public --add-port=$port/tcp 
      #firewall-cmd --reload
      iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      #sudo iptables-save > /etc/sysconfig/iptables
      #sudo chkconfig iptables on
      #sudo service iptables save
    
    elif [ "$distribution" = "Debian" ] || [ "$distribution" = "Ubuntu" ] || [ "$distribution" = "Deepin" ]; then
      #apt-get install ufw -y
      #ufw default deny
      #ufw default allow outgoing
      #ufw allow 22/tcp && ufw allow 443/tcp && ufw allow $port/tcp
      #ufw enable
      #apt-get install iptables-persistent -y
      iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      #iptables-save > /etc/iptables/rules.v4
      
fi

#==============================================
# SystemD
#==============================================
echo "Start & Enable Nagios NRPE Server Service"

systemctl enable nrpe
systemctl restart nrpe
