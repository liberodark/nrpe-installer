#!/bin/bash
#
# About: Install NRPE automatically
# Author: liberodark
# Thanks : frju365, Booti386
# License: GNU GPLv3

version="0.8.8"

echo "Welcome on NRPE Install Script $version"

#=================================================
# CHECK ROOT
#=================================================

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

#=================================================
# ASK
#=================================================

echo "What is your server ip ?"
read -r ip

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

distribution=$(cat /etc/*release | head -n +1 | awk '{print $1}')
#distribution_old=$(cat /etc/issue | head -n +1 | awk '{print $1}')

nrpe_conf=/usr/local/nagios/etc/nrpe.cfg
port=5666
nrpe_plugin=/usr/local/nagios/libexec/

test ! -e "$nrpe_conf" || echo "This path already contains a folder" | exit
test ! -e "$nrpe_plugin" || echo "This path already contains a folder" | exit

plugins_conf="
################################################################################\n 
#\n
# nrpe command configuration file\n
#\n
# COMMAND DEFINITIONS\n
# Syntax:\n
#       command[<command_name>]=<command_line>\n
#\n
command[service]=/usr/local/nagios/libexec/check_service.sh -o linux -t "systemctl list-units --state=failed"\n
command[memory]=/usr/local/nagios/libexec/check_mem -w $ARG1$ -c $ARG2$\n
command[cpu]=/usr/local/nagios/libexec/check_cpu -w $ARG1$ -c $ARG2$\n
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
command[proc_rsyslogd]=/usr/local/nagios/libexec/check_procs -w $ARG1$ -c $ARG2$ -C $ARG3$"

compile_nrpe_ssl(){
      tar xzf nrpe.tar.gz &> /dev/null
      pushd nrpe-nrpe-3.2.1/ || exit
      ./configure --enable-command-args &> /dev/null
      make all &> /dev/null
      make install-groups-users &> /dev/null
      make install &> /dev/null
      make install-config &> /dev/null
      echo >> /etc/services
      echo '# Nagios services' >> /etc/services
      echo 'nrpe    5666/tcp' >> /etc/services
      make install-init &> /dev/null
      popd || exit

      pushd plugins/ || exit
      mv * "$nrpe_plugin"
      popd || exit

      pushd $nrpe_plugin || exit
      chmod +x * && chown nagios:nagios *
      echo -e "$plugins_conf" >> $nrpe_conf
      }

compile_nrpe_nossl(){
      tar xzf nrpe.tar.gz &> /dev/null
      pushd nrpe-nrpe-3.2.1/ || exit
      ./configure --enable-command-args --disable-ssl &> /dev/null
      make all &> /dev/null
      make install-groups-users &> /dev/null
      make install &> /dev/null
      make install-config &> /dev/null
      echo >> /etc/services
      echo '# Nagios services' >> /etc/services
      echo 'nrpe    5666/tcp' >> /etc/services
      make install-init &> /dev/null
      popd || exit

      pushd plugins/ || exit
      mv * $nrpe_plugin
      popd || exit

      pushd $nrpe_plugin || exit
      chmod +x * && chown nagios:nagios *
      echo -e "$plugins_conf" >> $nrpe_conf
      popd || exit
      }

nrpe_ssl(){
echo "Install Nagios NRPE Server with SSL ($distribution)"

  # Check OS & nrpe

  command -v nrpe &> /dev/null

  if [ $? != 0 ]; then

    if [[ "$distribution" =~ .CentOS || "$distribution" = CentOS || "$distribution" =~ .Red\ Hat || "$distribution" =~ .Fedora || "$distribution" =~ .Suse ]]; then
      yum install -y make gcc glibc glibc-common openssl openssl-devel &> /dev/null

      compile_nrpe_ssl || exit
    
    elif [[ "$distribution" =~ .Debian || "$distribution" =~ .Ubuntu || "$distribution" =~ .Deepin ]]; then
      apt-get update
      apt-get install -y make autoconf automake gcc libc6 libmcrypt-dev libssl-dev openssl --force-yes &> /dev/null
    
      compile_nrpe_ssl || exit
      
    elif [[ "$distribution" =~ .Manjaro || "$distribution" =~ .Arch\ Linux ]]; then
      pacman -S make autoconf automake gcc glibc libmcrypt  openssl --noconfirm &> /dev/null
    
      compile_nrpe_ssl || exit

    fi
fi
}

nrpe_nossl(){
echo "Install Nagios NRPE Server without SSL ($distribution)"

  # Check OS & nrpe

  command -v nrpe &> /dev/null

  if [ $? != 0 ]; then

    if [[ "$distribution" =~ .CentOS || "$distribution" = CentOS || "$distribution" =~ .Red\ Hat || "$distribution" =~ .Fedora || "$distribution" =~ .Suse  ]]; then
      yum install -y make gcc glibc glibc-common &> /dev/null

      compile_nrpe_nossl || exit
    
    elif [[ "$distribution" =~ .Debian || "$distribution" =~ .Ubuntu || "$distribution" =~ .Deepin ]]; then
      apt-get update
      apt-get install -y make autoconf automake gcc libc6 libmcrypt-dev make --force-yes &> /dev/null
    
      compile_nrpe_nossl || exit
      
    elif [[ "$distribution" =~ .Manjaro || "$distribution" =~ .Arch\ Linux ]]; then
      pacman -S make autoconf automake gcc glibc libmcrypt --noconfirm &> /dev/null
    
      compile_nrpe_nossl || exit

    fi
fi
}

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

  if [ $? != 1 ]; then
    
    if [[ "$distribution" =~ .CentOS || "$distribution" = CentOS || "$distribution" =~ .Red || "$distribution" = RedHat || "$distribution" =~ .Fedora || "$distribution" = Fedora || "$distribution" =~ .Suse ]]; then
      firewall-cmd --permanent --zone=public --add-port=$port/tcp 
      firewall-cmd --reload
      #iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      #sudo iptables-save > /etc/sysconfig/iptables
      #sudo chkconfig iptables on
      #sudo service iptables save
    
    elif [[ "$distribution" =~ .Debian || "$distribution" = Debian || "$distribution" =~ .Ubuntu || "$distribution" = Ubuntu ]]; then
      #apt-get install ufw -y
      #ufw default deny
      #ufw default allow outgoing
      #ufw allow 22/tcp && ufw allow 443/tcp && ufw allow $port/tcp
      #ufw enable
      #apt-get install iptables-persistent -y
      iptables -I INPUT -p tcp --destination-port $port -j ACCEPT
      #iptables-save > /etc/iptables/rules.v4
      
    fi
fi

#==============================================
# SystemD
#==============================================
echo "Start & Enable Nagios NRPE Server Service"

systemctl enable nrpe 
systemctl restart nrpe
