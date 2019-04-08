# NRPE Installer
Nagios NRPE Installer

## How to use :

Copy and Past in your terminal :

```bash
wget -Nnv https://raw.githubusercontent.com/liberodark/nrpe-installer/beta/install.sh && chmod +x install.sh; ./install.sh
```

## SELinux :


```bash
yum install -y policycoreutils-python
grep denied /var/log/audit/audit.log | audit2allow -M nrpe
semodule -i nrpe.pp
```

Or use nrpe from github :

```bash
wget -O nrpe.tar.gz https://github.com/liberodark/nrpe-installer/releases/download/1.0/nrpe.tar.gz
tar -xvf nrpe.tar.gz && sudo rm nrpe.tar.gz && semodule -i nrpe.pp
```

## Plugins Configuration :

```
command[service]=/usr/local/nagios/libexec/check_service.sh -o linux -t "systemctl list-units --state=failed"
command[memory]=/usr/local/nagios/libexec/check_mem.sh -w 70% -c 90%
command[memory_min]=/usr/local/nagios/libexec/check_mem.sh -w 70% -c 90% # For minimal informations
command[cpu]=/usr/local/nagios/libexec/check_cpu_utilization.sh -w 70 -c 90
command[cpu_min]=/usr/local/nagios/libexec/check_cpu_utilization.sh -w 70 -c 90 # For minimal informations
command[users]=/usr/local/nagios/libexec/check_users -w 5 -c 10
command[load]=/usr/local/nagios/libexec/check_load -w 15,10,5 -c 30,25,20
command[check_load]=/usr/local/nagios/libexec/check_load -w 15,10,5 -c 30,25,20
command[swap]=/usr/local/nagios/libexec/check_swap -w 20% -c 10%
command[root_disk]=/usr/local/nagios/libexec/check_disk -w 20% -c 10% -p / -m
command[usr_disk]=/usr/local/nagios/libexec/check_disk -w 20% -c 10% -p /usr -m
command[var_disk]=/usr/local/nagios/libexec/check_disk -w 20% -c 10% -p /var -m
command[zombie_procs]=/usr/local/nagios/libexec/check_procs -w 5 -c 10 -s Z
command[total_procs]=/usr/local/nagios/libexec/check_procs -w 190 -c 200
command[proc_named]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:2 -C named
command[proc_crond]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:5 -C crond
command[proc_syslogd]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:2 -C syslog-ng
command[proc_rsyslogd]=/usr/local/nagios/libexec/check_procs -w 1: -c 1:2 -C rsyslogd
```

## Monitoring Compatibility :

https://www.eyesofnetwork.com/

https://www.centreon.com/

https://www.op5.com/

## Debian 6.x / 7.x

Save your source list :

```cp -a /etc/apt/sources.list /etc/apt/sources.list.bak```

For Debian 6.x

```echo "deb http://archive.debian.org/debian/ squeeze main" >> /etc/apt/sources.list```

For Debian 7.x

```echo "deb http://archive.debian.org/debian/ wheezy main" >> /etc/apt/sources.list```

## Linux Compatibility :

- Debian 7.x / 8.x / 9.x
- Ubuntu 18.04
- Centos 6.x / 7.x
- Fedora 27 / 29
