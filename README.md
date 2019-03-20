# NRPE Installer
Nagios NRPE Installer

## How to use :

Copy and Past in your terminal :

```bash
wget -Nnv https://raw.githubusercontent.com/liberodark/nrpe-installer/master/install.sh && chmod +x install.sh; ./install.sh
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
tar -xvf nrpe.tar.gz
semodule -i nrpe.pp
```

## Plugins Configuration :

```
command[service]=/usr/lib64/nagios/plugins/check_service.sh -o linux -t "systemctl list-units --state=failed"\n
command[memory]=/usr/lib/nagios/plugins/check_mem.sh -w 70 -c 90\n
command[cpu]=/usr/lib/nagios/plugins/check_cpu_utilization.sh -w 70 -c 90\n
command[users]=/usr/lib64/nagios/plugins/check_users -w 5 -c 10\n
command[load]=/usr/lib64/nagios/plugins/check_load -w 15,10,5 -c 30,25,20\n
command[check_load]=/usr/lib64/nagios/plugins/check_load -w 15,10,5 -c 30,25,20\n
command[swap]=/usr/lib64/nagios/plugins/check_swap -w 20% -c 10%\n
command[root_disk]=/usr/lib64/nagios/plugins/check_disk -w 20% -c 10% -p / -m\n
command[usr_disk]=/usr/lib64/nagios/plugins/check_disk -w 20% -c 10% -p /usr -m\n
command[var_disk]=/usr/lib64/nagios/plugins/check_disk -w 20% -c 10% -p /var -m\n
command[zombie_procs]=/usr/lib64/nagios/plugins/check_procs -w 5 -c 10 -s Z\n
command[total_procs]=/usr/lib64/nagios/plugins/check_procs -w 190 -c 200\n
command[proc_named]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:2 -C named\n
command[proc_crond]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:5 -C crond\n
command[proc_syslogd]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:2 -C syslog-ng\n
command[proc_rsyslogd]=/usr/lib64/nagios/plugins/check_procs -w 1: -c 1:2 -C rsyslogd'
```

## Monitoring Compatibility :

https://www.eyesofnetwork.com/

https://www.centreon.com/

https://www.op5.com/

## Linux Compatibility :

- Debian 9
- Ubuntu 18.04
- Centos 7
- Fedora 29
