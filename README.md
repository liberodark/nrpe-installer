# NRPE Installer

Nagios NRPE Installer is a script for install NRPE with a same configaration on most linux very easily.

And use custom and official nagios plugins :  https://github.com/nagios-plugins/nagios-plugins/

This product is for help supervision of yours servers or pc.


### How to use for Systemd OS :

Copy and Past in your terminal :

```bash
git clone https://github.com/liberodark/nrpe-installer && cd nrpe-installer && chmod +x install.sh; ./install.sh
```


### How to use for SysV / Upstart OS :

Copy and Past in your terminal :

```bash
git clone https://github.com/liberodark/nrpe-installer && cd nrpe-installer && chmod +x install-debug-old.sh; ./install-debug-old.sh
```

### Compile plugins :

#### For check_cpu :

`gcc check_cpu.c -o check_cpu -std=gnu99`

#### For check_logs :

`gcc -g check_logs.c -o check_logs -lcrypto -llzma -std=gnu99`

#### How to work check_logs plugin :

More information :
https://github.com/liberodark/nrpe-installer/wiki/Plugin-check_logs

#### For check_updates :

Debian : `apt install libpackagekit-glib2-dev`

Centos : `yum install PackageKit-glib-devel`

`gcc -g check_updates.c -o check_updates $(pkg-config --cflags --libs glib-2.0 packagekit-glib2 gio-2.0) -std=gnu99`

More information :
https://github.com/liberodark/nrpe-installer/wiki/Plugin-check_updates

#### For check_swap :

need nrpe-plugin source for compile.


### SELinux :


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

### Plugins Configuration :

```
command[service]=/usr/local/nagios/libexec/check_service.sh -o linux -t "systemctl list-units --state=failed"
command[memory]=/usr/local/nagios/libexec/check_mem -w 70 -c 90
command[cpu]=/usr/local/nagios/libexec/check_cpu -w 70 -c 90
command[update]=sudo /usr/local/nagios/libexec/check_updates -w 10 -c 20
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

### Monitoring Compatibility :

https://www.eyesofnetwork.com/

https://www.centreon.com/

https://www.op5.com/


### Linux Compatibility : (Systemd)

- Debian 8.x / 9.x / 10.x
- Deepin 15.x
- Ubuntu 16.04 / 19.10
- Centos 7.x / 8.x
- Oracle 7.x
- Red Hat 7.x / 8.x
- Fedora 15 / 30
- Clear Linux 30110

### Linux Compatibility : (SysV / Upstart)

- Debian 6.x / 7.x
- Ubuntu 14.04
- Centos 5.x / 6.x
- Red Hat 5.x / 6.x
- Fedora 14

# Troubleshouting Debian

### Update repo Debian 6.x / 7.x

For see your OS / Version

```cat /etc/*release```

Save your source list :

```cp -a /etc/apt/sources.list /etc/apt/sources.list.bak```

For Debian 6.x

```echo "deb http://archive.debian.org/debian/ squeeze main" > /etc/apt/sources.list```

For Debian 7.x

```echo "deb http://archive.debian.org/debian/ wheezy main" > /etc/apt/sources.list```


### Upgrade Debian 7 to 8

```
apt-get update && apt-get dist-upgrade -y
```

Remove source.list
```
rm /etc/apt/sources.list
```

Edit source.list
```
nano /etc/apt/sources.list
```

Copy and Past this on source.list
```
deb http://deb.debian.org/debian/ jessie main contrib non-free
deb-src http://deb.debian.org/debian/ jessie main contrib non-free

deb http://security.debian.org/ jessie/updates main contrib non-free
deb-src http://security.debian.org/ jessie/updates main contrib non-free
```

Upgrade APT
```
apt-get update && apt-get install apt -t jessie -y
```

Upgrade your OS (is important to stop all services ex: service apache2 stop)
```
apt dist-upgrade -y
```
