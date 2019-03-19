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

## Monitoring Compatibility :

https://www.eyesofnetwork.com/

https://www.centreon.com/

## Linux Compatibility :

- Debian 9
- Ubuntu 18.04
- Centos 7
- Fedora 29
