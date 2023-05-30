#!/bin/bash
#
# About: Backup Logs automatically
# Author: liberodark
# Thanks : 
# License: GNU GPLv3

version="0.0.4"
echo "Welcome on Backup Log Script $version"

#=================================================
# CHECK ROOT
#=================================================

if [[ $(id -u) -ne 0 ]] ; then echo "Please run as root" ; exit 1 ; fi

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

TEMP_365="/Data/tmp/365/"
TEMP_90="/Data/tmp/90/"
DIR_365="/Backup/365/"
DIR_90="/Backup/90/"
PWD="My_Password"

bin_check(){
if ! command -v check_logs > /dev/null 2>&1; then
    echo "check_logs not installed"
    ln -s /usr/local/nagios/libexec/check_logs /usr/bin/check_logs || exit
fi
}

move_log(){
if ! mount -a > /dev/null 2>&1; then
    echo "Mount NFS Error"
    export DIR_365="/Backup-Local/365/"
    export DIR_90="/Backup-Local/90/"
    mkdir -p "${DIR_365}" || exit
    mkdir -p "${DIR_90}" || exit
fi

mkdir -p /tmp/365 || exit
mkdir -p /tmp/90 || exit
mkdir -p "${TEMP_365}" || echo "Create ${TEMP_365} Error"
mkdir -p "${TEMP_90}" || echo "Create ${TEMP_90} Error"
mv /Data/365/*.log "${TEMP_365}" || echo "Move Log in ${TEMP_365} Error"
mv /Data/90/*.log "${TEMP_90}" || echo "Move Log in ${TEMP_90} Error"
systemctl restart rsyslog || echo "Rsyslog Service Error"
}

backup_365(){
check_logs -threads 4 \
             -lock "/tmp/365/file.lock" \
             -encrypt "${PWD}" \
             -in-path "${TEMP_365}" \
             -out-path "${DIR_365}" \
             -then -check -in-path "${DIR_365}" \
             -then -clean 1y -in-path "${DIR_365}"
}

backup_90(){
check_logs -threads 4 \
             -lock "/tmp/90/file.lock" \
             -encrypt "${PWD}" \
             -in-path "${TEMP_90}" \
             -out-path "${DIR_90}" \
             -then -check -in-path "${DIR_90}" \
             -then -clean 90d -in-path "${DIR_90}"
}


bin_check
move_log
backup_365
backup_90