#!/bin/bash
#
# About: Backup Logs automatically
# Author: liberodark
# Thanks : 
# License: GNU GPLv3

version="0.0.2"
echo "Welcome on Backup Log Script $version"

#=================================================
# RETRIEVE ARGUMENTS FROM THE MANIFEST AND VAR
#=================================================

TEMP_365="/Data/tmp/365/"
TEMP_90="/Data/tmp/365/"
DIR_365="/Backup/365/"
DIR_90="/Backup/90/"
PWD="My_Password"

bin_check(){
if ! command -v check_logs > /dev/null 2>&1; then
    echo "check_logs not installed"
    exit
fi
}

move_log(){
mount -a || echo "Mount NFS Error" && exit
mkdir -p "${TEMP_365}" || echo "Create ${TEMP_365} Error" && exit
mkdir -p "${TEMP_90}" || echo "Create ${TEMP_90} Error" && exit
mv /Data/365/*.log "${TEMP_365}" || echo "Move Log in ${TEMP_365} Error" && exit
mv /Data/90/*.log "${TEMP_90}" || echo "Move Log in ${TEMP_90} Error" && exit
systemctl restart rsyslog || echo "Rsyslog Service Error" && exit
}

backup_365(){
check_logs -threads 4 \
             -lock "${TEMP_365}file.lock" \
             -encrypt "${PWD}" \
             -in-path "${TEMP_365}" \
             -out-path "${DIR_365}" \
             -then -check -in-path "${DIR_365}" \
             -then -clean 1y -in-path "${DIR_365}"
}

backup_90(){
check_logs -threads 4 \
             -lock "${TEMP_90}file.lock" \
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