#!/bin/bash

ca=192.168.100.4
ca_password=123456
certdir=/etc/pki/certs
user=$1

sshpass -p $ca_password ssh -T root@$ca bash -s << EOF
if ! [ -f /etc/pki/keys/$user.key ]
then
	exit 1
else
	exit 0
fi 
EOF

not_exist=$?

if [ $not_exist -ne 0 ]
then
	sshpass -p $ca_password scp /etc/pki/certs/public.key root@$ca:/root/keys/$user.key 
fi
