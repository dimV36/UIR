#!/bin/bash

ca=192.168.100.4
ca_password=123456
certdir=/etc/pki/certs
user=$1
secontext=$2
key_folder=/etc/pki/keys/keys.inst/$user
private_key=$key_folder/private.key
request=$key_folder/$user.csr
certificate=$key_folder/$user.crt

if ! [ -f $private_key ]
then
	pgcert --genkey --output $private_key
	pgcert --genreq --pkey $private_key --user $user --secontext $secontext --output $request
	sshpass -p $ca_password ssh -T root@$ca bash -s <<-EOF
	if ! [ -d $certdir ]
	then
		exit 1
	else
		exit 0
	fi 
	EOF
	sshpass -p $ca_password scp $request root@$ca:$certdir/$user.csr
	sshpass -p $ca_password ssh -T root@$ca "pgcert --gencert --request $certdir/$user.csr --signature --output $certdir/$user.crt"
fi

# sshpass -p $ca_password ssh -T root@$ca bash -s << EOF
# if ! [ -f /etc/pki/keys/$user.key ]
# then
# 	exit 1
# else
# 	exit 0
# fi 
# EOF
# 
# not_exist=$?
# 
# if [ $not_exist -ne 0 ]
# then
# 	sshpass -p $ca_password scp /etc/pki/certs/public.key root@$ca:/root/keys/$user.key 
# fi
