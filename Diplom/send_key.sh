#!/bin/bash

user=$1
secontext=$2

ca=192.168.100.4
ca_password=123456
certdir=/etc/pki/certs
keydir=/etc/pki/keys/keys.inst/$user
devnull=/dev/null

private_key=$keydir/private.key
request=$keydir/$user.csr
certificate=$keydir/$user.crt

if ! [ -f $private_key ]
then
	pgcert --genkey --output $private_key >> $devnull
	pgcert --genreq --pkey $private_key --user $user --secontext $secontext --output $request >> $devnull
	sshpass -p $ca_password ssh -T root@$ca bash -s <<-EOF
	if ! [ -d $certdir ]
	then
		mkdir -p $certdir
	fi 
	EOF
	sshpass -p $ca_password scp $request root@$ca:$certdir/$user.csr
	sshpass -p $ca_password ssh -T root@$ca "pgcert --gencert --request $certdir/$user.csr --signature --output $certdir/$user.crt" >> $devnull
	sshpass -p $ca_password ssh -T root@$ca "rm -f $certdir/$user.csr" 
	sshpass -p $ca_password scp root@$ca:$certdir/$user.crt $certificate
	rm -f $request
fi
