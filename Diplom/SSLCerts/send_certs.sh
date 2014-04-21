#!/bin/bash

result
ssh -T dimv36@localhost << EOF
if ! [ -f /home/dimv36/test ]
then
	result = 1
	fi
EOF

echo $result
