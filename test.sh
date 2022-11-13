#!/bin/bash

set -e

EXE=scripts/validate.py

function do_test
{
	rm -rf $1
	mkdir $1
	scripts/validate.py $2 $3 $1
}

do_test /tmp/digsec . DNSKEY
do_test /tmp/digsec com DNSKEY
do_test /tmp/digsec metebalci.com DNSKEY
do_test /tmp/digsec metebalci.com A DNSKEY
