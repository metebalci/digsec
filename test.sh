#!/bin/bash

EXE=scripts/validate.py

function do_test
{
  q=$1
  rr=$2
	rm -rf /tmp/digsec
	mkdir /tmp/digsec
	scripts/validate.py $q $rr /tmp/digsec
  if [ $? -ne 0 ] 
  then
    exit 1
  fi
}

function do_ftest
{
  q=$1
  rr=$2
	rm -rf /tmp/digsec
	mkdir /tmp/digsec
	scripts/validate.py $q $rr /tmp/digsec
  if [ $? -eq 0 ] 
  then 
    exit 1
  fi
}

do_test . DNSKEY
do_test com DNSKEY
do_test metebalci.com DNSKEY
do_test metebalci.com A DNSKEY

do_ftest dnssec-failed.org DNSKEY
